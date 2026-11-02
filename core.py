"""Private host registration and bounded metadata outbox; no Hermes action API."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid

KINDS = frozenset({"response", "clarification", "approval"})
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROFILE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
MAX_REGISTRATIONS = 500
MAX_OUTBOX = 2_000
EVENT_LIFETIME = 300
_WINDOWS_IMPORT_LOCK = threading.RLock()


class PrivateStorageError(RuntimeError):
    """Native storage cannot be used; not a rejected registration input."""


def windows_files():
    # Stock also loads this core as a standalone API module, outside the plugin
    # package. Give the sibling adapter a fixed package for its relative imports.
    name = __name__ + "_windows_storage"
    with _WINDOWS_IMPORT_LOCK:
        if name not in sys.modules:
            spec = importlib.util.spec_from_file_location(
                name, Path(__file__).with_name("windows_files.py"),
                submodule_search_locations=[str(Path(__file__).parent)],
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(name, None)
                raise
        return sys.modules[name]


def assert_no_extended_acl(path):
    if sys.platform != "darwin":
        return
    try:
        result = subprocess.run(
            ["/bin/ls", "-lde", "--", str(path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("private store ACL cannot be verified") from None
    # ls -e lists one header followed by ACL entries. Extended attributes (@)
    # alone are harmless; any ACL entry or ambiguous metadata fails closed.
    raw = result.stdout
    if result.returncode != 0 or len(raw) > 8192:
        raise ValueError("private store ACL cannot be verified")
    lines = raw.splitlines()
    fields = lines[0].split() if len(lines) == 1 else []
    if (not fields or fields[0][:1] not in (b"d", b"-")
            or not (len(fields[0]) == 10 or (len(fields[0]) == 11 and fields[0].endswith(b"@")))):
        raise ValueError("extended store ACL is not supported")


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid identifier")
    return value


def registration(value):
    if not isinstance(value, dict) or set(value) != {
        "schema", "host_id", "binding_id", "host_secret", "enabled_kinds"
    } or type(value["schema"]) is not int or value["schema"] != 2:
        raise ValueError("invalid registration")
    canonical_uuid(value["host_id"])
    canonical_uuid(value["binding_id"])
    if not isinstance(value["host_secret"], str) or not HEX64.fullmatch(value["host_secret"]):
        raise ValueError("invalid capability")
    kinds = value["enabled_kinds"]
    if (not isinstance(kinds, list) or len(kinds) > 3
            or not all(isinstance(kind, str) and kind in KINDS for kind in kinds)
            or len(set(kinds)) != len(kinds)):
        raise ValueError("invalid preferences")
    return {**value, "enabled_kinds": sorted(kinds)}


class Store:
    def __init__(self, directory: Path):
        if not supports_private_storage():
            raise ValueError("native private storage is unavailable")
        self.directory = Path(directory).absolute()
        self.path = self.directory / "registrations.sqlite"
        self._windows_identity = None
        if os.name == "nt":
            with self._open_windows(initializing=True) as opened:
                self._windows_identity = opened
                # SQLite must reopen the exact canonical root guarded by the
                # native handles, never a retargetable junction alias.
                self.directory = opened.home / self.directory.name
                self.path = self.directory / "registrations.sqlite"
            return
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = self.directory.lstat()
        if (self.directory.resolve() != self.directory or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("private owned notification directory required")
        # macOS ACLs can grant access despite mode0700; never strip user ACLs.
        assert_no_extended_acl(self.directory)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        info = self.path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("private owned notification store required")
        assert_no_extended_acl(self.path)
        with self.connect() as db:
            self._schema(db)

    @staticmethod
    def _schema(db):
        db.executescript("""
                CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1), host_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS registrations(
                    binding_id TEXT PRIMARY KEY, host_secret TEXT NOT NULL, kinds TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox(
                    event_id TEXT PRIMARY KEY, binding_id TEXT NOT NULL,
                    payload TEXT NOT NULL, expires_at REAL NOT NULL, due REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
                    FOREIGN KEY(binding_id) REFERENCES registrations(binding_id) ON DELETE CASCADE);
        """)
        db.execute("INSERT OR IGNORE INTO identity VALUES (1,?)", (str(uuid.uuid4()),))

    @staticmethod
    def _configure_windows(db):
        # EXCLUSIVE precedes schema/journal inspection so crash recovery never
        # deletes the journal while its verified no-delete handle is pinned.
        if db.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0] != "exclusive":
            raise ValueError("private store locking unavailable")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA mmap_size=0")
        if db.execute("PRAGMA journal_mode").fetchone()[0] == "wal":
            raise ValueError("private store WAL is unsupported")
        if db.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] != "persist":
            raise ValueError("private store journaling unavailable")
        if (db.execute("PRAGMA synchronous").fetchone()[0] != 2
                or db.execute("PRAGMA temp_store").fetchone()[0] != 2
                or db.execute("PRAGMA mmap_size").fetchone()[0] != 0):
            raise ValueError("private store durability unavailable")

    @classmethod
    def _initialize_windows(cls, path):
        db = sqlite3.connect(path.as_uri()+"?mode=rw", uri=True, timeout=0.05)
        try:
            cls._configure_windows(db)
            with db:
                cls._schema(db)
        finally:
            db.close()

    @contextmanager
    def _open_windows(self, *, initializing=False):
        files = windows_files()
        try:
            with files.open_storage(
                self.directory.parent, self.directory.name, self.path.name, "store.lock",
                initialize=self._initialize_windows if initializing else None,
                expected_identity=self._windows_identity, lock_timeout=0.05,
            ) as opened:
                yield opened
        except files.WindowsStorageError:
            raise PrivateStorageError("native private store is unavailable") from None

    @contextmanager
    def connect(self):
        if os.name == "nt":
            with self._open_windows() as opened:
                path = opened.home / self.directory.name / self.path.name
                db = sqlite3.connect(path.as_uri()+"?mode=rw", uri=True, timeout=0.05)
                try:
                    self._configure_windows(db)
                    db.row_factory = sqlite3.Row
                    db.execute("PRAGMA foreign_keys=ON")
                    with db:
                        yield db
                    opened.verify()
                finally:
                    db.close()
                opened.verify()
                opened.flush()
            return
        db = sqlite3.connect(self.path, timeout=0.05)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

    def host_id(self):
        with self.connect() as db:
            return db.execute("SELECT host_id FROM identity WHERE id=1").fetchone()[0]

    def register(self, value):
        data = registration(value)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if data["host_id"] != db.execute("SELECT host_id FROM identity WHERE id=1").fetchone()[0]:
                raise ValueError("host identity mismatch")
            old = db.execute("SELECT host_secret FROM registrations WHERE binding_id=?", (data["binding_id"],)).fetchone()
            if old is not None and old[0] != data["host_secret"]:
                raise ValueError("registration capability conflict")
            if old is None and db.execute("SELECT count(*) FROM registrations").fetchone()[0] >= MAX_REGISTRATIONS:
                raise ValueError("registration limit reached")
            db.execute("INSERT INTO registrations VALUES (?,?,?) ON CONFLICT(binding_id) DO UPDATE SET kinds=excluded.kinds",
                       (data["binding_id"], data["host_secret"], json.dumps(data["enabled_kinds"])))
        return {"schema": 2, "host_id": data["host_id"], "binding_id": data["binding_id"], "registered": True}

    def remove(self, binding_id):
        canonical_uuid(binding_id)
        with self.connect() as db:
            db.execute("DELETE FROM registrations WHERE binding_id=?", (binding_id,))

    def enqueue(self, kind, profile, session_id, marker, *, now=None):
        if (kind not in KINDS or not isinstance(profile, str) or not PROFILE.fullmatch(profile)
                or not isinstance(session_id, str) or not SESSION.fullmatch(session_id)
                or not isinstance(marker, str) or not 1 <= len(marker) <= 512):
            raise ValueError("invalid event identity")
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM outbox WHERE expires_at<=?", (now,))
            capacity = MAX_OUTBOX - db.execute("SELECT count(*) FROM outbox").fetchone()[0]
            for row in db.execute("SELECT * FROM registrations ORDER BY binding_id").fetchall():
                if kind not in json.loads(row["kinds"]):
                    continue
                event_id = hashlib.sha256(json.dumps([row["binding_id"], profile, session_id, kind, marker],
                                                     separators=(",", ":")).encode()).hexdigest()
                if db.execute("SELECT 1 FROM outbox WHERE event_id=?", (event_id,)).fetchone():
                    continue
                if capacity <= 0:
                    raise ValueError("notification queue full")
                payload = {"event_id": event_id, "kind": kind, "profile": profile,
                           "session_id": session_id, "occurred_at": int(now)}
                db.execute("INSERT INTO outbox(event_id,binding_id,payload,expires_at,due) VALUES(?,?,?,?,?)",
                           (event_id, row["binding_id"], json.dumps(payload, separators=(",", ":")), now+EVENT_LIFETIME, now))
                capacity -= 1

    def claim(self, *, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM outbox WHERE expires_at<=?", (now,))
            row = db.execute("SELECT o.*,r.host_secret FROM outbox o JOIN registrations r USING(binding_id) "
                             "WHERE due<=? AND lease_until<=? ORDER BY due LIMIT 1", (now, now)).fetchone()
            if row is not None:
                db.execute("UPDATE outbox SET lease_until=? WHERE event_id=?", (now+20, row["event_id"]))
                return dict(row)
        return None

    def finish(self, item, retry, *, now=None):
        now = time.time() if now is None else now
        with self.connect() as db:
            attempts = item["attempts"] + 1
            if not retry or attempts >= 5:
                db.execute("DELETE FROM outbox WHERE event_id=?", (item["event_id"],))
            else:
                db.execute("UPDATE outbox SET attempts=?,due=?,lease_until=0 WHERE event_id=?",
                           (attempts, now+min(60, 2**attempts), item["event_id"]))


def process_store():
    from hermes_constants import get_default_hermes_root, get_routing_process_hermes_home
    # The API and observer can run in different profile/plugin-host processes.
    # Stock resolves their common installation root, including custom roots.
    return Store(get_default_hermes_root(home=get_routing_process_hermes_home()) / "h3rm35-push")


def supported_host():
    from hermes_cli.plugins import VALID_HOOKS
    # Old hooks lack a reliable stored session ID for every human request.
    return {"post_llm_call", "on_human_input_request"}.issubset(VALID_HOOKS)


def supports_private_storage():
    if os.name == "posix":
        return True
    if os.name == "nt":
        try:
            windows_files().require_native()
            return True
        except (ImportError, OSError, RuntimeError, ValueError):
            return False
    return False


def event_identity(session_id):
    """A context-qualified exact persisted row, never a live-session prefix match."""
    if not isinstance(session_id, str) or not SESSION.fullmatch(session_id):
        return None
    from hermes_constants import get_hermes_home
    from hermes_cli.profiles import current_profile_name
    profile = current_profile_name(default=None)
    if not isinstance(profile, str) or not PROFILE.fullmatch(profile):
        return None
    path = get_hermes_home() / "state.db"
    if not path.is_file():
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        # A legacy NULL profile row is scoped by its actual profile file; a
        # shared/symlinked database cannot supply that unique ownership proof.
        return None
    db = sqlite3.connect(path.resolve().as_uri()+"?mode=ro", uri=True, timeout=0.05)
    try:
        row = db.execute("SELECT id,profile_name FROM sessions WHERE id=?", (session_id,)).fetchone()
    finally:
        db.close()
    if row is None or row[0] != session_id or (row[1] and row[1] != profile):
        return None
    return profile, session_id
