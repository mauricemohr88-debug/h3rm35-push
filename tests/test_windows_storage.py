"""Actual NTFS fixtures, never a patched os.name or a real Hermes directory."""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from h3rm35_push_plugin_test import windows_files as files


native = pytest.mark.skipif(os.name != "nt", reason="requires native Windows and NTFS")
DIRECTORY = "push-test"
DATABASE = "registrations.sqlite"
LOCK = "store.lock"


def private_directory(path):
    """Create only the new fixture, leaving inherited TEMP permissions intact."""
    w = files.require_native()
    current, _allowed, system = files._principals(w)
    w.win32file.CreateDirectory(str(path), files._security_attributes(w, current, system, directory=True))
    return path


@pytest.fixture
def private_home(tmp_path):
    if os.name != "nt":
        pytest.skip("requires native Windows and NTFS")
    return private_directory(tmp_path / "private-fixture")


@contextmanager
def connection(path):
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0.1)
    try:
        # This order is part of hot-journal recovery with no-delete handles.
        assert db.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0] == "exclusive"
        assert db.execute("PRAGMA journal_mode=PERSIST").fetchone()[0] == "persist"
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA mmap_size=0")
        yield db
    finally:
        db.close()


def initialize(path):
    with connection(path) as db:
        db.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        db.execute("INSERT INTO evidence VALUES ('fixture')")
        db.commit()


def open_store(home, **kwargs):
    return files.open_storage(home, DIRECTORY, DATABASE, LOCK, initialize=initialize, **kwargs)


def identity(storage):
    return SimpleNamespace(**{name: getattr(storage, name)
                             for name in ("home", "root", "directory", "database", "lock", "journal")})


def paths(home):
    directory = home / DIRECTORY
    return {"root": home, "directory": directory, "database": directory / DATABASE,
            "journal": directory / (DATABASE + "-journal"), "lock": directory / LOCK}


def security_text(path):
    w = files.require_native()
    security = w.win32security
    flags = security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
    descriptor = security.GetFileSecurity(str(path), flags)
    return security.ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, security.SDDL_REVISION_1, flags)


def change_acl(path, *, foreign=False, protected=True, inherit=True, null=False):
    w = files.require_native()
    security = w.win32security
    current, _allowed, system = files._principals(w)
    acl = security.ACL()
    inheritance = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if inherit else 0
    for principal in {files._sid(w, value): value for value in (current, system)}.values():
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, inheritance, w.ntsecuritycon.FILE_ALL_ACCESS, principal)
    if foreign:
        everyone = security.ConvertStringSidToSid("S-1-1-0")
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, inheritance, w.ntsecuritycon.FILE_GENERIC_READ, everyone)
    flags = security.DACL_SECURITY_INFORMATION | (security.PROTECTED_DACL_SECURITY_INFORMATION if protected
                                                  else security.UNPROTECTED_DACL_SECURITY_INFORMATION)
    security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT, flags, None, None,
                                 None if null else acl, None)


def test_off_windows_native_api_refuses_without_importing_pywin32():
    if os.name == "nt":
        pytest.skip("non-Windows import boundary")
    with pytest.raises(files.WindowsStorageError, match="native Windows APIs"):
        files.require_native()


@native
def test_native_bootstrap_reopen_and_sqlite_commit(private_home):
    with open_store(private_home) as storage:
        original = identity(storage)
        assert storage.created
        for path in paths(private_home).values():
            assert "D:P" in security_text(path)
        with connection(paths(private_home)["database"]) as db:
            db.execute("INSERT INTO evidence VALUES ('committed')")
            db.commit()
        storage.flush()
    with open_store(private_home, expected_identity=original) as storage:
        assert not storage.created
        assert vars(identity(storage)) == vars(original)
        with connection(paths(private_home)["database"]) as db:
            assert db.execute("SELECT value FROM evidence").fetchall() == [("fixture",), ("committed",)]
    assert not list(private_home.glob(DIRECTORY + ".creating-*"))


@native
@pytest.mark.parametrize("role", ["directory", "database", "lock", "journal"])
@pytest.mark.parametrize("fault", ["foreign", "unprotected", "null"])
def test_native_acl_rejected_without_repair(private_home, role, fault):
    with open_store(private_home):
        pass
    target = paths(private_home)[role]
    change_acl(target, foreign=fault == "foreign", protected=fault != "unprotected", null=fault == "null")
    before = security_text(target)
    with pytest.raises(files.WindowsStorageError):
        with open_store(private_home):
            pass
    assert security_text(target) == before


@native
def test_directory_acl_must_inherit_privately_to_new_files(private_home):
    with open_store(private_home):
        pass
    directory = paths(private_home)["directory"]
    change_acl(directory, inherit=False)
    before = security_text(directory)
    with pytest.raises(files.WindowsStorageError, match="inherit"):
        with open_store(private_home):
            pass
    assert security_text(directory) == before


@native
def test_owner_is_compared_to_actual_native_descriptor(private_home):
    w = files.require_native()
    current, allowed, system = files._principals(w)
    if files._sid(w, current) == files._sid(w, system):
        pytest.skip("fixture account is SYSTEM")
    with open_store(private_home) as storage:
        # The descriptor comes from the real held handle; only the expected
        # account is deliberately wrong to exercise the owner guard safely.
        with pytest.raises(files.WindowsStorageError, match="owner"):
            files._verify_security(w, storage._handles["database"], system, allowed, role="database")


@native
def test_root_other_user_write_acl_rejected_without_creation(private_home):
    w = files.require_native()
    security = w.win32security
    current, _allowed, system = files._principals(w)
    acl = security.ACL()
    for principal in (current, system):
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, 3, w.ntsecuritycon.FILE_ALL_ACCESS, principal)
    acl.AddAccessAllowedAceEx(security.ACL_REVISION, 0, w.ntsecuritycon.FILE_GENERIC_WRITE,
                             security.ConvertStringSidToSid("S-1-1-0"))
    security.SetNamedSecurityInfo(str(private_home), security.SE_FILE_OBJECT,
                                 security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
                                 None, None, acl, None)
    before = security_text(private_home)
    with pytest.raises(files.WindowsStorageError, match="another account"):
        with open_store(private_home):
            pass
    assert not (private_home / DIRECTORY).exists()
    assert security_text(private_home) == before


@native
@pytest.mark.parametrize("role", ["database", "journal", "lock"])
def test_native_hardlinks_are_rejected(private_home, role):
    with open_store(private_home):
        pass
    source = paths(private_home)[role]
    os.link(source, private_home / (role + "-hardlink"))
    with pytest.raises(files.WindowsStorageError):
        with open_store(private_home):
            pass
    assert source.stat().st_nlink == 2


@native
@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_native_wal_and_shm_sidecars_are_rejected(private_home, suffix):
    with open_store(private_home):
        pass
    target = Path(str(paths(private_home)["database"]) + suffix)
    target.write_bytes(b"fixture sidecar")
    with pytest.raises(files.WindowsStorageError, match="WAL"):
        with open_store(private_home):
            pass
    assert target.read_bytes() == b"fixture sidecar"


@native
def test_missing_journal_is_not_recreated(private_home):
    with open_store(private_home):
        pass
    paths(private_home)["journal"].unlink()
    with pytest.raises(files.WindowsStorageError):
        with open_store(private_home):
            pass
    assert not paths(private_home)["journal"].exists()


@native
def test_native_metadata_junction_is_rejected(private_home):
    with open_store(private_home):
        pass
    original = paths(private_home)["directory"]
    target = original.with_name("moved-private")
    original.rename(target)
    result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(original), str(target)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr or result.stdout
    with pytest.raises(files.WindowsStorageError):
        with open_store(private_home):
            pass
    assert original.is_dir() and target.is_dir()


@native
@pytest.mark.parametrize("role", ["root", "directory", "database", "journal", "lock"])
def test_native_held_handles_deny_rename_until_close(private_home, role):
    with open_store(private_home) as storage:
        target = paths(private_home)[role]
        moved = target.with_name(target.name + "-moved")
        with pytest.raises(OSError):
            target.rename(moved)
        storage.verify()
    target.rename(moved)
    moved.rename(target)


@native
@pytest.mark.parametrize("role", ["root", "directory", "database", "journal", "lock"])
def test_expected_generation_is_checked(private_home, role):
    with open_store(private_home) as storage:
        expected = identity(storage)
    volume, index = getattr(expected, role)
    setattr(expected, role, (volume, index ^ 1))
    with pytest.raises(files.WindowsStorageIdentityError):
        with open_store(private_home, expected_identity=expected):
            pass


@native
def test_failed_stage_remains_private_and_is_not_published(private_home):
    def fail(path):
        initialize(path)
        raise RuntimeError("fixture interrupted before publication")

    with pytest.raises(RuntimeError, match="fixture interrupted"):
        with files.open_storage(private_home, DIRECTORY, DATABASE, LOCK, initialize=fail):
            pass
    assert not (private_home / DIRECTORY).exists()
    stages = list(private_home.glob(DIRECTORY + ".creating-*"))
    assert len(stages) == 1
    assert "D:P" in security_text(stages[0])


CHILD_IMPORT = """
import importlib.util
from pathlib import Path
import sys
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('isolated_push', root/'__init__.py',
                                             submodule_search_locations=[str(root)])
package = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = package
spec.loader.exec_module(package)
from isolated_push import windows_files as files
home = Path(sys.argv[2])
"""


@native
def test_native_lock_is_cross_process_and_released_on_process_exit(private_home):
    with open_store(private_home):
        pass
    script = CHILD_IMPORT + """
with files.open_storage(home, 'push-test', 'registrations.sqlite', 'store.lock'):
    (home/'fixture-ready').write_text('locked', encoding='utf-8')
    sys.stdin.readline()
"""
    child = subprocess.Popen([sys.executable, "-c", script, str(Path(files.__file__).parent), str(private_home)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        ready = private_home / "fixture-ready"
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists() and child.poll() is None
        with pytest.raises(files.WindowsStorageError, match="busy"):
            with open_store(private_home, lock_timeout=0.05):
                pass
        child.kill()
        child.communicate(timeout=10)
        with open_store(private_home, lock_timeout=0.2) as storage:
            storage.verify()
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


@native
def test_native_hot_journal_recovered_after_fixture_child_crash(private_home):
    with open_store(private_home):
        pass
    script = CHILD_IMPORT + """
import os
import sqlite3
with files.open_storage(home, 'push-test', 'registrations.sqlite', 'store.lock'):
    db = sqlite3.connect((home/'push-test'/'registrations.sqlite').as_uri()+'?mode=rw', uri=True)
    db.execute('PRAGMA locking_mode=EXCLUSIVE')
    db.execute('PRAGMA journal_mode=PERSIST')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA cache_size=1')
    db.execute('BEGIN IMMEDIATE')
    db.execute("UPDATE evidence SET value=?", ('x'*200000,))
    os._exit(19)
"""
    result = subprocess.run([sys.executable, "-c", script, str(Path(files.__file__).parent), str(private_home)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 19, result.stderr
    with open_store(private_home) as storage:
        with connection(paths(private_home)["database"]) as db:
            assert db.execute("SELECT value FROM evidence").fetchall() == [("fixture",)]
        storage.flush()
