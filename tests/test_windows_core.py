"""Native Windows qualification of the actual registration/outbox integration."""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from h3rm35_push_plugin_test import core

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires real Windows storage")


def grant(store):
    return {"schema": 2, "host_id": store.host_id(), "binding_id": str(uuid.uuid4()),
            "host_secret": "ab" * 32, "enabled_kinds": sorted(core.KINDS)}


def test_actual_store_three_kinds_reopen_and_revoke(tmp_path):
    store = core.Store(tmp_path / "push")
    registration = grant(store)
    store.register(registration)
    store = core.Store(store.directory)
    assert store.host_id() == registration["host_id"]
    for kind in sorted(core.KINDS):
        store.enqueue(kind, "research", "stored-session", kind + "-marker", now=100)
    received = []
    while item := store.claim(now=100):
        received.append(json.loads(item["payload"])["kind"])
        assert item["host_secret"] == registration["host_secret"]
        store.finish(item, False, now=100)
    assert sorted(received) == sorted(core.KINDS)
    store.remove(registration["binding_id"])
    store.enqueue("response", "research", "stored-session", "new-turn", now=100)
    assert store.claim(now=100) is None


BOOTSTRAP = """
import importlib.util, os, sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('isolated_push',root/'__init__.py',submodule_search_locations=[str(root)])
package = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = package
spec.loader.exec_module(package)
from isolated_push.core import Store
store = Store(Path(sys.argv[2]))
"""


def test_actual_store_crash_rolls_back_and_keeps_identity(tmp_path):
    store = core.Store(tmp_path / "push")
    registration = grant(store)
    store.register(registration)
    script = BOOTSTRAP + """
with store.connect() as db:
    db.execute('PRAGMA cache_size=1')
    db.execute('BEGIN IMMEDIATE')
    db.execute('UPDATE identity SET host_id=?', ('uncommitted-'+'x'*200000,))
    db.execute('DELETE FROM registrations')
    os._exit(19)
"""
    result = subprocess.run([sys.executable, "-c", script, str(Path(core.__file__).parent),
                             str(store.directory)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 19, result.stderr
    reopened = core.Store(store.directory)
    assert reopened.host_id() == registration["host_id"]
    reopened.enqueue("approval", "research", "session", "request", now=100)
    assert reopened.claim(now=100)["binding_id"] == registration["binding_id"]


def test_existing_store_is_not_silently_replaced(tmp_path):
    store = core.Store(tmp_path / "push")
    store.directory.rename(tmp_path / "old-push")
    replacement = core.Store(tmp_path / "push")
    assert replacement.host_id() != core.Store(tmp_path / "old-push").host_id()
    with pytest.raises(core.PrivateStorageError):
        store.host_id()


def test_missing_native_dependency_does_not_advertise_storage(monkeypatch):
    def unavailable():
        raise ImportError("fixture missing native dependency")
    monkeypatch.setattr(core.windows_files(), "require_native", unavailable)
    assert core.supports_private_storage() is False


def test_root_junction_alias_is_bound_to_original_canonical_store(tmp_path):
    from h3rm35_push_plugin_test import windows_files as files
    w = files.require_native()
    current, _allowed, system = files._principals(w)
    roots = [tmp_path / name for name in ("first", "second")]
    for root in roots:
        w.win32file.CreateDirectory(str(root), files._security_attributes(w, current, system, directory=True))
    alias = tmp_path / "alias"
    def link(target):
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(target)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
    link(roots[0])
    store = core.Store(alias / "push")
    original = store.host_id()
    assert store.directory == roots[0] / "push"
    alias.rmdir()
    link(roots[1])
    replacement = core.Store(alias / "push")
    assert replacement.host_id() != original
    assert store.host_id() == original


def test_simultaneous_first_store_publication_has_one_shared_identity(tmp_path):
    script = BOOTSTRAP.replace("store = Store(Path(sys.argv[2]))", "") + """
import json, time, uuid
sys.stdin.readline()
for attempt in range(100):
    try:
        store = Store(Path(sys.argv[2]))
        host_id = store.host_id()
        store.register({'schema':2,'host_id':host_id,'binding_id':str(uuid.uuid4()),
                        'host_secret':'ab'*32,'enabled_kinds':['response']})
        print(host_id, flush=True)
        break
    except (RuntimeError, ValueError, sqlite3.OperationalError):
        if attempt == 99:
            raise
        time.sleep(0.01)
"""
    children = [subprocess.Popen([sys.executable, "-c", script, str(Path(core.__file__).parent),
                                  str(tmp_path / "push")], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(3)]
    try:
        for child in children:
            child.stdin.write("start\n")
            child.stdin.flush()
        outputs = [child.communicate(timeout=20) for child in children]
        assert all(child.returncode == 0 for child in children), outputs
        identifiers = [stdout.strip() for stdout, _stderr in outputs]
        assert len(set(identifiers)) == 1
        with core.Store(tmp_path / "push").connect() as db:
            assert db.execute("SELECT count(*) FROM registrations").fetchone()[0] == 3
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
