import gc
import json
import os
from pathlib import Path
import sqlite3
import sys
from types import ModuleType
import uuid

import pytest

from h3rm35_push_plugin_test.core import Store, event_identity, registration
from h3rm35_push_plugin_test import Observer


def data(store, binding=None):
    return {"schema": 2, "host_id": store.host_id(), "binding_id": binding or str(uuid.uuid4()),
            "host_secret": "ab"*32, "enabled_kinds": ["response", "clarification", "approval"]}


def test_private_stable_identity_and_scoped_registration(tmp_path):
    store = Store(tmp_path/"push")
    first, second = data(store), data(store)
    assert Store(tmp_path/"push").host_id() == first["host_id"]
    receipt = store.register(first)
    assert receipt == {"schema": 2, "host_id": first["host_id"], "binding_id": first["binding_id"], "registered": True}
    assert "host_secret" not in receipt
    assert store.register(first) == receipt
    store.register(second)
    with pytest.raises(ValueError, match="conflict"):
        store.register({**first, "host_secret": "cd"*32})
    with pytest.raises(ValueError, match="mismatch"):
        store.register({**first, "host_id": str(uuid.uuid4())})
    store.remove(first["binding_id"])
    store.enqueue("response", "research", "session-1", "turn-1", now=100)
    item = store.claim(now=100)
    assert item["binding_id"] == second["binding_id"]
    assert stat_mode(store.path) == 0o600 and stat_mode(tmp_path/"push") == 0o700


def stat_mode(path):
    return path.stat().st_mode & 0o777


@pytest.mark.parametrize("change", [{"schema": True}, {"host_secret": "A"*64}, {"device_secret": "never"},
                                  {"enabled_kinds": ["response", "response"]}, {"enabled_kinds": ["unknown"]}])
def test_strict_registration(tmp_path, change):
    store = Store(tmp_path/"push")
    with pytest.raises(ValueError):
        registration({**data(store), **change})


def test_no_symlink_or_shared_store(tmp_path):
    private = tmp_path/"private"
    private.mkdir(mode=0o700)
    linked = tmp_path/"linked"
    linked.symlink_to(private)
    with pytest.raises(ValueError):
        Store(linked)
    store = Store(private)
    store.path.chmod(0o644)
    with pytest.raises(ValueError):
        Store(private)


def test_metadata_only_fanout_dedupe_preferences_and_expiry(tmp_path):
    store = Store(tmp_path/"push")
    first, second = data(store), data(store)
    store.register(first)
    store.register({**second, "enabled_kinds": ["approval"]})
    store.enqueue("response", "research", "session-1", "turn-1", now=100)
    store.enqueue("response", "research", "session-1", "turn-1", now=101)
    item = store.claim(now=101)
    assert item["binding_id"] == first["binding_id"]
    payload = json.loads(item["payload"])
    assert set(payload) == {"event_id", "kind", "profile", "session_id", "occurred_at"}
    assert payload["occurred_at"] == 100
    assert store.claim(now=101) is None
    store.finish(item, False, now=101)
    store.enqueue("approval", "research", "session-1", "request-1", now=102)
    a, b = store.claim(now=102), store.claim(now=102)
    assert a["event_id"] != b["event_id"]
    assert {a["binding_id"],b["binding_id"]} == {first["binding_id"],second["binding_id"]}
    assert store.claim(now=500) is None


def test_bounded_retry_and_revocation(tmp_path):
    store = Store(tmp_path/"push")
    grant = data(store)
    store.register(grant)
    store.enqueue("response", "default", "session", "turn", now=0)
    for now in (0, 2, 6, 14, 30):
        item = store.claim(now=now)
        assert item is not None
        store.finish(item, True, now=now)
    assert store.claim(now=100) is None
    store.enqueue("response", "default", "session", "turn2", now=100)
    store.remove(grant["binding_id"])
    assert store.claim(now=100) is None


def test_queue_limit_rolls_back_fanout(tmp_path, monkeypatch):
    from h3rm35_push_plugin_test import core
    store = Store(tmp_path/"push")
    store.register(data(store))
    store.register(data(store))
    monkeypatch.setattr(core, "MAX_OUTBOX", 1)
    with pytest.raises(ValueError, match="full"):
        store.enqueue("response", "default", "s", "turn", now=100)
    assert store.claim(now=100) is None


def test_connections_closed_without_garbage_collection(tmp_path, monkeypatch):
    store = Store(tmp_path/"push")
    original, opened = sqlite3.connect, []
    def connect(*args, **kwargs):
        db = original(*args, **kwargs)
        opened.append(db)
        return db
    monkeypatch.setattr(sqlite3, "connect", connect)
    enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(100):
            store.host_id()
            store.claim(now=100)
        for db in opened:
            with pytest.raises(sqlite3.ProgrammingError, match="closed"):
                db.execute("SELECT 1")
    finally:
        if enabled:
            gc.enable()


def test_current_profile_exact_row_no_cross_profile_guess(tmp_path, monkeypatch):
    home = tmp_path/"research"
    home.mkdir()
    db = sqlite3.connect(home/"state.db")
    db.execute("CREATE TABLE sessions(id TEXT,profile_name TEXT)")
    db.executemany("INSERT INTO sessions VALUES (?,?)", [("exact", "research"),("other","default"),("old",None)])
    db.commit()
    db.close()
    constants, profiles = ModuleType("hermes_constants"), ModuleType("hermes_cli.profiles")
    constants.get_hermes_home = lambda: home
    profiles.current_profile_name = lambda default: "research"
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    monkeypatch.setitem(sys.modules, "hermes_cli.profiles", profiles)
    assert event_identity("exact") == ("research", "exact")
    assert event_identity("old") == ("research", "old")
    assert event_identity("exac") is None
    assert event_identity("other") is None
    assert event_identity("missing") is None
    os.link(home/"state.db",home/"shared.db")
    assert event_identity("old") is None
    (home/"shared.db").unlink()
    profiles.current_profile_name = lambda default: None
    assert event_identity("exact") is None


def test_hooks_never_read_or_export_content_and_skip_forks():
    emitted = []
    class FakeStore:
        def enqueue(self, *args): emitted.append(args)
    observer = Observer(FakeStore(), lambda sid: ("research", sid) if sid == "stored" else None)
    assert observer.completed(session_id="stored", turn_id="turn1", platform="desktop", assistant_response="private") is None
    observer.completed(session_id="stored", turn_id="fork", platform="subagent")
    observer.completed(session_id="stored", turn_id="curator", platform="curator")
    observer.completed(session_id="missing", turn_id="turn2")
    observer.completed(session_id="stored", turn_id="empty", assistant_response="   ")
    assert observer.human_request(kind="clarify", session_id="stored", request_id="request1", prompt="private question") is None
    observer.human_request(kind="approval", session_id="stored", request_id="request2", command="private command")
    observer.human_request(kind="secret", session_id="stored", request_id="request3")
    assert emitted == [("response","research","stored","turn1"),("clarification","research","stored","request1"),
                       ("approval","research","stored","request2")]


@pytest.mark.parametrize("failure",["setup","body"])
def test_connection_closed_during_error(tmp_path,monkeypatch,failure):
    store=Store(tmp_path/"push")
    original=sqlite3.connect
    opened=[]
    class Connection(sqlite3.Connection):
        def execute(self,sql,*args,**kwargs):
            if failure=="setup" and sql.startswith("PRAGMA"):
                raise RuntimeError("synthetic setup failure")
            return super().execute(sql,*args,**kwargs)
    def connect(*args,**kwargs):
        db=original(*args,**kwargs,factory=Connection)
        opened.append(db)
        return db
    monkeypatch.setattr(sqlite3,"connect",connect)
    with pytest.raises(RuntimeError):
        with store.connect() as db:
            raise RuntimeError("synthetic body failure")
    with pytest.raises(sqlite3.ProgrammingError,match="closed"):
        opened[0].execute("SELECT 1")
