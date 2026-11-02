"""Bounded execution of actual pinned upstream source, without a running agent."""

import ast
import asyncio
import contextvars
import importlib.util
import logging
import os
from pathlib import Path
import sqlite3
import sys
from types import ModuleType, SimpleNamespace
import typing

from fastapi import Depends, FastAPI, HTTPException
import httpx
import pytest

from h3rm35_push_plugin_test import Observer
from h3rm35_push_plugin_test.core import Store, event_identity, process_store

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = Path(__file__).resolve().parent/"upstream-source-3d304a1"


def actual_functions(filename, names, namespace):
    path=UPSTREAM/filename
    if not path.is_file():
        pytest.skip("read-only upstream source fixture absent")
    tree=ast.parse(path.read_text(encoding="utf-8"))
    nodes=[node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names]
    assert {node.name for node in nodes}==set(names)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),namespace)
    return namespace


def test_actual_root_helpers_share_identity_across_profiles_and_custom_roots(tmp_path,monkeypatch):
    native=tmp_path/"native"
    custom=tmp_path/"custom"
    for path in (native, custom):
        if os.name == "nt":
            from h3rm35_push_plugin_test import windows_files as files
            w = files.require_native()
            current, _allowed, system = files._principals(w)
            w.win32file.CreateDirectory(str(path), files._security_attributes(w, current, system, directory=True))
        else:
            path.mkdir()
    namespace={"Path":Path,"os":os,"_get_platform_default_hermes_home":lambda:native,
               "_expand_hermes_home":lambda value:Path(value),"_PINNED_PROCESS_HERMES_HOME":None,
               "_default_hermes_root_memo":None}
    actual_functions("hermes_constants.py",["get_default_hermes_root","get_process_hermes_home","get_routing_process_hermes_home"],namespace)
    constants=ModuleType("hermes_constants")
    constants.get_default_hermes_root=namespace["get_default_hermes_root"]
    constants.get_routing_process_hermes_home=namespace["get_routing_process_hermes_home"]
    monkeypatch.setitem(sys.modules,"hermes_constants",constants)
    monkeypatch.setenv("HERMES_HOME",str(native))
    default=process_store()
    host_id=default.host_id()
    binding="11111111-1111-4111-8111-111111111111"
    default.register({"schema":2,"host_id":host_id,"binding_id":binding,"host_secret":"a"*64,"enabled_kinds":["response"]})
    monkeypatch.setenv("HERMES_HOME",str(native/"profiles/research"))
    assert process_store().host_id()==host_id
    with process_store().connect() as db:
        assert db.execute("SELECT binding_id FROM registrations").fetchone()[0]==binding
    monkeypatch.setenv("HERMES_HOME",str(custom))
    custom_id=process_store().host_id()
    assert custom_id!=host_id
    monkeypatch.setenv("HERMES_HOME",str(custom/"profiles/research"))
    assert process_store().host_id()==custom_id


def test_actual_human_and_completion_hooks_use_persisted_session_not_live_key(tmp_path,monkeypatch):
    home=tmp_path/"research"; home.mkdir()
    connection=sqlite3.connect(home/"state.db")
    connection.execute("CREATE TABLE sessions(id TEXT,profile_name TEXT)")
    connection.execute("INSERT INTO sessions VALUES ('stored-session','research')")
    connection.commit(); connection.close()
    constants=ModuleType("hermes_constants"); constants.get_hermes_home=lambda:home
    profiles=ModuleType("hermes_cli.profiles"); profiles.current_profile_name=lambda default:"research"
    monkeypatch.setitem(sys.modules,"hermes_constants",constants)
    monkeypatch.setitem(sys.modules,"hermes_cli.profiles",profiles)
    store=Store(tmp_path/"push"); binding="11111111-1111-4111-8111-111111111111"
    store.register({"schema":2,"host_id":store.host_id(),"binding_id":binding,"host_secret":"a"*64,
                    "enabled_kinds":["response","approval","clarification"]})
    observer=Observer(store,event_identity)
    approval=ModuleType("tools.approval_context")
    approval._approval_session_id=contextvars.ContextVar("fixture_session",default="stored-session")
    approval.get_current_session_key=lambda default:"live-key-not-a-db-row"
    tools_module=ModuleType("tools"); tools_module.approval_context=approval
    session_context=ModuleType("gateway.session_context")
    session_context.get_session_env=lambda name:{"HERMES_SESSION_ID":"wrong-fallback", "HERMES_SESSION_PLATFORM":"desktop"}.get(name)
    monkeypatch.setitem(sys.modules,"tools",tools_module)
    monkeypatch.setitem(sys.modules,"tools.approval_context",approval)
    monkeypatch.setitem(sys.modules,"gateway.session_context",session_context)
    monkeypatch.delenv("HERMES_PLATFORM",raising=False)
    lifecycle=ModuleType("hermes_cli.lifecycle")
    observed=[]
    def invoke(name,**payload):
        observed.append((name,payload))
        if name=="on_human_input_request": observer.human_request(**payload)
        if name=="post_llm_call": observer.completed(**payload)
        return []
    lifecycle.invoke_hook=invoke
    monkeypatch.setitem(sys.modules,"hermes_cli.lifecycle",lifecycle)
    spec=importlib.util.spec_from_file_location("h3rm35_actual_human_input",UPSTREAM/"human_input_hooks.py")
    human=importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules,spec.name,human)
    spec.loader.exec_module(human)
    for kind in ("approval","clarify"):
        with human.human_input_request(kind,prompt="fixture only",session_key="other-live-key") as request:
            request.outcome="deny"
    namespace={**vars(typing),"logging":logging,"apply_llm_output_transform":lambda agent,response,**kwargs:(response,False,None)}
    actual_functions("turn_finalizer.py",["_invoke_hook_safely","_apply_output_hooks"],namespace)
    agent=SimpleNamespace(session_id="stored-session",model="fixture",_persist_disabled=False)
    result=namespace["_apply_output_hooks"](agent,"fixture response",logging.getLogger("fixture"),
        platform="desktop",effective_task_id="task",turn_id="turn",original_user_message="fixture",messages=[])
    assert result==("fixture response",False,None)
    items=[store.claim(),store.claim(),store.claim()]
    import json
    payloads=[json.loads(item["payload"]) for item in items]
    assert {p["kind"] for p in payloads}=={"approval","clarification","response"}
    assert {p["session_id"] for p in payloads}=={"stored-session"}
    assert {p["profile"] for p in payloads}=={"research"}
    assert all("fixture response" not in item["payload"] and "fixture only" not in item["payload"] for item in items)
    assert any(payload.get("session_key")=="other-live-key" for _,payload in observed)


def test_actual_api_mount_function_loads_directory_route_and_gates_disabled(tmp_path,monkeypatch):
    import importlib
    server=ModuleType("hermes_cli.web_server")
    server._require_token=lambda request:None
    commands=ModuleType("hermes_cli.plugins_cmd")
    enabled={"h3rm35-push"}
    commands._get_enabled_set=lambda:enabled
    commands._get_disabled_set=lambda:set()
    isolation=ModuleType("hermes_cli.plugin_isolation")
    isolation.ISOLATION_HOST="host"; isolation.isolation_mode=lambda:"in-process"
    monkeypatch.setitem(sys.modules,"hermes_cli.web_server",server)
    monkeypatch.setitem(sys.modules,"hermes_cli.plugins_cmd",commands)
    monkeypatch.setitem(sys.modules,"hermes_cli.plugin_isolation",isolation)
    plugin={"name":"h3rm35-push","source":"user","_api_file":"plugin_api.py","_dir":str(ROOT/"dashboard")}
    server._get_dashboard_plugins=lambda:[plugin]
    async def scope(): yield
    namespace={**vars(typing),"Path":Path,"importlib":importlib,"sys":sys,"Depends":Depends,
               "_log":logging.getLogger("fixture"),"_plugin_route_secret_scope":scope}
    actual_functions("web_server_dashboard.py",["_plugin_api_mount_skip_reason","_mount_plugin_api_routes"],namespace)
    server.app=FastAPI()
    namespace["_mount_plugin_api_routes"]()
    mounted = sys.modules["_h3rm35_push_host_core"]
    monkeypatch.setattr(mounted,"supported_host",lambda:True)
    monkeypatch.setattr(mounted,"process_store",lambda:Store(tmp_path/"push"))
    async def status():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url="http://fixture") as client:
            return (await client.get("/api/plugins/h3rm35-push/capabilities")).status_code
    assert asyncio.run(status()) == 200
    enabled.clear()
    server.app=FastAPI()
    namespace["_mount_plugin_api_routes"]()
    assert asyncio.run(status()) == 404


def test_actual_context_registration_and_unload_stops_real_idle_worker(tmp_path,monkeypatch):
    import h3rm35_push_plugin_test as plugin
    path=UPSTREAM/"plugins.py"
    tree=ast.parse(path.read_text(encoding="utf-8"))
    klass=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="PluginContext")
    required={"__init__","_track","_track_callback","register_hook","on_unload"}
    methods=[node for node in klass.body if isinstance(node,ast.FunctionDef) and node.name in required]
    assert {node.name for node in methods}==required
    actual=ast.ClassDef(name="PluginContext",bases=[],keywords=[],body=methods,decorator_list=[])
    module=ast.Module(body=[ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0),actual],type_ignores=[])
    ast.fix_missing_locations(module)
    namespace={**vars(typing),"logger":logging.getLogger("fixture"),"VALID_HOOKS":{"post_llm_call","on_human_input_request"}}
    exec(compile(module,str(path),"exec"),namespace)
    class Manager:
        def __init__(self): self._hooks={}; self.records=[]
        def _track_registration(self,manifest,kind,key,release,**kwargs):
            handle=SimpleNamespace(kind=kind,key=key,release=release)
            self.records.append(handle)
            return handle
        def _remove_callback(self,mapping,key,callback): mapping[key].remove(callback)
    manager=Manager()
    context=namespace["PluginContext"](SimpleNamespace(name="h3rm35-push"),manager)
    monkeypatch.setattr(plugin,"process_store",lambda:Store(tmp_path/"push"))
    monkeypatch.setattr(plugin,"supported_host",lambda:True)
    monkeypatch.setattr(plugin,"supports_private_storage",lambda:True)
    assert plugin.register(context) is None
    assert set(manager._hooks)=={"post_llm_call","on_human_input_request"}
    cleanup=next(handle for handle in manager.records if handle.kind=="on_unload")
    worker=cleanup.release.__self__
    assert worker.thread.is_alive()
    for handle in reversed(manager.records): handle.release()
    worker.thread.join(timeout=0.2)
    assert worker.stopped.is_set() and not worker.thread.is_alive()
    assert all(not handlers for handlers in manager._hooks.values())
    # Unsupported private storage is rejected before registration/thread start.
    monkeypatch.setattr(plugin,"supports_private_storage",lambda:False)
    manager=Manager()
    assert plugin.register(namespace["PluginContext"](SimpleNamespace(name="h3rm35-push"),manager)) is None
    assert not manager.records and not manager._hooks
