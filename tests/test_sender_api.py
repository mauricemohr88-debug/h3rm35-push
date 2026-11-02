import asyncio
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import ModuleType
import urllib.error
import uuid

from fastapi import FastAPI, HTTPException
import httpx
import pytest

from h3rm35_push_plugin_test import sender
from h3rm35_push_plugin_test.core import Store


class Response:
    def __init__(self, body, status=200):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, count): return self.body[:count]


def discovery(**changes):
    return {"schema":2,"enabled":True,"relay_origin":"https://push.example",**changes}


def item():
    return {"event_id":"a"*64,"payload":json.dumps({"event_id":"a"*64}),"host_secret":"b"*64}


def test_publisher_discovery_is_fixed_bounded_cached_and_secret_free(monkeypatch):
    calls = []
    class Opener:
        def open(self, req, timeout):
            calls.append(req)
            return Response(discovery())
    monkeypatch.setattr(sender,"opener",lambda:Opener())
    monkeypatch.setattr(sender,"_cached",None)
    assert sender.publisher_origin() == "https://push.example"
    assert sender.publisher_origin() == "https://push.example"
    assert calls == ["https://kiablauf.de/h3rm35/push-service.json"]


@pytest.mark.parametrize("body", [discovery(schema=True), discovery(enabled=False), discovery(extra="bad"),
    discovery(relay_origin="http://push.example"),discovery(relay_origin="https://user:secret@push.example"),
    discovery(relay_origin="https://push.example/path"),discovery(relay_origin="https://push.example?"),
    discovery(relay_origin="https://push.example#"),discovery(relay_origin="https://push.example/"),
    b'x'*2049,b'{"schema":2,"schema":2,"enabled":true,"relay_origin":"https://push.example"}'])
def test_publisher_discovery_fails_closed(monkeypatch, body):
    class Opener:
        def open(self,*args,**kwargs): return Response(body)
    monkeypatch.setattr(sender,"opener",lambda:Opener())
    monkeypatch.setattr(sender,"_cached",None)
    with pytest.raises(ValueError): sender.publisher_origin()


@pytest.mark.parametrize("status,expected",[(401,"revoke"),(403,"revoke"),(410,"revoke"),
                                          (429,"retry"),(503,"retry"),(400,"done"),(302,"done")])
def test_relay_status_never_redirects_or_refreshes_capability(monkeypatch,status,expected):
    monkeypatch.setattr(sender,"publisher_origin",lambda:"https://push.example")
    calls = []
    class Opener:
        def open(self,request,timeout):
            calls.append(request)
            raise urllib.error.HTTPError(request.full_url,status,"redacted",{},io.BytesIO(b"not logged"))
    monkeypatch.setattr(sender,"opener",lambda:Opener())
    assert sender.send(item()) == expected
    assert len(calls)==1 and calls[0].full_url == "https://push.example/v1/events"
    assert calls[0].get_header("Authorization") == "Bearer "+"b"*64
    assert sender.NoRedirect().redirect_request(None,None,302,"",{},"https://evil.example") is None


def test_send_accepted_metadata_only(monkeypatch):
    monkeypatch.setattr(sender,"publisher_origin",lambda:"https://push.example")
    class Opener:
        def open(self,request,timeout):
            assert request.data == item()["payload"].encode()
            return Response({"event_id":"a"*64,"status":"pending"},202)
    monkeypatch.setattr(sender,"opener",lambda:Opener())
    assert sender.send(item()) == "done"


@pytest.fixture
def api(tmp_path, monkeypatch):
    path=Path(__file__).resolve().parents[1]/"dashboard/plugin_api.py"
    spec=importlib.util.spec_from_file_location("h3rm35_push_api_test",path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    store=Store(tmp_path/"push")
    monkeypatch.setattr(mod.core,"process_store",lambda:store)
    monkeypatch.setattr(mod.core,"supported_host",lambda:True)
    server=ModuleType("hermes_cli.web_server")
    def authenticate(request):
        if request.headers.get("Authorization") != "Bearer existing-hermes-session":
            raise HTTPException(401,"unauthorized")
    server._require_token=authenticate
    monkeypatch.setitem(sys.modules,"hermes_cli.web_server",server)
    app=FastAPI()
    app.include_router(mod.router,prefix="/api/plugins/h3rm35-push")
    return app,store,mod


def test_api_requires_stock_auth_before_body_and_scopes_devices(api):
    app,store,_=api
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            prefix="/api/plugins/h3rm35-push"
            assert (await client.get(prefix+"/capabilities")).status_code==401
            assert (await client.post(prefix+"/register",content=b'x'*3000)).status_code==401
            headers={"Authorization":"Bearer existing-hermes-session"}
            capability=(await client.get(prefix+"/capabilities",headers=headers)).json()
            assert capability=={"schema":2,"host_id":store.host_id(),"events":["approval","clarification","response"]}
            first=str(uuid.uuid4()); second=str(uuid.uuid4())
            value={"schema":2,"host_id":capability["host_id"],"binding_id":first,
                   "host_secret":"a"*64,"enabled_kinds":["response"]}
            response=await client.post(prefix+"/register",headers=headers,json=value)
            assert response.status_code==200 and "host_secret" not in response.text
            assert (await client.post(prefix+"/register",headers=headers,json=value)).json()==response.json()
            await client.post(prefix+"/register",headers=headers,json={**value,"binding_id":second})
            assert (await client.post(prefix+"/register",headers=headers,json={**value,"host_secret":"b"*64})).status_code==409
            assert (await client.post(prefix+"/register",headers=headers,content=b'x'*2049)).status_code==413
            assert (await client.post(prefix+"/register",headers=headers,content=b'{"a":1,"a":2}')).status_code==400
            assert (await client.delete(prefix+"/registrations/"+first,headers=headers)).status_code==200
            with store.connect() as db:
                assert [r[0] for r in db.execute("SELECT binding_id FROM registrations")]==[second]
    asyncio.run(run())


def test_older_host_does_not_advertise_unsupported_events(api,monkeypatch):
    app,_,mod=api
    monkeypatch.setattr(mod.core,"supported_host",lambda:False)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            response=await client.get("/api/plugins/h3rm35-push/capabilities",headers={"Authorization":"Bearer existing-hermes-session"})
            assert response.status_code==503
            assert response.json()=={"detail":"host_update_required"}
    asyncio.run(run())


def test_native_windows_store_is_explicitly_not_qualified(api,monkeypatch):
    app,_,mod=api
    monkeypatch.setattr(mod.core,"supports_private_storage",lambda:False)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
            response=await client.get("/api/plugins/h3rm35-push/capabilities",headers={"Authorization":"Bearer existing-hermes-session"})
            assert response.status_code==503
            assert response.json()=={"detail":"native_windows_storage_not_supported"}
    asyncio.run(run())
