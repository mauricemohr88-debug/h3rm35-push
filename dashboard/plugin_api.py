"""Stock-loaded API, explicitly using Stock's existing native authentication."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
_core_path = Path(__file__).resolve().parents[1] / "core.py"
_name = "_h3rm35_push_host_core"
if _name not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_name, _core_path)
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_name] = _module
    _spec.loader.exec_module(_module)
core = sys.modules[_name]


def authorize(request):
    from hermes_cli.web_server import _require_token
    _require_token(request)
    if not core.supported_host():
        raise HTTPException(503, "host_update_required")
    if not core.supports_private_storage():
        raise HTTPException(503, "native_windows_storage_not_supported")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


async def body(request):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 2048:
            raise HTTPException(413, "request_too_large")
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "invalid_registration") from None


@router.get("/capabilities")
async def capabilities(request: Request):
    authorize(request)
    try:
        host_id = await asyncio.to_thread(lambda: core.process_store().host_id())
    except (OSError, ValueError, sqlite3.Error, core.PrivateStorageError):
        raise HTTPException(503, "private_store_unavailable") from None
    return {"schema": 2, "host_id": host_id, "events": sorted(core.KINDS)}


@router.post("/register")
async def register(request: Request):
    authorize(request)
    data = await body(request)
    try:
        return await asyncio.to_thread(lambda: core.process_store().register(data))
    except core.PrivateStorageError:
        raise HTTPException(503, "private_store_unavailable") from None
    except ValueError:
        raise HTTPException(409, "registration_rejected") from None
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "private_store_unavailable") from None


@router.delete("/registrations/{binding_id}")
async def unregister(binding_id: str, request: Request):
    authorize(request)
    try:
        await asyncio.to_thread(lambda: core.process_store().remove(binding_id))
    except core.PrivateStorageError:
        raise HTTPException(503, "private_store_unavailable") from None
    except ValueError:
        raise HTTPException(400, "invalid_identifier") from None
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "private_store_unavailable") from None
    return {"ok": True}
