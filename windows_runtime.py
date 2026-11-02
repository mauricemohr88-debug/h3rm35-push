"""Lazy native Win32 bindings; importing this module has no filesystem effects."""

from __future__ import annotations

import os
from types import SimpleNamespace


def _win32():
    if os.name != "nt":
        raise RuntimeError("native Windows APIs are unavailable")
    import ntsecuritycon
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32security

    return SimpleNamespace(
        ntsecuritycon=ntsecuritycon, pywintypes=pywintypes, win32api=win32api,
        win32con=win32con, win32file=win32file, win32security=win32security,
    )


def _current_sid():
    w = _win32()
    token = w.win32security.OpenProcessToken(w.win32api.GetCurrentProcess(), w.win32con.TOKEN_QUERY)
    try:
        return w.win32security.GetTokenInformation(token, w.win32security.TokenUser)[0]
    finally:
        token.Close()


def _system_sid():
    return _win32().win32security.ConvertStringSidToSid("S-1-5-18")
