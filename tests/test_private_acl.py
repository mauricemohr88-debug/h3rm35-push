from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys

import pytest

from h3rm35_push_plugin_test import core


@pytest.mark.parametrize("output", [
    b"drwx------+ 2 user staff 64 Jan 1 00:00 /private/store\n 0: group:everyone allow read\n",
    b"-rw-------+ 1 user staff 64 Jan 1 00:00 /private/store\n",
    b"-rw-------@ 1 user staff 64 Jan 1 00:00 /private/store\n 0: user:other allow read\n",
    b"-rw-------? 1 user staff 64 Jan 1 00:00 /private/store\n",
    b"", b"x"*8193,
])
def test_macos_acl_or_ambiguous_metadata_fails_closed(monkeypatch,output):
    monkeypatch.setattr(core,"sys",SimpleNamespace(platform="darwin"))
    calls=[]
    def run(args,**kwargs):
        calls.append((args,kwargs))
        return SimpleNamespace(returncode=0,stdout=output)
    monkeypatch.setattr(core.subprocess,"run",run)
    with pytest.raises(ValueError): core.assert_no_extended_acl(Path("/private/store"))
    assert calls[0][0]==["/bin/ls","-lde","--","/private/store"]
    assert calls[0][1]["timeout"]==2 and not calls[0][1].get("shell",False)
    assert calls[0][1]["stderr"]==subprocess.DEVNULL


@pytest.mark.parametrize("kind",["timeout","failure","exec"])
def test_unverifiable_macos_acl_is_rejected(monkeypatch,kind):
    monkeypatch.setattr(core,"sys",SimpleNamespace(platform="darwin"))
    def run(*args,**kwargs):
        if kind=="timeout": raise subprocess.TimeoutExpired("ls",2)
        if kind=="exec": raise OSError("synthetic unavailable")
        return SimpleNamespace(returncode=1,stdout=b"")
    monkeypatch.setattr(core.subprocess,"run",run)
    with pytest.raises(ValueError,match="cannot be verified"):
        core.assert_no_extended_acl(Path("/private/store"))


@pytest.mark.parametrize("marker",[b"",b"@"])
def test_plain_macos_metadata_or_xattrs_without_acl_are_accepted(monkeypatch,marker):
    monkeypatch.setattr(core,"sys",SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(core.subprocess,"run",lambda *a,**kw:SimpleNamespace(
        returncode=0,stdout=b"-rw-------"+marker+b" 1 user staff 64 Jan 1 00:00 /private/store\n"))
    core.assert_no_extended_acl(Path("/private/store"))


def test_posix_linux_mode_policy_does_not_run_macos_tool(monkeypatch):
    monkeypatch.setattr(core,"sys",SimpleNamespace(platform="linux"))
    monkeypatch.setattr(core.subprocess,"run",lambda *a,**kw:pytest.fail("unexpected macOS subprocess"))
    core.assert_no_extended_acl(Path("/private/store"))


@pytest.mark.skipif(sys.platform!="darwin",reason="actual macOS ACL fixture")
@pytest.mark.parametrize("target",["directory","database"])
def test_actual_macos_private_fixture_acl_is_rejected_without_removal(tmp_path,target):
    store=core.Store(tmp_path/"push")
    path=store.directory if target=="directory" else store.path
    permission="list" if target=="directory" else "read"
    subprocess.run(["/bin/chmod","+a","everyone allow "+permission,str(path)],check=True,
                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=2)
    with pytest.raises(ValueError,match="ACL"):
        core.Store(store.directory)
    # The extension refuses access; it never removes or rewrites the ACL.
    listing=subprocess.run(["/bin/ls","-lde","--",str(path)],capture_output=True,check=True,timeout=2)
    assert b"group:everyone" in listing.stdout
