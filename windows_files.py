"""Native Windows file ownership for the private notification store.

Adapted from H3rm35's MIT-licensed atomic Windows storage adapter. This copy is
standalone and does not import or change a running Hermes installation.

The SQL layer owns transactions and schema checks. This layer holds native
identities, an OS-released metadata lock, and non-delete-shared handles until
that work ends. It does not repair existing permissions or claim that flushing
a file handle is a directory-fsync or a power-loss guarantee.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import math
from pathlib import Path
import re
import time
from typing import Any
import uuid


_OPEN_REPARSE_POINT = 0x00200000
_WRITE_THROUGH = 0x80000000
_MOVE_WRITE_THROUGH = 0x8
_DIRECTORY = 0x10
_REPARSE_POINT = 0x400
_READ_ATTRIBUTES = 0x80
_WRITE_RIGHTS = 0x000D0156 | 0x10000000 | 0x40000000
_ADMINISTRATORS_SID = "S-1-5-32-544"
_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")


class WindowsStorageError(ValueError):
    """Native storage is unavailable or does not meet the private-file contract."""


class WindowsStorageIdentityError(WindowsStorageError):
    """An already-authorized file or home belongs to another generation."""


def require_native():
    """Load actual Windows APIs without inspecting or modifying any files."""
    from .windows_runtime import _win32

    try:
        w = _win32()
    except (ImportError, RuntimeError, OSError) as exc:
        raise WindowsStorageError("atomic storage requires native Windows APIs") from exc
    methods = {
        "win32file": (
            "CreateFile", "CreateDirectory", "CloseHandle", "GetFileInformationByHandle",
            "GetFinalPathNameByHandle", "GetFileType", "GetVolumePathName", "GetDriveType",
            "LockFileEx", "UnlockFileEx", "FlushFileBuffers", "MoveFileEx",
        ),
        "win32security": (
            "GetSecurityInfo", "ConvertSidToStringSid", "ConvertStringSidToSid", "ACL",
            "SECURITY_DESCRIPTOR", "SECURITY_ATTRIBUTES", "OpenProcessToken", "GetTokenInformation",
        ),
        "win32api": ("GetCurrentProcess", "GetVolumeInformation"),
        "pywintypes": ("OVERLAPPED",),
    }
    if any(not callable(getattr(getattr(w, module), name, None))
           for module, names in methods.items() for name in names):
        raise WindowsStorageError("atomic storage requires complete native Windows APIs")
    constants = {
        "win32con": (
            "FILE_TYPE_DISK", "DRIVE_FIXED", "FILE_PERSISTENT_ACLS", "READ_CONTROL", "GENERIC_READ",
            "GENERIC_WRITE", "FILE_SHARE_READ", "FILE_SHARE_WRITE", "FILE_FLAG_BACKUP_SEMANTICS",
            "FILE_ATTRIBUTE_NORMAL", "CREATE_NEW", "OPEN_EXISTING", "LOCKFILE_EXCLUSIVE_LOCK",
            "LOCKFILE_FAIL_IMMEDIATELY", "TOKEN_QUERY",
        ),
        "win32security": (
            "TokenUser", "ACL_REVISION", "OBJECT_INHERIT_ACE", "CONTAINER_INHERIT_ACE", "INHERIT_ONLY_ACE",
            "NO_PROPAGATE_INHERIT_ACE", "SE_DACL_PROTECTED", "SE_FILE_OBJECT", "OWNER_SECURITY_INFORMATION",
            "DACL_SECURITY_INFORMATION", "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE",
        ),
        "ntsecuritycon": ("FILE_ALL_ACCESS",),
    }
    if any(type(getattr(getattr(w, module), name, None)) is not int
           for module, names in constants.items() for name in names):
        raise WindowsStorageError("atomic storage requires native Windows security constants")
    return w


def _sid(w, value) -> str:
    return w.win32security.ConvertSidToStringSid(value)


def _principals(w):
    from .windows_runtime import _current_sid, _system_sid

    current, system = _current_sid(), _system_sid()
    return current, {_sid(w, current), _sid(w, system)}, system


def _security_attributes(w, current, system, *, directory: bool):
    security = w.win32security
    acl = security.ACL()
    inheritance = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if directory else 0
    for principal in {_sid(w, value): value for value in (current, system)}.values():
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, inheritance,
                                 w.ntsecuritycon.FILE_ALL_ACCESS, principal)
    descriptor = security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(current, False)
    descriptor.SetSecurityDescriptorDacl(True, acl, False)
    descriptor.SetSecurityDescriptorControl(security.SE_DACL_PROTECTED, security.SE_DACL_PROTECTED)
    attributes = security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def _verify_security(w, handle, current, allowed, *, role: str) -> None:
    security = w.win32security
    descriptor = security.GetSecurityInfo(
        handle, security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
    )
    if _sid(w, descriptor.GetSecurityDescriptorOwner()) != _sid(w, current):
        raise WindowsStorageError("atomic storage owner is not the current Windows account")
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        raise WindowsStorageError("atomic storage has a null DACL")
    control, _revision = descriptor.GetSecurityDescriptorControl()
    if role != "root" and not control & security.SE_DACL_PROTECTED:
        raise WindowsStorageError("atomic metadata DACL is not protected")
    effective: dict[str, int] = {}
    inherited: dict[str, int] = {}
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        ace_type, flags = ace[0]
        mask, principal = int(ace[1]) & 0xFFFFFFFF, _sid(w, ace[-1])
        if role == "root":
            if ace_type == security.ACCESS_DENIED_ACE_TYPE:
                continue
            if ace_type != security.ACCESS_ALLOWED_ACE_TYPE:
                raise WindowsStorageError("atomic profile has an unsupported ACL entry")
            if flags & security.INHERIT_ONLY_ACE:
                # These rights do not apply to this home; the explicit protected
                # metadata DACL prevents them from reaching the private store.
                continue
            if principal not in allowed | {_ADMINISTRATORS_SID} and mask & _WRITE_RIGHTS:
                raise WindowsStorageError("atomic profile permits another account to modify storage")
            continue
        if ace_type != security.ACCESS_ALLOWED_ACE_TYPE or principal not in allowed:
            raise WindowsStorageError("atomic metadata has a non-private ACL entry")
        if not flags & security.INHERIT_ONLY_ACE:
            effective[principal] = effective.get(principal, 0) | mask
        inheritance = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE
        if flags & inheritance == inheritance and not flags & security.NO_PROPAGATE_INHERIT_ACE:
            inherited[principal] = inherited.get(principal, 0) | mask
    if role == "root":
        return
    full = w.ntsecuritycon.FILE_ALL_ACCESS
    if any(effective.get(principal, 0) & full != full for principal in allowed):
        raise WindowsStorageError("atomic metadata lacks private account access")
    if role == "directory" and any(inherited.get(principal, 0) & full != full for principal in allowed):
        raise WindowsStorageError("atomic metadata directory does not privately inherit journal permissions")


def _identity(info) -> tuple[int, int]:
    # This is NTFS's documented 64-bit file index, paired with its volume ID.
    # ReFS's different 128-bit identity contract is excluded by _local_volume.
    return int(info[4]) & 0xFFFFFFFF, ((int(info[8]) & 0xFFFFFFFF) << 32) | (int(info[9]) & 0xFFFFFFFF)


def _final_path(w, handle) -> Path:
    raw = w.win32file.GetFinalPathNameByHandle(handle, 0)
    if raw.startswith("\\\\?\\"):
        raw = raw[4:]
    path = Path(raw)
    if not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive):
        raise WindowsStorageError("atomic metadata requires a local drive-letter path")
    return path


def _verify_handle(w, handle, path, current, allowed, *, role, expected=None):
    info = w.win32file.GetFileInformationByHandle(handle)
    is_directory = role in {"root", "directory"}
    if w.win32file.GetFileType(handle) != w.win32con.FILE_TYPE_DISK or (
        bool(info[0] & _DIRECTORY) != is_directory or info[0] & _REPARSE_POINT
    ) or (not is_directory and info[7] != 1):
        raise WindowsStorageError("atomic metadata has an unsafe file type, reparse point or hard link")
    if _final_path(w, handle) != path:
        raise WindowsStorageIdentityError("atomic metadata handle escaped its original path")
    identity = _identity(info)
    if expected is not None and identity != expected:
        raise WindowsStorageIdentityError("atomic metadata file generation changed")
    _verify_security(w, handle, current, allowed, role=role)
    return identity


def _local_volume(w, home: Path) -> int:
    if not home.is_absolute() or not re.fullmatch(r"[A-Za-z]:", home.drive):
        raise WindowsStorageError("atomic metadata requires a local drive-letter path")
    volume = w.win32file.GetVolumePathName(str(home))
    if Path(volume) != Path(home.anchor) or w.win32file.GetDriveType(volume) != w.win32con.DRIVE_FIXED:
        raise WindowsStorageError("atomic metadata requires a local fixed volume")
    _label, serial, _maximum, flags, filesystem = w.win32api.GetVolumeInformation(volume)
    if filesystem.casefold() != "ntfs" or not flags & w.win32con.FILE_PERSISTENT_ACLS:
        raise WindowsStorageError("atomic metadata requires local NTFS with persistent ACLs")
    return int(serial) & 0xFFFFFFFF


def _open_handle(w, path, *, directory=False, create=False, attributes=None):
    access = w.win32con.READ_CONTROL | _READ_ATTRIBUTES
    if not directory:
        access |= w.win32con.GENERIC_READ | w.win32con.GENERIC_WRITE
    share = w.win32con.FILE_SHARE_READ | w.win32con.FILE_SHARE_WRITE
    flags = _OPEN_REPARSE_POINT | (w.win32con.FILE_FLAG_BACKUP_SEMANTICS if directory else
                                  w.win32con.FILE_ATTRIBUTE_NORMAL)
    if create and not directory:
        flags |= _WRITE_THROUGH
    return w.win32file.CreateFile(str(path), access, share, attributes,
                                 w.win32con.CREATE_NEW if create else w.win32con.OPEN_EXISTING,
                                 flags, None)


def _open_private_file(w, path, opened, attributes, *, create):
    handle = _open_handle(w, path, create=create, attributes=attributes if create else None)
    opened.callback(w.win32file.CloseHandle, handle)
    return handle


def _lock(w, handle, opened, timeout: float) -> None:
    overlapped = w.pywintypes.OVERLAPPED()
    flags = w.win32con.LOCKFILE_EXCLUSIVE_LOCK | w.win32con.LOCKFILE_FAIL_IMMEDIATELY
    deadline = time.monotonic() + timeout
    while True:
        try:
            w.win32file.LockFileEx(handle, flags, 1, 0, overlapped)
            opened.callback(w.win32file.UnlockFileEx, handle, 1, 0, overlapped)
            return
        except w.pywintypes.error as exc:
            if exc.winerror != 33:  # ERROR_LOCK_VIOLATION, not sharing or permission failures.
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WindowsStorageError("atomic metadata lock is busy") from exc
            time.sleep(min(0.01, remaining))


@dataclass(repr=False)
class WindowsStorage:
    home: Path
    created: bool
    root: tuple[int, int]
    directory: tuple[int, int]
    database: tuple[int, int]
    lock: tuple[int, int]
    journal: tuple[int, int]
    _w: Any = field(repr=False)
    _current: Any = field(repr=False)
    _allowed: set[str] = field(repr=False)
    _paths: dict[str, Path] = field(repr=False)
    _handles: dict[str, Any] = field(repr=False)

    def verify(self) -> None:
        """Check held native objects and their still-current pathname bindings."""
        try:
            volume = _local_volume(self._w, self.home)
            for role, handle in self._handles.items():
                expected = getattr(self, role)
                actual = _verify_handle(self._w, handle, self._paths[role], self._current, self._allowed,
                                        role=role, expected=expected)
                if actual[0] != volume:
                    raise WindowsStorageIdentityError("atomic metadata volume generation changed")
            self._verify_no_wal()
        except (OSError, self._w.pywintypes.error) as exc:
            raise WindowsStorageError("atomic Windows metadata verification failed") from exc

    def _verify_no_wal(self) -> None:
        for suffix in ("-wal", "-shm"):
            path = Path(str(self._paths["database"]) + suffix)
            try:
                handle = _open_handle(self._w, path)
            except self._w.pywintypes.error as exc:
                if exc.winerror in {2, 3}:
                    continue
                raise
            try:
                raise WindowsStorageError("atomic metadata must not use WAL sidecars")
            finally:
                self._w.win32file.CloseHandle(handle)

    def flush(self) -> None:
        """Flush file data using genuine Windows handles, never fake directory fsync."""
        self.verify()
        try:
            self._w.win32file.FlushFileBuffers(self._handles["database"])
            self._w.win32file.FlushFileBuffers(self._handles["journal"])
            self._w.win32file.FlushFileBuffers(self._handles["lock"])
        except (OSError, self._w.pywintypes.error) as exc:
            raise WindowsStorageError("atomic Windows metadata flush failed") from exc
        self.verify()


def _open_directory_storage(w, canonical, directory, database_name, lock_name, root_handle, current, allowed,
                            system, opened, *, directory_handle=None, expected_identity=None, create=False,
                            created=False, lock_timeout=2.0):
    paths = {"root": canonical, "directory": directory, "database": directory / database_name,
             "lock": directory / lock_name, "journal": directory / (database_name + "-journal")}
    handles = {"root": root_handle}
    identities = {"root": _verify_handle(w, root_handle, canonical, current, allowed, role="root",
                                          expected=getattr(expected_identity, "root", None))}
    handles["directory"] = directory_handle or _open_handle(w, directory, directory=True)
    opened.callback(w.win32file.CloseHandle, handles["directory"])
    identities["directory"] = _verify_handle(
        w, handles["directory"], directory, current, allowed, role="directory",
        expected=getattr(expected_identity, "directory", None),
    )
    attributes = _security_attributes(w, current, system, directory=False)
    handles["lock"] = _open_private_file(w, paths["lock"], opened, attributes, create=create)
    identities["lock"] = _verify_handle(w, handles["lock"], paths["lock"], current, allowed, role="lock",
                                          expected=getattr(expected_identity, "lock", None))
    _lock(w, handles["lock"], opened, lock_timeout)
    for role in ("database", "journal"):
        handles[role] = _open_private_file(w, paths[role], opened, attributes, create=create)
        identities[role] = _verify_handle(w, handles[role], paths[role], current, allowed, role=role,
                                           expected=getattr(expected_identity, role, None))
    storage = WindowsStorage(canonical, created, **identities, _w=w, _current=current,
                             _allowed=allowed, _paths=paths, _handles=handles)
    storage.verify()
    return storage


def _publish_stage(w, canonical, directory_name, database_name, lock_name, root_handle, current, allowed,
                   system, initialize, lock_timeout):
    stage = canonical / (directory_name + ".creating-" + uuid.uuid4().hex)
    w.win32file.CreateDirectory(str(stage), _security_attributes(w, current, system, directory=True))
    # Failed stages intentionally remain private for inspection. Removing them
    # after an uncertain initialization would erase the only local evidence.
    with contextlib.ExitStack() as staged:
        storage = _open_directory_storage(
            w, canonical, stage, database_name, lock_name, root_handle, current, allowed, system, staged,
            create=True, created=True, lock_timeout=lock_timeout,
        )
        initialize(storage._paths["database"])
        storage.flush()
    try:
        w.win32file.MoveFileEx(str(stage), str(canonical / directory_name), _MOVE_WRITE_THROUGH)
        return True
    except w.pywintypes.error as exc:
        if exc.winerror != 183:
            raise
        # Another fully initialized publisher may have won. The ordinary open
        # below must verify it; no replacing, merging, or reinitializing occurs.
        return False


def _expected_valid(expected_identity) -> None:
    if expected_identity is None:
        return
    if not isinstance(getattr(expected_identity, "home", None), Path) or any(
        not isinstance(value := getattr(expected_identity, role, None), tuple) or len(value) != 2
        or any(type(part) is not int for part in value)
        for role in ("root", "directory", "database", "lock", "journal")
    ):
        raise WindowsStorageIdentityError("atomic Windows metadata identity is incomplete")


@contextlib.contextmanager
def open_storage(home, directory_name, database_name, lock_name, *, initialize=None,
                 expected_identity=None, lock_timeout=2.0):
    """Pin private NTFS storage, publishing new stores only after initialization.

    ``initialize(stage_database_path)`` is called only for a new private stage,
    never for an existing final directory. The callback must finish and close
    its PERSIST/FULL SQLite transaction before returning.
    """
    w = require_native()
    if any(not isinstance(name, str) or not 0 < len(name) <= 128 or not _NAME.fullmatch(name)
           or name in {".", ".."} or name.endswith(".") for name in (directory_name, database_name, lock_name)):
        raise WindowsStorageError("invalid atomic metadata component names")
    if len({directory_name, database_name, lock_name, database_name + "-journal"}) != 4:
        raise WindowsStorageError("atomic metadata component names must be distinct")
    if isinstance(lock_timeout, bool) or not isinstance(lock_timeout, (int, float)) or (
        not math.isfinite(lock_timeout) or not 0 < lock_timeout <= 2.0
    ):
        raise WindowsStorageError("atomic metadata lock timeout is invalid")
    _expected_valid(expected_identity)
    try:
        canonical = Path(home).resolve(strict=True)
        if expected_identity is not None and canonical != expected_identity.home:
            raise WindowsStorageIdentityError("atomic profile root generation changed")
        volume = _local_volume(w, canonical)
        current, allowed, system = _principals(w)
        directory = canonical / directory_name
        with contextlib.ExitStack() as opened:
            root_handle = _open_handle(w, canonical, directory=True)
            opened.callback(w.win32file.CloseHandle, root_handle)
            root = _verify_handle(w, root_handle, canonical, current, allowed, role="root",
                                  expected=getattr(expected_identity, "root", None))
            if root[0] != volume:
                raise WindowsStorageIdentityError("atomic profile volume changed")
            created = False
            try:
                directory_handle = _open_handle(w, directory, directory=True)
            except w.pywintypes.error as exc:
                if exc.winerror not in {2, 3} or expected_identity is not None:
                    raise
                if not callable(initialize):
                    raise WindowsStorageError("new atomic storage requires staged SQL initialization") from exc
                created = _publish_stage(w, canonical, directory_name, database_name, lock_name, root_handle,
                                         current, allowed, system, initialize, float(lock_timeout))
                directory_handle = _open_handle(w, directory, directory=True)
            storage = _open_directory_storage(
                w, canonical, directory, database_name, lock_name, root_handle, current, allowed, system, opened,
                directory_handle=directory_handle, expected_identity=expected_identity, created=created,
                lock_timeout=float(lock_timeout),
            )
            yield storage
    except (OSError, w.pywintypes.error) as exc:
        raise WindowsStorageError("atomic Windows metadata storage is unavailable") from exc
