"""Redacted macOS login-Keychain operations for machine-local secrets."""
from __future__ import annotations

import ctypes
import getpass
import warnings
from collections.abc import Callable
from typing import Protocol

from .process import AgentError, ProcessSpec, Runner, Secret


_SECURITY_TRUSTED_APPLICATION = "/usr/bin/security"
_MAX_ENROLLMENT_BYTES = 16 * 1024
_ERR_SEC_ITEM_NOT_FOUND = -25300
_GENERIC_PASSWORD_ITEM_CLASS = 0x67656E70  # genp
_SERVICE_ATTRIBUTE_TAG = 0x73766365  # svce
_ACCOUNT_ATTRIBUTE_TAG = 0x61636374  # acct
_UTF8_CF_STRING_ENCODING = 0x08000100


class _KeychainAttribute(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class _KeychainAttributeList(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("attr", ctypes.POINTER(_KeychainAttribute)),
    ]


class _CFArrayCallBacks(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_long),
        ("retain", ctypes.c_void_p),
        ("release", ctypes.c_void_p),
        ("copy_description", ctypes.c_void_p),
        ("equal", ctypes.c_void_p),
    ]


class _NativeKeychainBridge(Protocol):
    def copy_default(self) -> object: ...
    def find_generic_password(
        self, keychain: object, service: bytes, account: bytes
    ) -> object | None: ...
    def modify_item_data(self, item: object, value: bytearray) -> None: ...
    def create_security_only_access(self, trusted_path: str) -> object: ...
    def create_generic_password(
        self,
        keychain: object,
        service: bytes,
        account: bytes,
        value: bytearray,
        access: object,
    ) -> object: ...
    def release(self, reference: object) -> None: ...


class _SecurityFrameworkBridge:
    """The small Security.framework surface needed for generic-password writes."""

    def __init__(self) -> None:
        self._security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        self._core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._configure_functions()

    def _configure_functions(self) -> None:
        pointer = ctypes.POINTER(ctypes.c_void_p)
        self._security.SecKeychainCopyDefault.argtypes = [pointer]
        self._security.SecKeychainCopyDefault.restype = ctypes.c_int32
        self._security.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_void_p, pointer, pointer, pointer,
        ]
        self._security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        self._security.SecKeychainItemModifyAttributesAndData.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ]
        self._security.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        self._security.SecKeychainItemCreateFromContent.argtypes = [
            ctypes.c_uint32, ctypes.POINTER(_KeychainAttributeList), ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, pointer,
        ]
        self._security.SecKeychainItemCreateFromContent.restype = ctypes.c_int32
        self._security.SecTrustedApplicationCreateFromPath.argtypes = [
            ctypes.c_char_p, pointer,
        ]
        self._security.SecTrustedApplicationCreateFromPath.restype = ctypes.c_int32
        self._security.SecAccessCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, pointer]
        self._security.SecAccessCreate.restype = ctypes.c_int32
        self._core_foundation.CFStringCreateWithCString.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
        ]
        self._core_foundation.CFStringCreateWithCString.restype = ctypes.c_void_p
        self._core_foundation.CFArrayCreate.argtypes = [
            ctypes.c_void_p, pointer, ctypes.c_long, ctypes.c_void_p,
        ]
        self._core_foundation.CFArrayCreate.restype = ctypes.c_void_p
        self._core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        self._core_foundation.CFRelease.restype = None
        self._cf_type_array_callbacks = _CFArrayCallBacks.in_dll(
            self._core_foundation, "kCFTypeArrayCallBacks"
        )

    @staticmethod
    def _status(status: int) -> None:
        if status != 0:
            raise OSError(f"Security.framework status {status}")

    @staticmethod
    def _pointer_bytes(value: bytes) -> tuple[ctypes.Array[ctypes.c_char], ctypes.c_void_p]:
        buffer = ctypes.create_string_buffer(value)
        return buffer, ctypes.cast(buffer, ctypes.c_void_p)

    @staticmethod
    def _pointer_secret(value: bytearray) -> tuple[ctypes.Array[ctypes.c_ubyte], ctypes.c_void_p]:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer(value)
        return buffer, ctypes.cast(buffer, ctypes.c_void_p)

    def copy_default(self) -> object:
        keychain = ctypes.c_void_p()
        self._status(self._security.SecKeychainCopyDefault(ctypes.byref(keychain)))
        return keychain

    def find_generic_password(
        self, keychain: object, service: bytes, account: bytes
    ) -> object | None:
        service_buffer, service_pointer = self._pointer_bytes(service)
        account_buffer, account_pointer = self._pointer_bytes(account)
        item = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            keychain, len(service), service_pointer, len(account), account_pointer,
            None, None, ctypes.byref(item),
        )
        _ = (service_buffer, account_buffer)
        if status == _ERR_SEC_ITEM_NOT_FOUND:
            return None
        self._status(status)
        return item

    def modify_item_data(self, item: object, value: bytearray) -> None:
        value_buffer, value_pointer = self._pointer_secret(value)
        self._status(
            self._security.SecKeychainItemModifyAttributesAndData(
                item, None, len(value), value_pointer
            )
        )
        _ = value_buffer

    def create_security_only_access(self, trusted_path: str) -> object:
        trusted_application = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        applications = ctypes.c_void_p()
        access = ctypes.c_void_p()
        try:
            self._status(
                self._security.SecTrustedApplicationCreateFromPath(
                    trusted_path.encode("utf-8"), ctypes.byref(trusted_application)
                )
            )
            descriptor = self._core_foundation.CFStringCreateWithCString(
                None, b"homelab-agent local secret", _UTF8_CF_STRING_ENCODING
            )
            if not descriptor:
                raise OSError("could not create Keychain access descriptor")
            members = (ctypes.c_void_p * 1)(trusted_application)
            applications = self._core_foundation.CFArrayCreate(
                None, members, 1, ctypes.byref(self._cf_type_array_callbacks)
            )
            if not applications:
                raise OSError("could not create Keychain access list")
            self._status(
                self._security.SecAccessCreate(
                    descriptor, applications, ctypes.byref(access)
                )
            )
            return access
        finally:
            if applications:
                self.release(applications)
            if descriptor:
                self.release(descriptor)
            if trusted_application:
                self.release(trusted_application)

    def create_generic_password(
        self,
        keychain: object,
        service: bytes,
        account: bytes,
        value: bytearray,
        access: object,
    ) -> object:
        service_buffer, service_pointer = self._pointer_bytes(service)
        account_buffer, account_pointer = self._pointer_bytes(account)
        value_buffer, value_pointer = self._pointer_secret(value)
        attributes = (_KeychainAttribute * 2)(
            _KeychainAttribute(_SERVICE_ATTRIBUTE_TAG, len(service), service_pointer),
            _KeychainAttribute(_ACCOUNT_ATTRIBUTE_TAG, len(account), account_pointer),
        )
        attribute_list = _KeychainAttributeList(2, attributes)
        item = ctypes.c_void_p()
        self._status(
            self._security.SecKeychainItemCreateFromContent(
                _GENERIC_PASSWORD_ITEM_CLASS,
                ctypes.byref(attribute_list),
                len(value), value_pointer, keychain, access, ctypes.byref(item),
            )
        )
        _ = (service_buffer, account_buffer, value_buffer)
        return item

    def release(self, reference: object) -> None:
        if reference:
            self._core_foundation.CFRelease(reference)


class MacOSKeychainBackend:
    """Update a generic password in-place or create it with a security-only ACL."""

    def __init__(self, bridge: _NativeKeychainBridge | None = None) -> None:
        self._bridge = bridge or _SecurityFrameworkBridge()

    def store(self, service: str, account: str, value: bytearray) -> None:
        keychain: object | None = None
        item: object | None = None
        access: object | None = None
        try:
            keychain = self._bridge.copy_default()
            item = self._bridge.find_generic_password(
                keychain, service.encode("utf-8"), account.encode("utf-8")
            )
            if item is not None:
                # Passing no attribute list updates only data and preserves ACLs.
                self._bridge.modify_item_data(item, value)
                return
            access = self._bridge.create_security_only_access(
                _SECURITY_TRUSTED_APPLICATION
            )
            item = self._bridge.create_generic_password(
                keychain,
                service.encode("utf-8"),
                account.encode("utf-8"),
                value,
                access,
            )
        except Exception:
            raise AgentError("Keychain enrollment failed") from None
        finally:
            if item is not None:
                self._bridge.release(item)
            if access is not None:
                self._bridge.release(access)
            if keychain is not None:
                self._bridge.release(keychain)


def _interactive_prompt(prompt: str) -> str:
    """Prompt locally and fail instead of accepting a non-hidden fallback prompt."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def _enrollment_bytes(prompt: Callable[[str], str]) -> bytearray:
    try:
        entered = prompt("Enter homelab-agent secret (input hidden): ")
    except Exception:
        raise AgentError("Keychain enrollment prompt failed") from None
    if not isinstance(entered, str):
        raise AgentError("Keychain enrollment prompt returned invalid text")
    if entered.endswith("\r\n"):
        entered = entered[:-2]
    elif entered.endswith("\n"):
        entered = entered[:-1]
    try:
        encoded = bytearray(entered.encode("utf-8"))
    except UnicodeError:
        raise AgentError("Keychain enrollment text is invalid") from None
    # Python strings cannot be reliably erased; retain this mutable buffer only
    # long enough to make the Security.framework call and zero it in ``finally``.
    if not encoded:
        raise AgentError("Keychain enrollment value must not be empty")
    if len(encoded) > _MAX_ENROLLMENT_BYTES or b"\0" in encoded:
        for index in range(len(encoded)):
            encoded[index] = 0
        raise AgentError("Keychain enrollment value is invalid")
    return encoded


class Keychain:
    """Read and enroll generic-password values without putting them in argv."""

    def __init__(
        self,
        runner: Runner | None = None,
        *,
        prompt: Callable[[str], str] = _interactive_prompt,
        native_factory: Callable[[], MacOSKeychainBackend] = MacOSKeychainBackend,
    ) -> None:
        self._runner = runner or Runner()
        self._prompt = prompt
        self._native_factory = native_factory

    def local_account(self) -> str:
        """Return the whitespace-normalized LocalHostName used as the account."""
        completed = self._runner.run(
            ProcessSpec(
                argv=("/usr/sbin/scutil", "--get", "LocalHostName"),
                display_name="local hostname lookup",
            )
        )
        account = completed.stdout.strip()
        if not account:
            raise AgentError("local hostname lookup returned no account")
        return account

    def read(self, service: str, account: str) -> Secret:
        """Read a generic-password value for the supplied public service/account."""
        completed = self._runner.run(
            ProcessSpec(
                argv=(
                    "/usr/bin/security",
                    "find-generic-password",
                    "-w",
                    "-s",
                    service,
                    "-a",
                    account,
                ),
                display_name="Keychain secret lookup",
            )
        )
        value = completed.stdout.rstrip("\r\n")
        if not value:
            raise AgentError("Keychain secret lookup returned no value")
        return Secret(value)

    def enroll(self, service: str, account: str) -> None:
        """Prompt locally, then write data through Security.framework without a shell."""
        value = _enrollment_bytes(self._prompt)
        try:
            self._native_factory().store(service, account, value)
        except AgentError:
            raise
        except Exception:
            raise AgentError("Keychain enrollment failed") from None
        finally:
            for index in range(len(value)):
                value[index] = 0
