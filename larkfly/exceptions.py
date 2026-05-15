"""Exception types for the Larkfly camera client."""
from . import types as t


class LarkflyError(Exception):
    """Base for all errors raised by this package."""


class TransportError(LarkflyError):
    """TCP / socket / framing problem (not a PTP-level error)."""


class InitFailError(LarkflyError):
    """Camera rejected the PTP-IP InitCommand handshake."""
    def __init__(self, reason: int, hint: str = ""):
        self.reason = reason
        self.hint = hint
        msg = f"InitFail reason=0x{reason:08x}"
        if hint:
            msg += f" — {hint}"
        super().__init__(msg)


class PtpError(LarkflyError):
    """Camera returned a non-OK PTP response code."""
    def __init__(self, response_code: int, op: int = None, context: str = ""):
        self.response_code = response_code
        self.op = op
        self.context = context
        name = t.RC_NAMES.get(response_code, "?")
        msg = f"PTP error 0x{response_code:04x} ({name})"
        if op is not None:
            msg += f" on op 0x{op:04x}"
        if context:
            msg += f" — {context}"
        super().__init__(msg)


class DeviceBusyError(PtpError):
    """Convenience subclass for the common 'session already open' state."""
    def __init__(self, op: int = None):
        super().__init__(t.RC_DEVICE_BUSY, op,
                         "previous session still open; client should send "
                         "CloseSession first")
