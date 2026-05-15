"""larkfly — Python client for the Larkfly A6+ / iCatch action camera
PTP-IP protocol.

Tested against camera model 'V11' (the marketing name 'Larkfly A6+'
maps to iCatch product code 'V11'), firmware 20251206.

Quick start:
    from larkfly import Camera
    with Camera('192.168.1.1', bind='192.168.1.10') as cam:
        info = cam.device_info()
        print(info['model'])
        handle = cam.take_photo()
"""
from .camera import Camera
from .exceptions import (
    LarkflyError, TransportError, InitFailError, PtpError, DeviceBusyError,
)
from . import types
from . import protocol

__all__ = [
    'Camera',
    'LarkflyError', 'TransportError', 'InitFailError', 'PtpError', 'DeviceBusyError',
    'types', 'protocol',
]
