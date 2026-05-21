"""larkfly — Python client for the Larkfly A6+ / iCatch action camera
PTP-IP protocol.

Tested against the 'Larkfly A6+' action camera. 'V11' is the ODM/
white-label model code the camera reports in its ProductName property
(0x501E) — the same hardware also sells as VIRAN V11 / CERASTES V11.
It is NOT an iCatch designation; the SoC is an iCatch V37/V39-family
part (the sibling V11 hardware is specified as iCatch V39A). FwVersion
(0x501F) reports '20251206', a YYYYMMDD build-date stamp.

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
