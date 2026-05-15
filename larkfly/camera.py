"""High-level Camera client for the iCatch / Larkfly PTP-IP protocol.

Usage:
    from larkfly import Camera

    with Camera('192.168.1.1', bind='192.168.1.10') as cam:
        info = cam.device_info()
        print(info['model'])

        # Take a photo
        handle = cam.take_photo()
        print(f"new photo handle: {handle}")

        # List + download
        for h in cam.list_objects():
            obj = cam.object_info(h)
            print(obj['filename'])

        # Video
        cam.start_recording()
        time.sleep(5)
        cam.stop_recording()
"""
from __future__ import annotations

import socket
import time
import uuid
from typing import Callable, Iterator, Optional

from . import types as t
from . import protocol as p
from .exceptions import LarkflyError, TransportError, InitFailError, PtpError, DeviceBusyError


class Camera:
    """Single-camera client over PTP-IP. Not thread-safe."""

    DEFAULT_TIMEOUT = 5.0
    DEFAULT_NAME = "localhost"  # iCatch firmware whitelists this

    def __init__(self, host: str, port: int = t.PTPIP_PORT,
                 bind: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 name: str = DEFAULT_NAME,
                 session_id: int = 1):
        """
        host: camera IP (e.g. '192.168.1.1')
        port: PTP-IP port (default 15740)
        bind: local source IP to bind the socket to. Use this when
            multiple interfaces share the camera's subnet — otherwise
            Linux may route via the wrong interface and the connect
            silently goes to the wrong host. See docs/findings.md for
            the dual-WiFi setup.
        timeout: per-recv socket timeout in seconds.
        name: initiator name to send in InitCmdReq. iCatch firmware
            only accepts 'localhost' or '' (empty); anything else
            gets InitFail reason=3.
        session_id: PTP session ID (any non-zero integer).
        """
        self.host = host
        self.port = port
        self.bind = bind
        self.timeout = timeout
        self.name = name
        self.session_id = session_id

        self._cmd_sock: Optional[socket.socket] = None
        self._evt_sock: Optional[socket.socket] = None
        self._txid = 0
        self._connection_number = 0

    # ---------- connection lifecycle --------------------------------
    def connect(self) -> None:
        """Open the command + event channels, handshake, and OpenSession."""
        guid = uuid.uuid4().bytes
        self._cmd_sock = self._tcp_connect()

        # InitCmdReq
        p.send_container(self._cmd_sock, t.PT_INIT_CMD_REQ,
                         p.encode_init_cmd_req(guid, self.name))
        ptype, body = p.recv_container(self._cmd_sock)
        if ptype == t.PT_INIT_FAIL:
            import struct
            reason = struct.unpack_from('<I', body, 0)[0]
            hint = ""
            if reason == 3 and self.name not in ('localhost', ''):
                hint = (f"iCatch firmware rejects initiator name "
                        f"{self.name!r}; only 'localhost' or '' work")
            raise InitFailError(reason, hint=hint)
        if ptype != t.PT_INIT_CMD_ACK:
            raise TransportError(
                f"expected InitCmdAck, got {t.PT_NAMES.get(ptype, ptype)}")
        ack = p.parse_init_cmd_ack(body)
        self._connection_number = ack['connection_number']

        # InitEvtReq (event channel)
        self._evt_sock = self._tcp_connect()
        import struct
        p.send_container(self._evt_sock, t.PT_INIT_EVT_REQ,
                         struct.pack('<I', self._connection_number))
        ptype, _ = p.recv_container(self._evt_sock)
        if ptype != t.PT_INIT_EVT_ACK:
            raise TransportError(
                f"expected InitEvtAck, got {t.PT_NAMES.get(ptype, ptype)}")

        # OpenSession; if camera reports a stuck prior session, close + retry
        rc, _, _ = self._raw_op(t.OP_OPEN_SESSION, [self.session_id])
        if rc == t.RC_DEVICE_BUSY:
            self._raw_op(t.OP_CLOSE_SESSION, [])
            rc, _, _ = self._raw_op(t.OP_OPEN_SESSION, [self.session_id])
        if rc != t.RC_OK:
            raise PtpError(rc, t.OP_OPEN_SESSION, "OpenSession failed")

    def close(self) -> None:
        """Cleanly close the session and TCP channels. Idempotent."""
        if self._cmd_sock is not None:
            try:
                self._raw_op(t.OP_CLOSE_SESSION, [])
            except Exception:
                pass
            try: self._cmd_sock.close()
            except Exception: pass
            self._cmd_sock = None
        if self._evt_sock is not None:
            try: self._evt_sock.close()
            except Exception: pass
            self._evt_sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def _tcp_connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        if self.bind:
            sock.bind((self.bind, 0))
        try:
            sock.connect((self.host, self.port))
        except OSError as e:
            raise TransportError(
                f"cannot connect to {self.host}:{self.port}: {e}") from e
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    # ---------- raw + checked operation primitives -------------------
    def _next_txid(self) -> int:
        self._txid += 1
        return self._txid

    def _raw_op(self, opcode: int, params: list[int] = (),
                tx_data: bytes = b'') -> tuple[int, list[int], bytes]:
        """Issue one PTP operation; collect any data phase + the final
        OpResp. Returns (response_code, response_params, received_data)."""
        if self._cmd_sock is None:
            raise LarkflyError("not connected")
        txid = self._next_txid() if self._txid != 0 else 0
        # OpenSession uses txid=0 conventionally; everything else is txid>0.
        if opcode == t.OP_OPEN_SESSION:
            txid = 0
        elif self._txid == 0:
            # If this is the first op and it's not OpenSession, bump
            self._txid = 1
            txid = 1
        else:
            txid = self._txid

        data_phase = 2 if tx_data else 1
        body = p.encode_op_req(opcode, txid, list(params), data_phase=data_phase)
        p.send_container(self._cmd_sock, t.PT_OP_REQ, body)

        if tx_data:
            import struct
            p.send_container(self._cmd_sock, t.PT_START_DATA,
                             struct.pack('<IQ', txid, len(tx_data)))
            p.send_container(self._cmd_sock, t.PT_END_DATA,
                             struct.pack('<I', txid) + tx_data)

        rx_data = b''
        while True:
            ptype, body = p.recv_container(self._cmd_sock)
            if ptype == t.PT_START_DATA:
                continue
            if ptype == t.PT_DATA or ptype == t.PT_END_DATA:
                rx_data += body[4:]  # skip txid
                continue
            if ptype == t.PT_OP_RESP:
                resp = p.parse_op_resp(body)
                self._txid = txid  # last completed
                return resp['response_code'], resp['params'], rx_data
            # ignore unsolicited events on the cmd channel
            if ptype == t.PT_EVENT:
                continue
            raise TransportError(
                f"unexpected packet type {t.PT_NAMES.get(ptype, ptype)} "
                f"in op response")

    def op(self, opcode: int, params=(), tx_data: bytes = b'',
           context: str = "") -> tuple[list[int], bytes]:
        """Checked op call. Returns (response_params, received_data).
        Raises PtpError on non-OK response."""
        rc, resp_params, data = self._raw_op(opcode, params, tx_data)
        if rc != t.RC_OK:
            raise PtpError(rc, opcode, context or t.PT_NAMES.get(opcode, ''))
        return resp_params, data

    # ---------- standard PTP operations ------------------------------
    def device_info(self) -> dict:
        _, data = self.op(t.OP_GET_DEVICE_INFO, context="GetDeviceInfo")
        info = p.parse_device_info(data)
        info['_raw_hex'] = data.hex()
        return info

    def storage_ids(self) -> list[int]:
        _, data = self.op(t.OP_GET_STORAGE_IDS, context="GetStorageIDs")
        import struct
        if not data:
            return []
        n = struct.unpack('<I', data[:4])[0]
        return [struct.unpack('<I', data[4 + i*4:8 + i*4])[0] for i in range(n)]

    def storage_info(self, storage_id: int) -> dict:
        _, data = self.op(t.OP_GET_STORAGE_INFO, [storage_id],
                          context="GetStorageInfo")
        return p.parse_storage_info(data)

    def num_objects(self, storage_id: int = 0xFFFFFFFF,
                    format_code: int = 0, association: int = 0) -> int:
        rp, _ = self.op(t.OP_GET_NUM_OBJECTS,
                        [storage_id, format_code, association],
                        context="GetNumObjects")
        return rp[0] if rp else 0

    def list_objects(self, storage_id: int = 0xFFFFFFFF,
                     format_code: int = 0, association: int = 0) -> list[int]:
        _, data = self.op(t.OP_GET_OBJECT_HANDLES,
                          [storage_id, format_code, association],
                          context="GetObjectHandles")
        import struct
        if not data:
            return []
        n = struct.unpack('<I', data[:4])[0]
        return [struct.unpack('<I', data[4 + i*4:8 + i*4])[0] for i in range(n)]

    def object_info(self, handle: int) -> dict:
        _, data = self.op(t.OP_GET_OBJECT_INFO, [handle],
                          context="GetObjectInfo")
        return p.parse_object_info(data)

    def get_object(self, handle: int) -> bytes:
        """Download the full object (photo/video) bytes."""
        _, data = self.op(t.OP_GET_OBJECT, [handle], context="GetObject")
        return data

    def get_thumb(self, handle: int) -> bytes:
        _, data = self.op(t.OP_GET_THUMB, [handle], context="GetThumb")
        return data

    def delete_object(self, handle: int) -> None:
        self.op(t.OP_DELETE_OBJECT, [handle], context="DeleteObject")

    def get_prop_desc(self, prop_code: int) -> dict:
        _, data = self.op(t.OP_GET_DEVICE_PROP_DESC, [prop_code],
                          context=f"GetDevicePropDesc(0x{prop_code:04x})")
        return p.parse_prop_desc(data)

    def get_prop_value(self, prop_code: int):
        """Returns the parsed value. Needs the property's datatype, which
        we fetch via GetDevicePropDesc."""
        desc = self.get_prop_desc(prop_code)
        _, data = self.op(t.OP_GET_DEVICE_PROP_VALUE, [prop_code],
                          context=f"GetDevicePropValue(0x{prop_code:04x})")
        v, _ = p.decode_value(data, 0, desc['datatype'])
        return v

    def set_prop_value(self, prop_code: int, value, datatype: int = None) -> None:
        """Set a property. Looks up datatype via GetDevicePropDesc if not given."""
        if datatype is None:
            desc = self.get_prop_desc(prop_code)
            datatype = desc['datatype']
        payload = p.encode_value(value, datatype)
        self.op(t.OP_SET_DEVICE_PROP_VALUE, [prop_code], tx_data=payload,
                context=f"SetDevicePropValue(0x{prop_code:04x})")

    # ---------- capture --------------------------------------------
    def take_photo(self, storage_id: int = 0, format_code: int = 0) -> Optional[int]:
        """InitiateCapture. Returns the new object handle if the camera
        reports it in resp_params[2], else None."""
        rp, _ = self.op(t.OP_INITIATE_CAPTURE, [storage_id, format_code],
                        context="InitiateCapture")
        return rp[2] if len(rp) >= 3 and rp[2] != 0 else None

    def start_recording(self, storage_id: int = 0, format_code: int = 0) -> int:
        """InitiateOpenCapture. Returns the transaction ID — needed to
        stop the recording with stop_recording().

        WARNING: as of writing, the param shape that stop_recording wants
        isn't fully figured out. See docs/findings.md."""
        # Record the txid manually since we need to return it
        before_txid = self._txid
        self.op(t.OP_INITIATE_OPEN_CAPTURE, [storage_id, format_code],
                context="InitiateOpenCapture")
        return self._txid  # the txid of the OpenCapture we just sent

    def stop_recording(self, start_txid: int) -> None:
        """TerminateOpenCapture. `start_txid` is the value returned by
        start_recording()."""
        self.op(t.OP_TERMINATE_OPEN_CAPTURE, [start_txid],
                context="TerminateOpenCapture")

    # ---------- iCatch vendor ops --------------------------------------
    def icatch_poll(self) -> tuple[int, list[int]]:
        """The 0x9601 polling op iSmart DV2 calls ~once per second with
        params (0xD001, 0xFFFFFFFF, 0). Returns (rc, resp_params).
        Doesn't raise on non-OK — this is for keepalive."""
        rc, rp, _ = self._raw_op(t.OP_ICATCH_POLL,
                                  [0xD001, 0xFFFFFFFF, 0x00000000])
        return rc, rp

    # ---------- event channel -----------------------------------------
    def poll_event(self, timeout: Optional[float] = None) -> Optional[dict]:
        """Read one event from the event channel, or None if timeout.

        Sets the event socket's timeout and restores it after."""
        if self._evt_sock is None:
            return None
        old = self._evt_sock.gettimeout()
        try:
            self._evt_sock.settimeout(timeout if timeout is not None else 0.1)
            ptype, body = p.recv_container(self._evt_sock)
            if ptype == t.PT_EVENT:
                return p.parse_event(body)
            return {'type': t.PT_NAMES.get(ptype, ptype), 'raw': body.hex()}
        except (socket.timeout, TransportError):
            return None
        finally:
            try:
                self._evt_sock.settimeout(old)
            except Exception:
                pass

    def wait_for_event(self, event_code: int,
                       timeout: float = 5.0) -> Optional[dict]:
        """Block until an event with the given code arrives or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ev = self.poll_event(timeout=max(0.1, deadline - time.monotonic()))
            if ev is None: continue
            if ev.get('event_code') == event_code:
                return ev
        return None
