"""Unit tests for larkfly.protocol — pure codec/framing logic, no hardware
required.

Run with:
    python3 -m unittest tests/test_protocol.py
"""
import struct
import sys
import os
import unittest

# Make the repo importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from larkfly import protocol as p
from larkfly import types as t


class TestContainerFraming(unittest.TestCase):
    def test_encode_container(self):
        out = p.encode_container(6, b'hello')
        # length=13 (5 body + 8 header), type=6
        self.assertEqual(out, struct.pack('<II', 13, 6) + b'hello')

    def test_encode_empty(self):
        out = p.encode_container(4, b'')
        self.assertEqual(out, struct.pack('<II', 8, 4))


class TestIcatchNameCodec(unittest.TestCase):
    """iCatch's no-length-prefix UTF-16LE null-terminated name encoding —
    the wire-format quirk identified by comparing our probe to iSmart DV2."""
    def test_encode_localhost(self):
        out = p.encode_icatch_name('localhost')
        # "localhost\0" in UTF-16LE, no length byte
        expected = 'localhost'.encode('utf-16-le') + b'\x00\x00'
        self.assertEqual(out, expected)
        self.assertEqual(len(out), 20)

    def test_encode_empty(self):
        out = p.encode_icatch_name('')
        self.assertEqual(out, b'\x00\x00')

    def test_decode_localhost(self):
        buf = 'localhost'.encode('utf-16-le') + b'\x00\x00'
        name, off = p.decode_icatch_name(buf, 0)
        self.assertEqual(name, 'localhost')
        self.assertEqual(off, 20)

    def test_roundtrip(self):
        for s in ('', 'localhost', 'A', 'long name 中文'):
            encoded = p.encode_icatch_name(s)
            decoded, _ = p.decode_icatch_name(encoded, 0)
            self.assertEqual(decoded, s, f"roundtrip failed for {s!r}")


class TestPtpString(unittest.TestCase):
    """Standard PTP-string (length-prefixed) used INSIDE operation data."""
    def test_encode_empty(self):
        self.assertEqual(p.encode_ptp_string(''), b'\x00')

    def test_encode_hello(self):
        out = p.encode_ptp_string('hello')
        # 6 chars including null, UTF-16LE + null terminator
        self.assertEqual(out[0], 6)
        chars = 'hello'.encode('utf-16-le') + b'\x00\x00'
        self.assertEqual(out[1:], chars)

    def test_decode(self):
        buf = bytes([6]) + 'hello'.encode('utf-16-le') + b'\x00\x00'
        s, off = p.decode_ptp_string(buf, 0)
        self.assertEqual(s, 'hello')
        self.assertEqual(off, len(buf))

    def test_decode_empty(self):
        s, off = p.decode_ptp_string(b'\x00', 0)
        self.assertEqual(s, '')
        self.assertEqual(off, 1)


class TestValueCodec(unittest.TestCase):
    def test_uint8(self):
        self.assertEqual(p.encode_value(42, t.DT_UINT8), b'\x2a')
        v, off = p.decode_value(b'\xff', 0, t.DT_UINT8)
        self.assertEqual(v, 255)
        self.assertEqual(off, 1)

    def test_int8(self):
        self.assertEqual(p.encode_value(-1, t.DT_INT8), b'\xff')
        v, _ = p.decode_value(b'\xff', 0, t.DT_INT8)
        self.assertEqual(v, -1)

    def test_uint16(self):
        out = p.encode_value(0x1234, t.DT_UINT16)
        self.assertEqual(out, b'\x34\x12')
        v, _ = p.decode_value(out, 0, t.DT_UINT16)
        self.assertEqual(v, 0x1234)

    def test_uint32(self):
        out = p.encode_value(0xDEADBEEF, t.DT_UINT32)
        self.assertEqual(out, b'\xef\xbe\xad\xde')
        v, _ = p.decode_value(out, 0, t.DT_UINT32)
        self.assertEqual(v, 0xDEADBEEF)

    def test_string(self):
        out = p.encode_value('test', t.DT_STRING)
        self.assertEqual(out[0], 5)  # 4 chars + null
        v, _ = p.decode_value(out, 0, t.DT_STRING)
        self.assertEqual(v, 'test')

    def test_array(self):
        out = p.encode_value([1, 2, 3], t.DT_AUINT16)
        # 4-byte count + 3×2-byte values
        self.assertEqual(out, struct.pack('<I', 3) + b'\x01\x00\x02\x00\x03\x00')
        v, _ = p.decode_value(out, 0, t.DT_AUINT16)
        self.assertEqual(v, [1, 2, 3])


class TestOpReqEncoding(unittest.TestCase):
    def test_open_session(self):
        # OpenSession opcode 0x1002, txid=0, param[0]=1 (session id)
        out = p.encode_op_req(0x1002, 0, [1])
        # dphase(4) + opcode(2) + txid(4) + 1×u32 param = 14 bytes
        self.assertEqual(len(out), 14)
        # Compare against the bytes the probe sends + matches iSmart DV2
        expected = (struct.pack('<I', 1)         # dphase=1 (no data)
                    + struct.pack('<H', 0x1002)
                    + struct.pack('<I', 0)
                    + struct.pack('<I', 1))
        self.assertEqual(out, expected)

    def test_get_device_info(self):
        out = p.encode_op_req(0x1001, 1, [])
        expected = (struct.pack('<I', 1)
                    + struct.pack('<H', 0x1001)
                    + struct.pack('<I', 1))
        self.assertEqual(out, expected)


class TestInitCmdReqEncoding(unittest.TestCase):
    """Critical: the wire format that this firmware will accept."""
    def test_full_packet_matches_ismartdv2(self):
        # Reproduce the exact bytes iSmart DV2 sent (frame 455 of the
        # decrypted capture), then verify our encoder produces the same shape.
        guid = bytes.fromhex('da8e0a4347f7ade14489899e75df421f')
        payload = p.encode_init_cmd_req(guid, 'localhost')
        # Wrap in container
        full = p.encode_container(t.PT_INIT_CMD_REQ, payload)
        expected = bytes.fromhex(
            '30000000'                                      # length 48
            '01000000'                                      # type 1
            'da8e0a4347f7ade14489899e75df421f'              # GUID (the one
                                                            # captured)
            '6c006f00630061006c0068006f00730074000000'      # "localhost\0"
            '00000100'                                      # version 0x10000
        )
        self.assertEqual(full, expected)


class TestOpRespParsing(unittest.TestCase):
    def test_basic(self):
        # rc=0x2001 (OK), txid=5, no params
        body = struct.pack('<H', 0x2001) + struct.pack('<I', 5)
        out = p.parse_op_resp(body)
        self.assertEqual(out['response_code'], 0x2001)
        self.assertEqual(out['transaction_id'], 5)
        self.assertEqual(out['params'], [])

    def test_with_padding(self):
        # iCatch pads bodies with trailing zeros up to ~26 bytes.
        body = (struct.pack('<H', 0x2001) + struct.pack('<I', 5)
                + struct.pack('<I', 42)  # one real param
                + b'\x00' * 16)          # padding
        out = p.parse_op_resp(body)
        self.assertEqual(out['response_code'], 0x2001)
        self.assertEqual(out['transaction_id'], 5)
        self.assertIn(42, out['params'])


class TestObjectInfoParsing(unittest.TestCase):
    def test_directory_entry(self):
        # Construct a minimal ObjectInfo for a directory named "JPG".
        data = (
            struct.pack('<I', 0x00050001)  # storage_id
            + struct.pack('<H', 0x3001)    # association format
            + struct.pack('<H', 0)         # protection
            + struct.pack('<I', 0)         # compressed size
            + struct.pack('<H', 0)         # thumb format
            + struct.pack('<I', 0)         # thumb compressed size
            + struct.pack('<I', 0)         # thumb pix width
            + struct.pack('<I', 0)         # thumb pix height
            + struct.pack('<I', 0)         # image pix width
            + struct.pack('<I', 0)         # image pix height
            + struct.pack('<I', 0)         # image bit depth
            + struct.pack('<I', 0)         # parent
            + struct.pack('<H', 0)         # association type
            + struct.pack('<I', 0)         # association desc
            + struct.pack('<I', 0)         # seq num
            + p.encode_ptp_string('JPG')
            + p.encode_ptp_string('')
            + p.encode_ptp_string('')
            + p.encode_ptp_string('')
        )
        info = p.parse_object_info(data)
        self.assertEqual(info['storage_id'], 0x00050001)
        self.assertEqual(info['object_format'], 0x3001)
        self.assertEqual(info['filename'], 'JPG')


class TestDeviceInfoParsing(unittest.TestCase):
    def test_real_v11_capture(self):
        """Parse the real DeviceInfo bytes captured from the camera."""
        # Hex from the actual GetDeviceInfo response data
        data = bytes.fromhex(
            '6400'                          # standard_version = 0x0064
            '00000000'                      # vendor extension id
            '0000'                          # vendor extension version
            '00'                            # vendor extension desc (empty)
            '0000'                          # functional mode
            # operations_supported: 28 entries
            '1c000000'
            '0110' '0210' '0310' '0410' '0510' '0610' '0710' '0810'
            '0910' '0a10' '0b10' '0c10' '0d10' '0e10' '0f10' '1210'
            '1410' '1510' '1610' '1b10'
            '0196' '0296' '1298' '1496' '0198' '0298' '0398' '0598'
            # events_supported: 9 entries
            '09000000'
            '0240' '0340' '0440' '0540' '0640' '0840' '0940' '0d40'
            '01c6'
            # device_properties_supported: 0 (truncate for test)
            '00000000'
            # capture_formats: 0
            '00000000'
            # image_formats: 0
            '00000000'
            # Manufacturer/Model/DeviceVersion/SerialNumber: empty
            '00' '00' '00' '00'
        )
        info = p.parse_device_info(data)
        self.assertEqual(info['standard_version'], 0x0064)  # 1.00
        self.assertEqual(info['vendor_extension_id'], 0)
        self.assertEqual(len(info['operations_supported']), 28)
        self.assertIn(0x1001, info['operations_supported'])
        self.assertIn(0x9601, info['operations_supported'])
        self.assertEqual(len(info['events_supported']), 9)
        self.assertIn(0xC601, info['events_supported'])


class TestOpcodeConstants(unittest.TestCase):
    """Guard the standard PTP operation-code constants against their
    PIMA 15740-2000 §10 (Operations) spec values.

    Regression cover for the bug RETROSPECTIVE.md documents: three
    constants in larkfly/types.py held the wrong opcode —
    OP_INITIATE_CAPTURE was 0x100C (SendObjectInfo), OP_INITIATE_OPEN_CAPTURE
    was 0x100D (SendObject), OP_TERMINATE_OPEN_CAPTURE was 0x101B
    (GetPartialObject). The library decoded the camera's DeviceInfo
    correctly but filled its own constants in wrong, so take_photo()
    silently created empty object stubs. Asserting every constant against
    the spec catches that whole class of mistake on the next edit."""

    # opcode constant name -> (expected value, PIMA 15740 operation name)
    SPEC = {
        'OP_GET_DEVICE_INFO':       (0x1001, 'GetDeviceInfo'),
        'OP_OPEN_SESSION':          (0x1002, 'OpenSession'),
        'OP_CLOSE_SESSION':         (0x1003, 'CloseSession'),
        'OP_GET_STORAGE_IDS':       (0x1004, 'GetStorageIDs'),
        'OP_GET_STORAGE_INFO':      (0x1005, 'GetStorageInfo'),
        'OP_GET_NUM_OBJECTS':       (0x1006, 'GetNumObjects'),
        'OP_GET_OBJECT_HANDLES':    (0x1007, 'GetObjectHandles'),
        'OP_GET_OBJECT_INFO':       (0x1008, 'GetObjectInfo'),
        'OP_GET_OBJECT':            (0x1009, 'GetObject'),
        'OP_GET_THUMB':             (0x100A, 'GetThumb'),
        'OP_DELETE_OBJECT':         (0x100B, 'DeleteObject'),
        'OP_INITIATE_CAPTURE':      (0x100E, 'InitiateCapture'),
        'OP_FORMAT_STORE':          (0x100F, 'FormatStore'),
        'OP_GET_DEVICE_PROP_DESC':  (0x1014, 'GetDevicePropDesc'),
        'OP_GET_DEVICE_PROP_VALUE': (0x1015, 'GetDevicePropValue'),
        'OP_SET_DEVICE_PROP_VALUE': (0x1016, 'SetDevicePropValue'),
        'OP_TERMINATE_OPEN_CAPTURE': (0x1018, 'TerminateOpenCapture'),
        'OP_GET_PARTIAL_OBJECT':    (0x101B, 'GetPartialObject'),
        'OP_INITIATE_OPEN_CAPTURE': (0x101C, 'InitiateOpenCapture'),
    }

    def test_opcode_constants_match_spec(self):
        for name, (value, op_name) in self.SPEC.items():
            self.assertEqual(
                getattr(t, name), value,
                f"{name} should be 0x{value:04X} ({op_name} per PIMA 15740)")

    def test_no_opcode_collisions(self):
        """No two operation-code constants may share a value — the
        original bug aliased InitiateCapture onto SendObjectInfo's code."""
        values = [getattr(t, name) for name in self.SPEC]
        self.assertEqual(len(values), len(set(values)),
                         "duplicate opcode value among OP_* constants")

    def test_initiate_capture_is_not_sendobjectinfo(self):
        """Explicit regression pin: 0x100C is SendObjectInfo, not capture."""
        self.assertNotEqual(t.OP_INITIATE_CAPTURE, 0x100C)


if __name__ == '__main__':
    unittest.main()
