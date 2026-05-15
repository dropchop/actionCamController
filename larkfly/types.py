"""Constants for the iCatch / Larkfly PTP-IP protocol.

Values come from PIMA 15740-2000 (PTP), its PTP-IP supplement, and
empirical investigation of the Larkfly A6+ (camera model 'V11', firmware
20251206). See docs/findings.md for the trail.
"""

# ---- PTP-IP container packet types ------------------------------------
# Reference: PIMA 15740-2 (PTP-IP supplement). iCatch + libgphoto2 follow
# the convention where 11=Cancel, 12=EndData (NOT the reverse — many
# Wikipedia-style summaries have these swapped).
PT_INIT_CMD_REQ  = 1
PT_INIT_CMD_ACK  = 2
PT_INIT_EVT_REQ  = 3
PT_INIT_EVT_ACK  = 4
PT_INIT_FAIL     = 5
PT_OP_REQ        = 6
PT_OP_RESP       = 7
PT_EVENT         = 8
PT_START_DATA    = 9
PT_DATA          = 10
PT_CANCEL        = 11
PT_END_DATA      = 12
PT_PROBE_REQ     = 13
PT_PROBE_RESP    = 14

PT_NAMES = {
    1: "InitCmdReq", 2: "InitCmdAck", 3: "InitEvtReq", 4: "InitEvtAck",
    5: "InitFail",   6: "OpReq",      7: "OpResp",     8: "Event",
    9: "StartData", 10: "Data",      11: "Cancel",    12: "EndData",
    13: "ProbeReq", 14: "ProbeResp",
}

PTPIP_PORT = 15740
PROTOCOL_VERSION = 0x00010000  # PTP-IP v1.0

# ---- PTP standard operation codes (§5.5.3) ----------------------------
OP_GET_DEVICE_INFO          = 0x1001
OP_OPEN_SESSION             = 0x1002
OP_CLOSE_SESSION            = 0x1003
OP_GET_STORAGE_IDS          = 0x1004
OP_GET_STORAGE_INFO         = 0x1005
OP_GET_NUM_OBJECTS          = 0x1006
OP_GET_OBJECT_HANDLES       = 0x1007
OP_GET_OBJECT_INFO          = 0x1008
OP_GET_OBJECT               = 0x1009
OP_GET_THUMB                = 0x100A
OP_DELETE_OBJECT            = 0x100B
OP_INITIATE_CAPTURE         = 0x100C  # take a photo
OP_FORMAT_STORE             = 0x100F  # DANGEROUS — wipes SD card
OP_GET_DEVICE_PROP_DESC     = 0x1014
OP_GET_DEVICE_PROP_VALUE    = 0x1015
OP_SET_DEVICE_PROP_VALUE    = 0x1016
OP_INITIATE_OPEN_CAPTURE    = 0x100D  # start video recording
OP_TERMINATE_OPEN_CAPTURE   = 0x101B  # stop video recording
OP_GET_PARTIAL_OBJECT       = 0x101B  # ALSO 0x101B in PTP; same opcode reused.
                                       # In PTP-IP context, 0x101B is
                                       # GetPartialObject; in iCatch context
                                       # the camera advertises it as
                                       # supported and uses it for both.
OP_GET_PARTIAL_OBJECT_64    = 0x101B  # (alias)

# Vendor opcodes the Larkfly A6+ advertises (0x9000-0x97FF range)
OP_ICATCH_POLL              = 0x9601  # heartbeat / event-poll (iSmart DV2
                                       # calls this once/sec)
OP_ICATCH_VENDOR_9602       = 0x9602  # purpose unknown — not used by iSmart
OP_ICATCH_VENDOR_9614       = 0x9614  # purpose unknown
OP_ICATCH_VENDOR_9801       = 0x9801  # purpose unknown
OP_ICATCH_VENDOR_9802       = 0x9802  # purpose unknown
OP_ICATCH_VENDOR_9803       = 0x9803  # purpose unknown
OP_ICATCH_VENDOR_9805       = 0x9805  # "global query" — iSmart DV2 calls once
OP_ICATCH_VENDOR_9812       = 0x9812  # purpose unknown

# ---- PTP response codes (§5.5.7) --------------------------------------
RC_OK                       = 0x2001
RC_GENERAL_ERROR            = 0x2002
RC_SESSION_NOT_OPEN         = 0x2003
RC_INVALID_TRANSACTION_ID   = 0x2004
RC_OPERATION_NOT_SUPPORTED  = 0x2005
RC_PARAMETER_NOT_SUPPORTED  = 0x2006
RC_INCOMPLETE_TRANSFER      = 0x2007
RC_INVALID_STORAGE_ID       = 0x2008
RC_INVALID_OBJECT_HANDLE    = 0x2009
RC_DEVICE_PROP_NOT_SUPPORTED = 0x200A
RC_INVALID_OBJECT_FORMAT_CODE = 0x200B
RC_STORE_FULL               = 0x200C
RC_OBJECT_WRITE_PROTECTED   = 0x200D
RC_STORE_READ_ONLY          = 0x200E
RC_ACCESS_DENIED            = 0x200F
RC_NO_THUMBNAIL_PRESENT     = 0x2010
RC_SELF_TEST_FAILED         = 0x2011
RC_PARTIAL_DELETION         = 0x2012
RC_STORE_NOT_AVAILABLE      = 0x2013
RC_SPECIFICATION_BY_FORMAT_UNSUPPORTED = 0x2014
RC_NO_VALID_OBJECT_INFO     = 0x2015
RC_INVALID_CODE_FORMAT      = 0x2016
RC_UNKNOWN_VENDOR_CODE      = 0x2017
RC_CAPTURE_ALREADY_TERMINATED = 0x2018
RC_DEVICE_BUSY              = 0x201E
RC_INVALID_PARENT_OBJECT    = 0x201F
RC_INVALID_DEVICE_PROP_FORMAT = 0x2020
RC_INVALID_DEVICE_PROP_VALUE = 0x2021
RC_INVALID_PARAMETER        = 0x2022
RC_SESSION_ALREADY_OPEN     = 0x2023

RC_NAMES = {
    0x2001: "OK", 0x2002: "GeneralError", 0x2003: "SessionNotOpen",
    0x2004: "InvalidTransactionID", 0x2005: "OperationNotSupported",
    0x2006: "ParameterNotSupported", 0x2007: "IncompleteTransfer",
    0x2008: "InvalidStorageID", 0x2009: "InvalidObjectHandle",
    0x200A: "DevicePropNotSupported", 0x200B: "InvalidObjectFormatCode",
    0x200C: "StoreFull", 0x200D: "ObjectWriteProtected",
    0x200E: "StoreReadOnly", 0x200F: "AccessDenied",
    0x2010: "NoThumbnailPresent", 0x2011: "SelfTestFailed",
    0x2012: "PartialDeletion", 0x2013: "StoreNotAvailable",
    0x2014: "SpecificationByFormatUnsupported", 0x2015: "NoValidObjectInfo",
    0x2016: "InvalidCodeFormat", 0x2017: "UnknownVendorCode",
    0x2018: "CaptureAlreadyTerminated", 0x201E: "DeviceBusy",
    0x201F: "InvalidParentObject", 0x2020: "InvalidDevicePropFormat",
    0x2021: "InvalidDevicePropValue", 0x2022: "InvalidParameter",
    0x2023: "SessionAlreadyOpen",
}

# ---- PTP data types (§5.2.2) ------------------------------------------
DT_INT8   = 0x0001;  DT_UINT8   = 0x0002
DT_INT16  = 0x0003;  DT_UINT16  = 0x0004
DT_INT32  = 0x0005;  DT_UINT32  = 0x0006
DT_INT64  = 0x0007;  DT_UINT64  = 0x0008
DT_INT128 = 0x0009;  DT_UINT128 = 0x000A
DT_AINT8  = 0x4001;  DT_AUINT8  = 0x4002
DT_AINT16 = 0x4003;  DT_AUINT16 = 0x4004
DT_AINT32 = 0x4005;  DT_AUINT32 = 0x4006
DT_AINT64 = 0x4007;  DT_AUINT64 = 0x4008
DT_STRING = 0xFFFF

DT_NAMES = {
    0x0001: 'INT8',    0x0002: 'UINT8',
    0x0003: 'INT16',   0x0004: 'UINT16',
    0x0005: 'INT32',   0x0006: 'UINT32',
    0x0007: 'INT64',   0x0008: 'UINT64',
    0x0009: 'INT128',  0x000A: 'UINT128',
    0x4001: 'AINT8',   0x4002: 'AUINT8',
    0x4003: 'AINT16',  0x4004: 'AUINT16',
    0x4005: 'AINT32',  0x4006: 'AUINT32',
    0x4007: 'AINT64',  0x4008: 'AUINT64',
    0xFFFF: 'STRING',
}

# Bytes per element; -1 for variable-length (strings, arrays)
DT_SIZE = {
    0x0001: 1, 0x0002: 1,
    0x0003: 2, 0x0004: 2,
    0x0005: 4, 0x0006: 4,
    0x0007: 8, 0x0008: 8,
    0x0009: 16, 0x000A: 16,
}

# ---- PTP standard event codes -----------------------------------------
EV_CANCEL_TRANSACTION    = 0x4001
EV_OBJECT_ADDED          = 0x4002
EV_OBJECT_REMOVED        = 0x4003
EV_STORE_ADDED           = 0x4004
EV_STORE_REMOVED         = 0x4005
EV_DEVICE_PROP_CHANGED   = 0x4006
EV_OBJECT_INFO_CHANGED   = 0x4007
EV_DEVICE_INFO_CHANGED   = 0x4008
EV_REQUEST_OBJECT_TRANSFER = 0x4009
EV_STORE_FULL            = 0x400A
EV_DEVICE_RESET          = 0x400B
EV_STORAGE_INFO_CHANGED  = 0x400C
EV_CAPTURE_COMPLETE      = 0x400D
EV_UNREPORTED_STATUS     = 0x400E

# ---- Object format codes (§5.5.5.2) -----------------------------------
OF_UNDEFINED   = 0x3000
OF_ASSOCIATION = 0x3001  # PTP directory
OF_EXIF_JPEG   = 0x3801
OF_DEFINED     = 0x3800
OF_MP4         = 0xB982  # vendor / extension (advertised by Larkfly)

# ---- Property codes — named ones from iCatch SDK + standard PTP -------
# ---- iCatch camera operating modes (property 0xD604 values) ------------
# Empirically confirmed: setting D604=17 starts video recording, D604=1
# stops it. Other modes are listed in the Java SDK enum; meanings of
# 5/6/9/10 aren't fully documented.
MODE_VIDEO_OFF        = 1      # idle (camera ready, not recording)
MODE_SHARED           = 2
MODE_CAMERA           = 3      # photo / still capture mode
MODE_IDLE             = 4
MODE_VIDEO_ON         = 17     # ACTIVELY RECORDING video
MODE_VIDEO            = 42     # (not in Larkfly A6+'s allowed values)
MODE_TIMELAPSE        = 43     # (likewise)

MODE_NAMES = {
    1: 'VIDEO_OFF', 2: 'SHARED', 3: 'CAMERA', 4: 'IDLE',
    5: '?5', 6: '?6', 7: 'TIMELAPSE_STILL', 8: 'TIMELAPSE_VIDEO',
    9: '?9', 10: '?10', 17: 'VIDEO_ON', 42: 'VIDEO', 43: 'TIMELAPSE',
}

PROP_MODE = 0xD604   # The camera-mode property

# Names that this firmware actually advertises.
PROP_NAMES = {
    # Standard PTP capture-control properties
    0x5001: 'BatteryLevel',
    0x5003: 'ImageSize',
    0x5004: 'CompressionSetting',
    0x5005: 'WhiteBalance',
    0x5007: 'FNumber',
    0x500A: 'FocusMode',
    0x500B: 'ExposureMeteringMode',
    0x500C: 'FlashMode',
    0x500D: 'ExposureTime',
    0x500E: 'ExposureProgramMode',
    0x500F: 'ExposureIndex',
    0x5010: 'ExposureBiasCompensation',
    0x5011: 'DateTime',
    0x5012: 'CaptureDelay',
    0x5013: 'StillCaptureMode',
    0x5015: 'Contrast',
    0x5018: 'BurstNumber',
    0x501A: 'TimelapseNumber',
    0x501B: 'TimelapseInterval',
    0x501E: 'ProductName',
    0x501F: 'FwVersion',
    # iCatch vendor (from ICatchCamProperty.java + empirical)
    0xD605: 'VideoSize',
    0xD606: 'LightFrequency',
    0xD607: 'DateStamp',
    0xD615: 'SlowMotion',
    0xD801: 'HostScriptPath',
    0xD83E: 'HostScriptPath2',
}
