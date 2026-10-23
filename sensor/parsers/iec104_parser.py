"""
IEC 60870-5-104 Parser for Solar Park Watchman Sensor.
Dissects APDUs (I, S, U formats) and extracts ASDU fields (Types, Causes, IOAs, Commands).
"""
import struct
from typing import Optional, Any

ASDU_TYPE_NAMES = {
    1: "M_SP_NA_1_SINGLE_POINT",
    3: "M_DP_NA_1_DOUBLE_POINT",
    9: "M_ME_NA_1_MEASURED_NORMALIZED",
    13: "M_ME_NC_1_MEASURED_SHORT_FLOAT",
    30: "M_SP_TB_1_SINGLE_POINT_TIME",
    36: "M_ME_TF_1_MEASURED_SHORT_FLOAT_TIME",
    45: "C_SC_NA_1_SINGLE_COMMAND",
    46: "C_DC_NA_1_DOUBLE_COMMAND",
    50: "C_SE_NC_1_SETPOINT_COMMAND_SHORT_FLOAT",
    100: "C_IC_NA_1_INTERROGATION_COMMAND",
}

def parse_iec104_apdu(payload: bytes) -> Optional[dict[str, Any]]:
    """
    Parse a raw IEC 60870-5-104 APDU.
    Returns structured dictionary or None if payload is not valid IEC-104.
    """
    if len(payload) < 6 or payload[0] != 0x68:
        return None

    length = payload[1]
    if len(payload) < 2 + length:
        return None

    ctrl = payload[2:6]
    ctrl0 = ctrl[0]

    result: dict[str, Any] = {
        "start_byte": 0x68,
        "length": length,
        "format": None,
        "u_type": None,
        "tx_seq": None,
        "rx_seq": None,
        "asdu": None
    }

    # U-Format (Bits 0-1 of ctrl0 are 11)
    if (ctrl0 & 0x03) == 0x03:
        result["format"] = "U"
        u_map = {
            0x07: "STARTDT_ACT",
            0x0B: "STARTDT_CON",
            0x13: "STOPDT_ACT",
            0x23: "STOPDT_CON",
            0x43: "TESTFR_ACT",
            0x83: "TESTFR_CON",
        }
        result["u_type"] = u_map.get(ctrl0, f"U_UNKNOWN_0x{ctrl0:02X}")
        return result

    # S-Format (Bits 0-1 of ctrl0 are 01)
    elif (ctrl0 & 0x03) == 0x01:
        result["format"] = "S"
        rx_seq = struct.unpack("<H", ctrl[2:4])[0] >> 1
        result["rx_seq"] = rx_seq
        return result

    # I-Format (Bit 0 of ctrl0 is 0)
    elif (ctrl0 & 0x01) == 0x00:
        result["format"] = "I"
        tx_seq = struct.unpack("<H", ctrl[0:2])[0] >> 1
        rx_seq = struct.unpack("<H", ctrl[2:4])[0] >> 1
        result["tx_seq"] = tx_seq
        result["rx_seq"] = rx_seq

        # Parse ASDU if present
        asdu_bytes = payload[6:2 + length]
        if len(asdu_bytes) >= 6:
            type_id = asdu_bytes[0]
            vsq = asdu_bytes[1]
            cot = struct.unpack("<H", asdu_bytes[2:4])[0]
            ca = struct.unpack("<H", asdu_bytes[4:6])[0]

            asdu_info: dict[str, Any] = {
                "type_id": type_id,
                "type_name": ASDU_TYPE_NAMES.get(type_id, f"TYPE_{type_id}"),
                "vsq": vsq,
                "cot": cot,
                "common_address": ca,
                "ioa": None,
                "value": None
            }

            if len(asdu_bytes) >= 9:
                ioa = struct.unpack("<I", asdu_bytes[6:9] + b"\x00")[0]
                asdu_info["ioa"] = ioa
                body = asdu_bytes[9:]

                if type_id == 1 and len(body) >= 1:  # Single Point
                    asdu_info["value"] = body[0] & 0x01
                elif type_id == 13 and len(body) >= 4:  # Short Float
                    asdu_info["value"] = round(struct.unpack("<f", body[:4])[0], 3)
                elif type_id in (45, 46) and len(body) >= 1:  # Single / Double Command
                    asdu_info["value"] = body[0]
                elif type_id == 50 and len(body) >= 4:  # Setpoint Float
                    asdu_info["value"] = round(struct.unpack("<f", body[:4])[0], 3)

            result["asdu"] = asdu_info

        return result

    return None
