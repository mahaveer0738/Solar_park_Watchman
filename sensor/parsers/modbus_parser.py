"""
Modbus TCP Parser for Solar Park Watchman Sensor.
Extracts MBAP Header and PDU semantics (FC, Unit ID, Addresses, Values).
"""
import struct
from typing import Optional, Any

FC_NAMES = {
    1: "READ_COILS",
    2: "READ_DISCRETE_INPUTS",
    3: "READ_HOLDING_REGISTERS",
    4: "READ_INPUT_REGISTERS",
    5: "WRITE_SINGLE_COIL",
    6: "WRITE_SINGLE_REGISTER",
    15: "WRITE_MULTIPLE_COILS",
    16: "WRITE_MULTIPLE_REGISTERS",
    43: "ENCAPSULATED_INTERFACE_TRANSPORT"
}

def parse_modbus_tcp(payload: bytes) -> Optional[dict[str, Any]]:
    """
    Parse a raw Modbus TCP APDU.
    Returns structured dictionary or None if payload is not valid Modbus TCP.
    """
    if len(payload) < 8:
        return None

    # MBAP Header:
    # Transaction ID (2 bytes), Protocol ID (2 bytes, 0 for Modbus),
    # Length (2 bytes), Unit ID (1 byte)
    trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
    if proto_id != 0:
        return None  # Not standard Modbus TCP

    pdu = payload[7:7 + length - 1]
    if not pdu:
        return None

    fc_byte = pdu[0]
    is_exception = bool(fc_byte & 0x80)
    fc = fc_byte & 0x7F
    fc_name = FC_NAMES.get(fc, f"FC_{fc}")

    result = {
        "transaction_id": trans_id,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": fc_name,
        "is_exception": is_exception,
        "address": None,
        "count": None,
        "values": None,
    }

    if is_exception:
        result["exception_code"] = pdu[1] if len(pdu) > 1 else None
        return result

    pdu_body = pdu[1:]
    # Parse requests based on Function Code
    if fc in (1, 2, 3, 4):  # Read requests
        if len(pdu_body) >= 4:
            addr, count = struct.unpack(">HH", pdu_body[:4])
            result["address"] = addr
            result["count"] = count
        elif len(pdu_body) >= 1:
            # Response: byte count + data
            byte_count = pdu_body[0]
            data_bytes = pdu_body[1:1 + byte_count]
            if fc in (3, 4) and len(data_bytes) >= 2:
                # Holding/Input registers: list of 16-bit uints
                reg_count = len(data_bytes) // 2
                result["values"] = list(struct.unpack(f">{reg_count}H", data_bytes[:reg_count * 2]))
                result["count"] = reg_count

    elif fc in (5, 6):  # Write Single Coil / Register
        if len(pdu_body) >= 4:
            addr, val = struct.unpack(">HH", pdu_body[:4])
            result["address"] = addr
            result["values"] = [val]
            result["count"] = 1

    elif fc == 16:  # Write Multiple Registers
        if len(pdu_body) >= 5:
            addr, qty, byte_count = struct.unpack(">HHB", pdu_body[:5])
            result["address"] = addr
            result["count"] = qty
            data_bytes = pdu_body[5:5 + byte_count]
            if len(data_bytes) >= qty * 2:
                result["values"] = list(struct.unpack(f">{qty}H", data_bytes[:qty * 2]))

    return result
