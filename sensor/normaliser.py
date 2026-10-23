"""
Event Normaliser for Solar Park Watchman Sensor.
Converts heterogeneous OT network frames (Modbus TCP, IEC-104, ARP, ICMP)
into a unified canonical record:
(time, src, dst, protocol, function, address, value).
"""
import time
from datetime import datetime, timezone
from typing import Optional, Any
from sensor.parsers.modbus_parser import parse_modbus_tcp
from sensor.parsers.iec104_parser import parse_iec104_apdu
from sim.common import iso_utc_now

class EventNormaliser:
    """Normalizes raw packet payloads and network metadata into standard event records."""

    @staticmethod
    def normalise(
        src_ip: str,
        dst_ip: str,
        protocol: str,
        payload: bytes,
        src_mac: str = "00:00:00:00:00:00",
        dst_mac: str = "00:00:00:00:00:00",
        timestamp: Optional[float] = None,
        dst_port: int = 502
    ) -> Optional[dict[str, Any]]:
        epoch = timestamp or time.time()
        time_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

        # Modbus TCP (standard port 502 or 5020-5023)
        if protocol.upper() in ("MODBUS", "MODBUS_TCP") or dst_port in (502, 5020, 5021, 5022, 5023):
            parsed = parse_modbus_tcp(payload)
            if parsed:
                # Value resolution: first value if available
                val = None
                if parsed.get("values"):
                    val = parsed["values"][0] if len(parsed["values"]) == 1 else parsed["values"]

                return {
                    "time": time_iso,
                    "timestamp_epoch": epoch,
                    "src_ip": src_ip,
                    "src_mac": src_mac,
                    "dst_ip": dst_ip,
                    "dst_mac": dst_mac,
                    "protocol": "MODBUS_TCP",
                    "function": parsed["function_name"],
                    "function_code": parsed["function_code"],
                    "address": parsed.get("address"),
                    "count": parsed.get("count", 1),
                    "value": val,
                    "unit_id": parsed.get("unit_id", 1),
                    "is_exception": parsed.get("is_exception", False),
                    "raw_summary": f"Modbus {parsed['function_name']} (FC{parsed['function_code']:02d}) addr={parsed.get('address')} val={val} unit={parsed.get('unit_id')}"
                }

        # IEC 60870-5-104 (standard port 2404)
        elif protocol.upper() in ("IEC104", "IEC_104") or dst_port == 2404:
            parsed = parse_iec104_apdu(payload)
            if parsed:
                fmt = parsed["format"]
                asdu = parsed.get("asdu")
                func_name = f"IEC104_{fmt}"
                addr = None
                val = None

                if fmt == "U":
                    func_name = f"IEC104_U_{parsed.get('u_type')}"
                elif fmt == "S":
                    func_name = f"IEC104_S_RX_{parsed.get('rx_seq')}"
                elif fmt == "I" and asdu:
                    func_name = f"IEC104_{asdu.get('type_name')}"
                    addr = asdu.get("ioa")
                    val = asdu.get("value")

                return {
                    "time": time_iso,
                    "timestamp_epoch": epoch,
                    "src_ip": src_ip,
                    "src_mac": src_mac,
                    "dst_ip": dst_ip,
                    "dst_mac": dst_mac,
                    "protocol": "IEC_104",
                    "function": func_name,
                    "asdu_type": asdu.get("type_id") if asdu else None,
                    "address": addr,
                    "count": 1,
                    "value": val,
                    "cot": asdu.get("cot") if asdu else None,
                    "raw_summary": f"IEC-104 {func_name} ioa={addr} val={val}"
                }

        # Network Discovery (ARP / ICMP Ping)
        elif protocol.upper() in ("ARP", "ICMP"):
            return {
                "time": time_iso,
                "timestamp_epoch": epoch,
                "src_ip": src_ip,
                "src_mac": src_mac,
                "dst_ip": dst_ip,
                "dst_mac": dst_mac,
                "protocol": protocol.upper(),
                "function": f"{protocol.upper()}_SCAN",
                "address": None,
                "count": 1,
                "value": None,
                "raw_summary": f"{protocol.upper()} probe {src_ip} -> {dst_ip}"
            }

        return None
