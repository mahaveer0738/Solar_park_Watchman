"""
Milestone 2 Verification Tests: Protocol Parsers and Event Normaliser.
"""
import struct
import pytest
from scapy.all import IP, TCP, Ether
from sensor.parsers.modbus_parser import parse_modbus_tcp
from sensor.parsers.iec104_parser import parse_iec104_apdu
from sensor.normaliser import EventNormaliser
from sensor.capture import PassiveSensorCapture
from sim.iec104 import build_asdu_type45, build_apdu_i, build_apdu_u

def test_modbus_parser_fc03_read():
    # MBAP: TransID=1, ProtoID=0, Len=6, UnitID=1
    # PDU: FC=3, StartAddr=101, Count=5
    mbap = struct.pack(">HHHB", 1, 0, 6, 1)
    pdu = struct.pack(">BHH", 3, 101, 5)
    payload = mbap + pdu

    parsed = parse_modbus_tcp(payload)
    assert parsed is not None
    assert parsed["function_code"] == 3
    assert parsed["function_name"] == "READ_HOLDING_REGISTERS"
    assert parsed["address"] == 101
    assert parsed["count"] == 5
    assert parsed["unit_id"] == 1

def test_modbus_parser_fc06_write():
    # MBAP: TransID=2, ProtoID=0, Len=6, UnitID=1
    # PDU: FC=6, RegAddr=101, RegVal=1000
    mbap = struct.pack(">HHHB", 2, 0, 6, 1)
    pdu = struct.pack(">BHH", 6, 101, 1000)
    payload = mbap + pdu

    parsed = parse_modbus_tcp(payload)
    assert parsed is not None
    assert parsed["function_code"] == 6
    assert parsed["function_name"] == "WRITE_SINGLE_REGISTER"
    assert parsed["address"] == 101
    assert parsed["values"] == [1000]

def test_iec104_parser_u_and_i_frames():
    # Test U-format STARTDT_ACT
    u_apdu = build_apdu_u("STARTDT_ACT")
    u_parsed = parse_iec104_apdu(u_apdu)
    assert u_parsed is not None
    assert u_parsed["format"] == "U"
    assert u_parsed["u_type"] == "STARTDT_ACT"

    # Test I-format Type 45 Single Command to IOA 1000
    asdu = build_asdu_type45(ioa=1000, command_state=1)
    i_apdu = build_apdu_i(tx_seq=1, rx_seq=0, asdu_payload=asdu)
    i_parsed = parse_iec104_apdu(i_apdu)
    assert i_parsed is not None
    assert i_parsed["format"] == "I"
    assert i_parsed["asdu"]["type_id"] == 45
    assert i_parsed["asdu"]["ioa"] == 1000
    assert i_parsed["asdu"]["value"] == 1

def test_event_normaliser():
    # Test Modbus normalisation
    mbap = struct.pack(">HHHB", 5, 0, 6, 1)
    pdu = struct.pack(">BHH", 6, 101, 0)  # S2 write 0 to reg 101
    payload = mbap + pdu

    event = EventNormaliser.normalise(
        src_ip="10.10.1.99",
        dst_ip="10.10.1.12",
        protocol="MODBUS_TCP",
        payload=payload,
        src_mac="02:42:0a:0a:01:99"
    )
    assert event is not None
    assert event["src_ip"] == "10.10.1.99"
    assert event["dst_ip"] == "10.10.1.12"
    assert event["protocol"] == "MODBUS_TCP"
    assert event["function"] == "WRITE_SINGLE_REGISTER"
    assert event["address"] == 101
    assert event["value"] == 0

def test_passive_capture_scapy_packet():
    events_captured = []
    capture = PassiveSensorCapture(on_event_callback=lambda e: events_captured.append(e))

    # Synthetic Scapy packet
    mbap_pdu = struct.pack(">HHHBBHH", 10, 0, 6, 1, 3, 101, 5)
    pkt = Ether(src="02:42:0a:0a:01:0a", dst="02:42:0a:0a:01:0b") / \
          IP(src="10.10.1.10", dst="10.10.1.11") / \
          TCP(sport=45678, dport=502) / \
          mbap_pdu

    res = capture.process_packet(pkt)
    assert res is not None
    assert len(events_captured) == 1
    assert events_captured[0]["src_ip"] == "10.10.1.10"
    assert events_captured[0]["dst_ip"] == "10.10.1.11"
    assert events_captured[0]["function"] == "READ_HOLDING_REGISTERS"
