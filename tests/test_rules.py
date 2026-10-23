"""
Milestone 4 Verification Tests: Deterministic Rule Engine (S2, S3, S5, S6, S8).
"""
import pytest
from datetime import datetime, timezone
from sensor.rule_engine import RuleEngine

@pytest.fixture
def rule_engine():
    return RuleEngine(policy_path="config/policy.yaml")

def test_s2_unauthorized_setpoint_write(rule_engine):
    # 1. Legitimate PPC write to Inverter-2 register 101
    ppc_evt = {
        "time": "2026-10-23T12:00:00Z",
        "src_ip": "10.10.1.30",
        "dst_ip": "10.10.1.12",
        "protocol": "MODBUS_TCP",
        "function": "WRITE_SINGLE_REGISTER",
        "address": 101,
        "value": 1000,
        "raw_summary": "PPC Write Reg 101 = 1000"
    }
    assert len(rule_engine.evaluate_event(ppc_evt)) == 0, "Approved PPC write must not trigger alert"

    # 2. Attacker writes 0 to Inverter-2 register 101
    atk_evt = {
        "time": "2026-10-23T12:01:00Z",
        "src_ip": "10.10.1.99",
        "dst_ip": "10.10.1.12",
        "protocol": "MODBUS_TCP",
        "function": "WRITE_SINGLE_REGISTER",
        "address": 101,
        "value": 0,
        "raw_summary": "Attacker Write Reg 101 = 0"
    }
    alerts = rule_engine.evaluate_event(atk_evt)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["scenario"] == "S2_unauthorized_setpoint_write"
    assert "inverter-2 set-point written by 10.10.1.99; only 10.10.1.30 is allowed to write it" in a["reason"]
    assert a["attack_technique"] == "T0836"
    assert a["severity"] == "high"

def test_s3_vendor_out_of_hours(rule_engine):
    # Legitimate vendor read inside window (11:00)
    in_win_dt = datetime(2026, 10, 23, 11, 0, 0, tzinfo=timezone.utc)
    read_evt = {
        "time": in_win_dt.isoformat(),
        "src_ip": "10.10.1.50",
        "dst_ip": "10.10.1.11",
        "protocol": "MODBUS_TCP",
        "function": "READ_HOLDING_REGISTERS",
        "address": 105,
        "raw_summary": "Vendor Read FW"
    }
    assert len(rule_engine.evaluate_event(read_evt, current_time_override=in_win_dt)) == 0

    # Vendor write at 02:10 outside maintenance window (10:00 - 16:00)
    out_win_dt = datetime(2026, 10, 23, 2, 10, 0, tzinfo=timezone.utc)
    write_evt = {
        "time": out_win_dt.isoformat(),
        "src_ip": "10.10.1.50",
        "dst_ip": "10.10.1.11",
        "protocol": "MODBUS_TCP",
        "function": "WRITE_SINGLE_REGISTER",
        "address": 101,
        "value": 500,
        "raw_summary": "Vendor Write Reg 101 = 500"
    }
    alerts = rule_engine.evaluate_event(write_evt, current_time_override=out_win_dt)
    assert len(alerts) >= 1
    # Check S3 alert
    s3_alerts = [a for a in alerts if a["scenario"] == "S3_vendor_out_of_hours"]
    assert len(s3_alerts) == 1
    a = s3_alerts[0]
    assert "Vendor gateway sent writes at 02:10; its approved window is 10:00 to 16:00" in a["reason"]
    assert a["attack_technique"] == "T0885"

def test_s6_unauthorized_iec104_command(rule_engine):
    # Legitimate Grid Control Master (10.10.2.10) sends Single Command Type 45
    auth_cmd = {
        "time": "2026-10-23T12:00:00Z",
        "src_ip": "10.10.2.10",
        "dst_ip": "10.10.1.40",
        "protocol": "IEC_104",
        "function": "IEC104_C_SC_NA_1_SINGLE_COMMAND",
        "asdu_type": 45,
        "address": 1000,
        "value": 1,
        "raw_summary": "Grid Master Command"
    }
    assert len(rule_engine.evaluate_event(auth_cmd)) == 0

    # Attacker sends Single Command Type 45 to breaker point 1000
    unauth_cmd = {
        "time": "2026-10-23T12:02:00Z",
        "src_ip": "10.10.1.99",
        "dst_ip": "10.10.1.40",
        "protocol": "IEC_104",
        "function": "IEC104_C_SC_NA_1_SINGLE_COMMAND",
        "asdu_type": 45,
        "address": 1000,
        "value": 0,
        "raw_summary": "Attacker Command"
    }
    alerts = rule_engine.evaluate_event(unauth_cmd)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["scenario"] == "S6_unauthorized_iec104_command"
    assert "Control command to breaker point 1000 came from 10.10.1.99; only the grid control centre master 10.10.2.10 may send commands" in a["reason"]
    assert a["attack_technique"] == "T0855"
    assert a["severity"] == "critical"

def test_s5_iec104_flood(rule_engine):
    # Send 45 IEC-104 frames within 1 minute
    alerts = []
    base_epoch = 1700000000.0
    for i in range(45):
        evt = {
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": base_epoch + (i * 0.5),
            "src_ip": "10.10.1.99",
            "dst_ip": "10.10.1.40",
            "protocol": "IEC_104",
            "function": "IEC104_U_TESTFR_ACT",
            "asdu_type": None,
            "address": None,
            "raw_summary": "Flood Frame"
        }
        res = rule_engine.evaluate_event(evt)
        alerts.extend(res)

    s5_alerts = [a for a in alerts if a["scenario"] == "S5_iec104_flood"]
    assert len(s5_alerts) >= 1
    assert "IEC-104 outstation received" in s5_alerts[0]["reason"]
    assert s5_alerts[0]["attack_technique"] == "T0814"

def test_s8_protocol_recon(rule_engine):
    # Scan 55 distinct registers across multiple devices
    alerts = []
    base_epoch = 1700001000.0
    for r in range(1, 56):
        target_ip = "10.10.1.11" if r % 2 == 0 else "10.10.1.12"
        evt = {
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": base_epoch + (r * 0.2),
            "src_ip": "10.10.1.99",
            "dst_ip": target_ip,
            "protocol": "MODBUS_TCP",
            "function": "READ_HOLDING_REGISTERS",
            "address": r,
            "raw_summary": f"Recon Read Reg {r}"
        }
        res = rule_engine.evaluate_event(evt)
        alerts.extend(res)

    s8_alerts = [a for a in alerts if a["scenario"] == "S8_protocol_recon"]
    assert len(s8_alerts) >= 1
    assert "read" in s8_alerts[0]["reason"] and "distinct registers" in s8_alerts[0]["reason"]
    assert s8_alerts[0]["attack_technique"] == "T0846"
