"""
Milestone 5 Verification Tests: ML Detector & Physical Consistency Check (S5, S7, S8).
"""
import pytest
import numpy as np
from sensor.ml_detector import MLAnomalyDetector

TEST_MODEL_PATH = "data/test_isolation_forest.joblib"

@pytest.fixture
def ml_detector():
    return MLAnomalyDetector(model_path=TEST_MODEL_PATH, contamination=0.01)

def test_ml_normal_traffic(ml_detector):
    # Ingest typical normal traffic
    base_epoch = 1700000000.0
    alerts = []
    for i in range(20):
        evt = {
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": base_epoch + (i * 2.0),
            "src_ip": "10.10.1.10",
            "dst_ip": "10.10.1.11",
            "protocol": "MODBUS_TCP",
            "function": "READ_HOLDING_REGISTERS",
            "address": 101,
            "value": 1000
        }
        res = ml_detector.ingest_event(evt)
        alerts.extend(res)

    assert len(alerts) == 0, "Normal polling traffic should not trigger ML alerts"

def test_s7_frozen_telemetry_consistency(ml_detector):
    base_epoch = 1700005000.0
    alerts = []

    # Weather irradiance is rising significantly (500 W/m^2 to 950 W/m^2)
    # But inverter-1 power is frozen at exactly 850 kW
    for i in range(12):
        t = base_epoch + (i * 10.0)
        curr_irr = 500.0 + (i * 40.0)  # Total delta = 440 W/m^2

        # PLC publishes weather update
        ml_detector.ingest_event({
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": t,
            "src_ip": "10.10.1.20",
            "dst_ip": "10.10.1.10",
            "protocol": "MODBUS_TCP",
            "function": "READ_HOLDING_REGISTERS",
            "address": 201,
            "value": curr_irr
        })

        # SCADA reads Inverter-1: power is frozen at 850 kW!
        res = ml_detector.ingest_event({
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": t,
            "src_ip": "10.10.1.10",
            "dst_ip": "10.10.1.11",
            "protocol": "MODBUS_TCP",
            "function": "READ_HOLDING_REGISTERS",
            "address": 102,
            "value": 850
        })
        alerts.extend(res)

    s7_alerts = [a for a in alerts if a["scenario"] == "S7_frozen_telemetry"]
    assert len(s7_alerts) >= 1
    a = s7_alerts[0]
    assert "inverter-1 reported identical power for 20 minutes while irradiance varied" in a["reason"]
    assert a["attack_technique"] == "T0830"
    assert a["confidence"] >= 0.80

def test_s5_ml_flood_detection(ml_detector):
    base_epoch = 1700010000.0
    alerts = []
    # Send 70 IEC-104 packets in rapid succession from attacker
    for i in range(70):
        evt = {
            "time": "2026-10-23T12:00:00Z",
            "timestamp_epoch": base_epoch + (i * 0.3),
            "src_ip": "10.10.1.99",
            "dst_ip": "10.10.1.40",
            "protocol": "IEC_104",
            "function": "IEC104_I",
            "address": 1000,
            "value": 1
        }
        res = ml_detector.ingest_event(evt)
        alerts.extend(res)

    ml_s5 = [a for a in alerts if "S5" in a["scenario"]]
    assert len(ml_s5) >= 1
    assert ml_s5[0]["confidence"] > 0.60
