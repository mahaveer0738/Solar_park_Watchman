"""
Milestone 6 Verification Tests: Alert Builder, Central Collector & Store-and-Forward Resilience.
"""
import os
import time
import pytest
from sensor.alert_builder import AlertBuilder
from central.app import CentralServer
from sensor.forwarder import StoreAndForwardClient

TEST_ALERTS_FILE = "runs/test_alerts.jsonl"
TEST_QUEUE_FILE = "data/test_queue.jsonl"
TEST_PORT = 8011

@pytest.fixture
def clean_files():
    for f in (TEST_ALERTS_FILE, TEST_QUEUE_FILE):
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass
    yield
    for f in (TEST_ALERTS_FILE, TEST_QUEUE_FILE):
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass

def test_alert_builder_schema(clean_files):
    builder = AlertBuilder(alerts_path=TEST_ALERTS_FILE)
    alert = builder.build_and_publish(
        severity="high",
        scenario="S2_unauthorized_setpoint_write",
        device="inverter-2",
        source="10.10.1.99",
        reason="inverter-2 set-point written by 10.10.1.99; only 10.10.1.30 is allowed to write it",
        attack_technique="T0836",
        evidence=["zeek_modbus_log:1842"]
    )

    assert alert["severity"] == "high"
    assert alert["scenario"] == "S2_unauthorized_setpoint_write"
    assert alert["attack_technique"] == "T0836"
    assert len(alert["evidence"]) == 1

    # Verify JSON lines file exists and contains the exact record
    assert os.path.exists(TEST_ALERTS_FILE)
    recent = builder.get_recent_alerts()
    assert len(recent) == 1
    assert recent[0]["device"] == "inverter-2"

def test_store_and_forward_resilience(clean_files):
    endpoint = f"http://127.0.0.1:{TEST_PORT}/api/alerts"
    client = StoreAndForwardClient(endpoint=endpoint, queue_path=TEST_QUEUE_FILE, retry_interval=0.5)

    alert_sample = {
        "time": "2026-10-23T12:00:00Z",
        "severity": "high",
        "scenario": "S1_rogue_device",
        "device": "10.10.1.99",
        "source": "10.10.1.99",
        "reason": "New device 10.10.1.99 appeared",
        "attack_technique": "T0886",
        "evidence": ["arp_probe"]
    }

    # 1. Central is currently DOWN. Send alert -> must be queued to disk!
    delivered = client.send_alert(alert_sample)
    assert delivered is False, "Delivery should fail when server is offline"
    assert os.path.exists(TEST_QUEUE_FILE), "Failed alert must be queued to file"

    # 2. Start Central Server
    server = CentralServer(port=TEST_PORT)
    server.start()
    time.sleep(0.5)

    try:
        # Start client retry worker
        client.start()
        # Wait for queue to flush
        time.sleep(1.5)

        # 3. Verify queue file is cleared
        assert not os.path.exists(TEST_QUEUE_FILE) or os.path.getsize(TEST_QUEUE_FILE) == 0

        # 4. Send another alert while Central is UP -> delivered directly
        direct_delivered = client.send_alert(alert_sample)
        assert direct_delivered is True

    finally:
        client.stop()
        server.stop()
