"""
Milestone 3 Verification Tests: Device Inventory and Behavioral Role Inference.
"""
import os
import pytest
from sensor.inventory import DeviceInventory

TEST_DB = "data/test_inventory.db"

@pytest.fixture
def clean_inventory():
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    inv = DeviceInventory(db_path=TEST_DB, policy_path="config/policy.yaml")
    yield inv
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

def test_approved_device_discovery(clean_inventory):
    # Legitimate SCADA polling Inverter-1
    evt1 = {
        "time": "2026-10-23T12:00:00Z",
        "src_ip": "10.10.1.10",
        "src_mac": "02:42:0a:0a:01:0a",
        "dst_ip": "10.10.1.11",
        "dst_mac": "02:42:0a:0a:01:0b",
        "protocol": "MODBUS_TCP",
        "function": "READ_HOLDING_REGISTERS",
        "address": 101,
        "raw_summary": "SCADA Poll"
    }

    alert, is_new = clean_inventory.update_from_event(evt1)
    assert alert is None, "Approved device should not raise rogue device alert"
    assert is_new is True

    scada = clean_inventory.get_device("10.10.1.10")
    assert scada is not None
    assert scada["approved"] == 1
    assert scada["inferred_role"] == "SCADA"

    inv1 = clean_inventory.get_device("10.10.1.11")
    assert inv1 is not None
    assert inv1["approved"] == 1
    assert inv1["inferred_role"] == "Inverter"

def test_s1_rogue_laptop_detection(clean_inventory):
    alerts = []
    clean_inventory.on_new_device_alert = lambda a: alerts.append(a)

    # Rogue device appears on network sending ARP or Modbus probe
    rogue_evt = {
        "time": "2026-10-23T12:05:00Z",
        "src_ip": "10.10.1.99",
        "src_mac": "02:42:0a:0a:01:99",
        "dst_ip": "10.10.1.12",
        "dst_mac": "02:42:0a:0a:01:0c",
        "protocol": "ARP",
        "function": "ARP_SCAN",
        "address": None,
        "raw_summary": "ARP probe 10.10.1.99 -> 10.10.1.12"
    }

    alert, is_new = clean_inventory.update_from_event(rogue_evt)
    assert is_new is True
    assert alert is not None
    assert alert["scenario"] == "S1_rogue_device"
    assert alert["device"] == "10.10.1.99"
    assert "New device 10.10.1.99 (MAC 02:42:0a:0a:01:99) appeared on the control network and has not been approved" in alert["reason"]
    assert alert["attack_technique"] == "T0886"

    # Verify database state
    dev = clean_inventory.get_device("10.10.1.99")
    assert dev is not None
    assert dev["approved"] == 0
    assert dev["mac"] == "02:42:0a:0a:01:99"
