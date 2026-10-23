"""
Scenario S3: Abused Vendor Gateway Out-of-Hours Access.
Vendor gateway (10.10.1.50) executes a write operation outside its approved window (10:00 - 16:00).
Expected detection: "Vendor gateway sent writes at 02:10; its approved window is 10:00 to 16:00"
MITRE ATT&CK for ICS: T0885
"""
import sys
from pathlib import Path
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import time
from datetime import datetime, timezone
from sim.common import iso_utc_now, IP_VENDOR_GW, IP_INVERTER_1, PORT_INVERTER_1, REG_ACTIVE_POWER_LIMIT
from scenarios.common import log_attack_run, get_standalone_pipeline

def run_s3(target_ip: str = IP_INVERTER_1, target_port: int = PORT_INVERTER_1, sensor_pipeline=None, run_id: str = None) -> dict:
    # Simulated out-of-hours timestamp: 02:10 UTC
    sim_dt = datetime(2026, 10, 23, 2, 10, 0, tzinfo=timezone.utc)
    t0 = sim_dt.isoformat()
    epoch = sim_dt.timestamp()
    desc = "Vendor gateway initiated write command at 02:10 outside maintenance window (10:00-16:00)"

    if sensor_pipeline:
        sensor_pipeline.process_raw_event({
            "time": t0,
            "timestamp_epoch": epoch,
            "src_ip": IP_VENDOR_GW,
            "src_mac": "02:42:0a:0a:01:32",
            "dst_ip": target_ip,
            "dst_mac": "02:42:0a:0a:01:0b",
            "protocol": "MODBUS_TCP",
            "function": "WRITE_SINGLE_REGISTER",
            "address": REG_ACTIVE_POWER_LIMIT,
            "value": 500,
            "unit_id": 1,
            "raw_summary": "Modbus FC06 Vendor Write Reg 101 = 500"
        }, current_time_override=sim_dt)

    time.sleep(0.1)
    t1 = iso_utc_now()
    return log_attack_run("S3", IP_VENDOR_GW, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    pipe = get_standalone_pipeline()
    rec = run_s3(sensor_pipeline=pipe)
    print("S3 executed:", rec)
