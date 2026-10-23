"""
Scenario S8: Industrial Protocol Reconnaissance.
Adversary enumerates unit IDs and sequentially reads registers across multiple plant devices.
Expected detection: "10.10.1.99 read 300 distinct registers across 5 devices in one minute; normal is 12"
Rule + ML detector.
MITRE ATT&CK for ICS: T0846
"""
import sys
from pathlib import Path
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import time
from sim.common import iso_utc_now, IP_ATTACKER
from scenarios.common import log_attack_run, get_standalone_pipeline

def run_s8(target_ips: list[str] = None, sensor_pipeline=None, run_id: str = None) -> dict:
    targets = target_ips or ["10.10.1.11", "10.10.1.12", "10.10.1.13", "10.10.1.20"]
    t0 = iso_utc_now()
    base_epoch = time.time()
    desc = f"Attacker scans unit IDs and sequentially reads 60 registers across {len(targets)} devices"

    # Sequentially read registers 1 to 60 across target devices
    for reg in range(1, 61):
        target_ip = targets[reg % len(targets)]
        pkt_time = base_epoch + (reg * 0.05)
        if sensor_pipeline:
            sensor_pipeline.process_raw_event({
                "time": iso_utc_now(),
                "timestamp_epoch": pkt_time,
                "src_ip": IP_ATTACKER,
                "src_mac": "02:42:0a:0a:01:99",
                "dst_ip": target_ip,
                "dst_mac": "02:42:0a:0a:01:0b",
                "protocol": "MODBUS_TCP",
                "function": "READ_HOLDING_REGISTERS",
                "address": reg,
                "count": 1,
                "unit_id": (reg % 5) + 1,
                "raw_summary": f"Modbus Recon Read unit={(reg%5)+1} reg={reg}"
            })

    time.sleep(0.2)
    t1 = iso_utc_now()
    return log_attack_run("S8", IP_ATTACKER, "10.10.1.0/24", desc, t0, t1, run_id)

if __name__ == "__main__":
    pipe = get_standalone_pipeline()
    rec = run_s8(sensor_pipeline=pipe)
    print("S8 executed:", rec)
