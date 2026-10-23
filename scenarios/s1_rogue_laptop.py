"""
Scenario S1: Rogue Laptop in Inverter Control Room (ICR).
Adversary connects an unapproved rogue laptop to the ICR switch and initiates discovery scanning.
Expected detection: "New device 10.10.1.X (MAC ...) appeared on the control network and has not been approved"
MITRE ATT&CK for ICS: T0886
"""
import sys
from pathlib import Path
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import time
from sim.common import iso_utc_now
from scenarios.common import log_attack_run, get_standalone_pipeline

def run_s1(target_ip: str = "10.10.1.11", sensor_pipeline=None, run_id: str = None) -> dict:
    t0 = iso_utc_now()
    epoch = time.time()

    # Assign dynamic rogue IP and MAC based on run index if provided
    idx = 99
    if run_id:
        digits = "".join(filter(str.isdigit, run_id))
        if digits:
            idx = 90 + int(digits) % 10

    rogue_ip = f"10.10.1.{idx}"
    rogue_mac = f"02:42:0a:0a:01:{idx:02x}"
    desc = f"Rogue laptop {rogue_ip} plugged into ICR switch; initiates ARP/Ping discovery scan"

    if sensor_pipeline:
        sensor_pipeline.process_raw_event({
            "time": t0,
            "timestamp_epoch": epoch,
            "src_ip": rogue_ip,
            "src_mac": rogue_mac,
            "dst_ip": target_ip,
            "dst_mac": "02:42:0a:0a:01:0b",
            "protocol": "ARP",
            "function": "ARP_SCAN",
            "address": None,
            "value": None,
            "raw_summary": f"ARP probe who-has {target_ip} tell {rogue_ip}"
        })

    time.sleep(0.1)
    t1 = iso_utc_now()
    return log_attack_run("S1", rogue_ip, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    pipe = get_standalone_pipeline()
    rec = run_s1(sensor_pipeline=pipe)
    print("S1 executed:", rec)
