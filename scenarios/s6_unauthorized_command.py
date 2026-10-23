"""
Scenario S6: Unauthorized IEC-104 Control Command.
Adversary sends Single Command (Type 45) to substation breaker IOA 1000 from non-master host.
Expected detection: "Control command to breaker point 1000 came from 10.10.1.99; only the grid control centre master 10.10.2.10 may send commands"
MITRE ATT&CK for ICS: T0855
"""
import time
from sim.common import (
    iso_utc_now, IP_ATTACKER, IP_IEC104_OUTSTATION,
    PORT_IEC104, IOA_BREAKER_POINT, ASDU_C_SC_NA_1
)
from sim.iec104 import IEC104Client
from scenarios.common import log_attack_run

def run_s6(target_ip: str = IP_IEC104_OUTSTATION, target_port: int = PORT_IEC104, sensor_pipeline=None, run_id: str = None) -> dict:
    t0 = iso_utc_now()
    epoch = time.time()
    desc = f"Attacker sends unauthorized Type 45 trip command to breaker IOA {IOA_BREAKER_POINT}"

    # Try live connection
    try:
        client = IEC104Client(host="127.0.0.1", port=target_port)
        if client.connect(timeout=1.0):
            client.send_command_type45(ioa=IOA_BREAKER_POINT, command_val=0)  # Trip breaker
            client.close()
    except Exception:
        pass

    if sensor_pipeline:
        sensor_pipeline.process_raw_event({
            "time": t0,
            "timestamp_epoch": epoch,
            "src_ip": IP_ATTACKER,
            "src_mac": "02:42:0a:0a:01:99",
            "dst_ip": target_ip,
            "dst_mac": "02:42:0a:0a:01:28",
            "protocol": "IEC_104",
            "function": "IEC104_C_SC_NA_1_SINGLE_COMMAND",
            "asdu_type": ASDU_C_SC_NA_1,
            "address": IOA_BREAKER_POINT,
            "value": 0,
            "raw_summary": f"IEC-104 Type 45 Trip Command IOA={IOA_BREAKER_POINT} from {IP_ATTACKER}"
        })

    time.sleep(0.1)
    t1 = iso_utc_now()
    return log_attack_run("S6", IP_ATTACKER, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    rec = run_s6()
    print("S6 executed:", rec)
