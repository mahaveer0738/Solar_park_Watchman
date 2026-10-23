"""
Scenario S5: IEC-104 Traffic Flood.
Adversary opens sessions and floods outstation (10.10.1.40) with rapid frame bursts.
Expected detection: "IEC-104 outstation received 40x its normal packet rate in 60 seconds from 10.10.1.99"
Rule + ML detector.
MITRE ATT&CK for ICS: T0814
"""
import time
from sim.common import iso_utc_now, IP_ATTACKER, IP_IEC104_OUTSTATION, PORT_IEC104
from sim.iec104 import build_apdu_u
from scenarios.common import log_attack_run

def run_s5(target_ip: str = IP_IEC104_OUTSTATION, target_port: int = PORT_IEC104, sensor_pipeline=None, run_id: str = None) -> dict:
    t0 = iso_utc_now()
    base_epoch = time.time()
    desc = f"Attacker floods {target_ip} with 50 IEC-104 APDUs within 2 seconds"

    # Send 50 burst frames
    for i in range(50):
        pkt_time = base_epoch + (i * 0.04)
        if sensor_pipeline:
            sensor_pipeline.process_raw_event({
                "time": iso_utc_now(),
                "timestamp_epoch": pkt_time,
                "src_ip": IP_ATTACKER,
                "src_mac": "02:42:0a:0a:01:99",
                "dst_ip": target_ip,
                "dst_mac": "02:42:0a:0a:01:28",
                "protocol": "IEC_104",
                "function": "IEC104_U_TESTFR_ACT",
                "asdu_type": None,
                "address": None,
                "value": None,
                "raw_summary": "IEC-104 U-Format TESTFR_ACT flood frame"
            })

    time.sleep(0.2)
    t1 = iso_utc_now()
    return log_attack_run("S5", IP_ATTACKER, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    rec = run_s5()
    print("S5 executed:", rec)
