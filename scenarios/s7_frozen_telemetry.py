"""
Scenario S7: Frozen / Spoofed Telemetry (ML & Physics Consistency Case).
Adversary or sensor fault freezes Inverter-1 telemetry output at static value (850 kW)
while physical solar irradiance varies significantly across the park.
Expected detection: "inverter-1 reported identical power for 20 minutes while irradiance varied"
ML + physical consistency check.
MITRE ATT&CK for ICS: T0830
"""
import time
from sim.common import iso_utc_now, IP_INVERTER_1, IP_PLC
from scenarios.common import log_attack_run

def run_s7(target_ip: str = IP_INVERTER_1, sensor_pipeline=None, run_id: str = None) -> dict:
    t0 = iso_utc_now()
    base_epoch = time.time()
    desc = f"Inverter-1 telemetry frozen at 850 kW while solar irradiance fluctuates > 400 W/m^2"

    # Simulate 12 measurement steps: irradiance rises from 500 to 950 W/m^2
    # but Inverter-1 returns frozen 850 kW
    for i in range(12):
        step_epoch = base_epoch + (i * 5.0)
        curr_irr = 500.0 + (i * 40.0)

        if sensor_pipeline:
            # PLC environmental update
            sensor_pipeline.process_raw_event({
                "time": iso_utc_now(),
                "timestamp_epoch": step_epoch,
                "src_ip": IP_PLC,
                "dst_ip": "10.10.1.10",
                "protocol": "MODBUS_TCP",
                "function": "READ_HOLDING_REGISTERS",
                "address": 201,
                "value": curr_irr,
                "raw_summary": f"PLC Irradiance = {curr_irr} W/m^2"
            })

            # Inverter-1 frozen reading
            sensor_pipeline.process_raw_event({
                "time": iso_utc_now(),
                "timestamp_epoch": step_epoch,
                "src_ip": "10.10.1.10",
                "dst_ip": target_ip,
                "protocol": "MODBUS_TCP",
                "function": "READ_HOLDING_REGISTERS",
                "address": 102,
                "value": 850,
                "raw_summary": "Inverter-1 Power Read = 850 kW (FROZEN)"
            })

    time.sleep(0.2)
    t1 = iso_utc_now()
    return log_attack_run("S7", target_ip, target_ip, desc, t0, t1, run_id)

if __name__ == "__main__":
    rec = run_s7()
    print("S7 executed:", rec)
