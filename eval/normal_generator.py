"""
Normal Traffic Generator for Solar Park Watchman.
Simulates realistic normal operation of a solar plant ICR:
- SCADA poller reading inverters 1, 2, 3 and PLC holding registers
- PPC sending approved active power limits (register 101)
- IEC-104 Outstation sending spontaneous telemetry (active power, breaker status)
- Vendor Gateway performing approved health/firmware reads during maintenance window (10:00-16:00)
Supports --speedup to generate:
- At least 12 hours of baseline normal operation (for model training)
- At least 1 hour of held-out normal traffic (never used for training, for false-positive validation)
"""
import json
import time
import argparse
import random
from datetime import datetime, timezone, timedelta
from typing import Iterator
from sim.common import (
    IP_SCADA, IP_INVERTER_1, IP_INVERTER_2, IP_INVERTER_3,
    IP_PLC, IP_PPC, IP_IEC104_OUTSTATION, IP_GRID_CENTRE,
    IP_VENDOR_GW, REG_ACTIVE_POWER_LIMIT, REG_PLC_IRRADIANCE,
    calculate_solar_irradiance
)

def generate_normal_stream(sim_hours: float = 12.0, start_sim_hour: float = 6.0, speedup: float = 60.0, step_sec: float = 10.0) -> Iterator[dict]:
    """
    Yields normalized events representing authentic normal plant traffic.
    sim_hours: total simulated hours to produce.
    speedup: simulated time acceleration factor.
    step_sec: simulated step resolution in seconds.
    """
    base_time = datetime(2026, 10, 23, int(start_sim_hour), 0, 0, tzinfo=timezone.utc)
    sim_seconds_total = sim_hours * 3600.0

    inverters = [
        {"ip": IP_INVERTER_1, "mac": "02:42:0a:0a:01:0b", "name": "inverter-1"},
        {"ip": IP_INVERTER_2, "mac": "02:42:0a:0a:01:0c", "name": "inverter-2"},
        {"ip": IP_INVERTER_3, "mac": "02:42:0a:0a:01:0d", "name": "inverter-3"},
    ]

    current_sim_sec = 0.0
    while current_sim_sec < sim_seconds_total:
        curr_dt = base_time + timedelta(seconds=current_sim_sec)
        time_iso = curr_dt.isoformat()
        epoch = curr_dt.timestamp()
        sim_h = (start_sim_hour + (current_sim_sec / 3600.0)) % 24.0

        irr, amb, mod = calculate_solar_irradiance(sim_h)

        # 1. SCADA Polling PLC
        yield {
            "time": time_iso,
            "timestamp_epoch": epoch,
            "src_ip": IP_SCADA,
            "src_mac": "02:42:0a:0a:01:0a",
            "dst_ip": IP_PLC,
            "dst_mac": "02:42:0a:0a:01:14",
            "protocol": "MODBUS_TCP",
            "function": "READ_HOLDING_REGISTERS",
            "address": REG_PLC_IRRADIANCE,
            "count": 5,
            "value": int(irr),
            "unit_id": 1,
            "raw_summary": f"SCADA Poll PLC Irradiance={int(irr)}"
        }

        # 2. SCADA Polling Inverters
        for inv in inverters:
            gen_kw = min(1000.0, (irr / 1000.0) * 980.0 + random.gauss(0, 2.0)) if irr > 20 else 0.0
            yield {
                "time": time_iso,
                "timestamp_epoch": epoch + 0.1,
                "src_ip": IP_SCADA,
                "src_mac": "02:42:0a:0a:01:0a",
                "dst_ip": inv["ip"],
                "dst_mac": inv["mac"],
                "protocol": "MODBUS_TCP",
                "function": "READ_HOLDING_REGISTERS",
                "address": 101,
                "count": 5,
                "value": int(gen_kw),
                "unit_id": 1,
                "raw_summary": f"SCADA Poll {inv['name']} Power={int(gen_kw)} kW"
            }

        # 3. PPC periodic approved setpoint updates (every 5 minutes / 300s)
        if int(current_sim_sec) % 300 < step_sec:
            for inv in inverters:
                yield {
                    "time": time_iso,
                    "timestamp_epoch": epoch + 0.5,
                    "src_ip": IP_PPC,
                    "src_mac": "02:42:0a:0a:01:1e",
                    "dst_ip": inv["ip"],
                    "dst_mac": inv["mac"],
                    "protocol": "MODBUS_TCP",
                    "function": "WRITE_SINGLE_REGISTER",
                    "address": REG_ACTIVE_POWER_LIMIT,
                    "value": 1000,
                    "unit_id": 1,
                    "raw_summary": f"PPC Setpoint Update {inv['name']} Reg 101 = 1000"
                }

        # 4. IEC-104 Outstation spontaneous telemetry (every 10 seconds)
        if int(current_sim_sec) % 10 < step_sec:
            total_mw = round(max(0.0, (irr / 1000.0) * 2.94), 2)
            yield {
                "time": time_iso,
                "timestamp_epoch": epoch + 0.3,
                "src_ip": IP_IEC104_OUTSTATION,
                "src_mac": "02:42:0a:0a:01:28",
                "dst_ip": IP_GRID_CENTRE,
                "dst_mac": "02:42:0a:0a:02:0a",
                "protocol": "IEC_104",
                "function": "IEC104_M_ME_NC_1_MEASURED_SHORT_FLOAT",
                "asdu_type": 13,
                "address": 1001,
                "value": total_mw,
                "raw_summary": f"IEC-104 Telemetry Total MW={total_mw}"
            }

        # 5. Vendor Gateway periodic maintenance read (only during 10:00 - 16:00, e.g. every 15 min)
        if 10.0 <= sim_h < 16.0 and int(current_sim_sec) % 900 < step_sec:
            yield {
                "time": time_iso,
                "timestamp_epoch": epoch + 0.7,
                "src_ip": IP_VENDOR_GW,
                "src_mac": "02:42:0a:0a:01:32",
                "dst_ip": IP_INVERTER_1,
                "dst_mac": "02:42:0a:0a:01:0b",
                "protocol": "MODBUS_TCP",
                "function": "READ_HOLDING_REGISTERS",
                "address": 105,
                "value": 0x0102,
                "unit_id": 1,
                "raw_summary": "Vendor GW Routine Diagnostics Read FW Version"
            }

        current_sim_sec += step_sec

def save_traffic_file(output_path: str, sim_hours: float, speedup: float = 60.0, step_sec: float = 10.0):
    events = list(generate_normal_stream(sim_hours=sim_hours, speedup=speedup, step_sec=step_sec))
    with open(output_path, "w", encoding="utf-8") as f:
        for evt in events:
            f.write(json.dumps(evt) + "\n")
    print(f"Generated {len(events)} normal events ({sim_hours} sim hours, step={step_sec}s) -> {output_path}")
    return len(events)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normal Traffic Generator for Solar Park Watchman")
    parser.add_argument("--hours", type=float, default=12.0, help="Simulated hours to generate")
    parser.add_argument("--speedup", type=float, default=60.0, help="Speedup multiplier")
    parser.add_argument("--step", type=float, default=10.0, help="Step seconds")
    parser.add_argument("--out", type=str, default="data/baseline_train.jsonl", help="Output file")
    args = parser.parse_args()

    save_traffic_file(args.out, args.hours, args.speedup, args.step)
