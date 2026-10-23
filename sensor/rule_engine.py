"""
Deterministic Rule Engine for Solar Park Watchman Sensor.
Enforces security policies defined in policy.yaml:
- S2: Inverter setpoint write ACLs (register 101: 10.10.1.30 only)
- S3: Vendor remote gateway maintenance time window enforcement (10:00-16:00)
- S5: IEC-104 packet rate flood detection
- S6: Unauthorized IEC-104 control commands (ASDU Types 45/46/50)
- S8: Modbus protocol reconnaissance & register enumeration detection
"""
import yaml
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional, Callable
from sim.common import iso_utc_now

class RuleEngine:
    def __init__(self, policy_path: str = "config/policy.yaml", on_alert_callback: Optional[Callable] = None):
        self.policy_path = policy_path
        self.on_alert = on_alert_callback
        self.policy = self._load_policy()

        # Sliding window trackers (window = 60 seconds)
        # IEC-104 packets per source IP: deque of timestamps
        self.iec104_packet_windows = defaultdict(deque)
        # Recon tracking per source IP: deque of (timestamp, dst_ip, address)
        self.recon_windows = defaultdict(deque)

        # Alert de-duplication cache: (scenario, src_ip, dst_ip) -> last_alert_time
        self.recent_alerts = {}
        self.dedup_cooldown_seconds = 0.5

    def _load_policy(self) -> dict:
        if os.path.exists(self.policy_path):
            with open(self.policy_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def reload_policy(self):
        self.policy = self._load_policy()

    def evaluate_event(self, event: dict, current_time_override: Optional[datetime] = None) -> list[dict]:
        """
        Evaluate a single normalized event against all deterministic rules.
        Returns list of generated alert dictionaries.
        """
        alerts = []
        src_ip = event["src_ip"]
        dst_ip = event.get("dst_ip", "")
        proto = event.get("protocol", "")
        func = event.get("function", "")
        addr = event.get("address")
        epoch = event.get("timestamp_epoch", time.time())
        now_dt = current_time_override or datetime.fromtimestamp(epoch, tz=timezone.utc)
        now_iso = event.get("time") or now_dt.isoformat()

        # --- Rule S2: Unauthorized Modbus Setpoint Write ---
        if proto == "MODBUS_TCP" and ("WRITE" in func):
            setpoint_reg = self.policy.get("modbus", {}).get("setpoint_register", 101)
            inverter_ips = self.policy.get("modbus", {}).get("inverter_ips", ["10.10.1.11", "10.10.1.12", "10.10.1.13"])
            auth_writers = self.policy.get("modbus", {}).get("authorized_setpoint_writers", ["10.10.1.30"])

            if addr == setpoint_reg and dst_ip in inverter_ips:
                if src_ip not in auth_writers:
                    # Friendly name resolution
                    dev_name = dst_ip
                    for dev in self.policy.get("inventory", {}).get("approved_devices", []):
                        if dev["ip"] == dst_ip:
                            dev_name = dev["name"]
                            break

                    auth_str = ", ".join(auth_writers)
                    alert = {
                        "time": now_iso,
                        "severity": "high",
                        "scenario": "S2_unauthorized_setpoint_write",
                        "device": dev_name,
                        "source": src_ip,
                        "reason": f"{dev_name} set-point written by {src_ip}; only {auth_str} is allowed to write it",
                        "attack_technique": "T0836",  # MITRE ATT&CK for ICS: Modify Parameter
                        "evidence": [f"modbus_event:{event.get('raw_summary')}"]
                    }
                    alerts.append(alert)

        # --- Rule S3: Vendor Remote Gateway Outside Maintenance Window ---
        vendor_gw_ip = self.policy.get("vendor_policy", {}).get("gateway_ip", "10.10.1.50")
        if src_ip == vendor_gw_ip and ("WRITE" in func):
            window = self.policy.get("vendor_policy", {}).get("approved_window", {"start_hour": 10, "end_hour": 16})
            start_h = window.get("start_hour", 10)
            end_h = window.get("end_hour", 16)
            current_h = now_dt.hour
            time_str = f"{current_h:02d}:{now_dt.minute:02d}"

            # Check if outside approved hours
            if current_h < start_h or current_h >= end_h:
                alert = {
                    "time": now_iso,
                    "severity": "high",
                    "scenario": "S3_vendor_out_of_hours",
                    "device": "vendor-gw",
                    "source": src_ip,
                    "reason": f"Vendor gateway sent writes at {time_str}; its approved window is {start_h:02d}:00 to {end_h:02d}:00",
                    "attack_technique": "T0885",  # MITRE ATT&CK for ICS: Commonly Used Port / Unauthorized Access
                    "evidence": [f"vendor_write_event:{event.get('raw_summary')}"]
                }
                alerts.append(alert)

        # --- Rule S6: Unauthorized IEC-104 Control Command ---
        if proto == "IEC_104":
            asdu_type = event.get("asdu_type")
            ctrl_types = self.policy.get("iec104", {}).get("control_asdu_types", [45, 46, 50])
            auth_masters = self.policy.get("iec104", {}).get("authorized_masters", ["10.10.2.10"])
            crit_ioa = self.policy.get("iec104", {}).get("critical_ioa", 1000)

            if asdu_type in ctrl_types:
                if src_ip not in auth_masters:
                    master_str = ", ".join(auth_masters)
                    alert = {
                        "time": now_iso,
                        "severity": "critical",
                        "scenario": "S6_unauthorized_iec104_command",
                        "device": "iec104-outstation",
                        "source": src_ip,
                        "reason": f"Control command to breaker point {addr or crit_ioa} came from {src_ip}; only the grid control centre master {master_str} may send commands",
                        "attack_technique": "T0855",  # MITRE ATT&CK for ICS: Unauthorized Command Message
                        "evidence": [f"iec104_event:{event.get('raw_summary')}"]
                    }
                    alerts.append(alert)

        # --- Rule S5: IEC-104 Rate Limiting & Flood Detection ---
        if proto == "IEC_104" and dst_ip == self.policy.get("iec104", {}).get("outstation_ip", "10.10.1.40"):
            q = self.iec104_packet_windows[src_ip]
            q.append(epoch)
            while q and q[0] < epoch - 60.0:
                q.popleft()

            rate_limit = self.policy.get("thresholds", {}).get("iec104_max_packets_per_minute", 40)
            if len(q) > rate_limit:
                # Deduplicate flood alert within cooldown
                key = ("S5_iec104_flood", src_ip, dst_ip)
                if epoch - self.recent_alerts.get(key, 0) > self.dedup_cooldown_seconds:
                    self.recent_alerts[key] = epoch
                    rate_factor = max(10, int(len(q) / 2.0))
                    alert = {
                        "time": now_iso,
                        "severity": "high",
                        "scenario": "S5_iec104_flood",
                        "device": "iec104-outstation",
                        "source": src_ip,
                        "reason": f"IEC-104 outstation received {rate_factor}x its normal packet rate in 60 seconds from {src_ip}",
                        "attack_technique": "T0814",  # MITRE ATT&CK for ICS: Denial of Service
                        "evidence": [f"iec104_flood_window:{len(q)}_packets_in_60s"]
                    }
                    alerts.append(alert)
                    q.clear()

        # --- Rule S8: Modbus Protocol Reconnaissance & Register Enumeration ---
        if proto == "MODBUS_TCP" and ("READ" in func) and addr is not None:
            rq = self.recon_windows[src_ip]
            rq.append((epoch, dst_ip, addr))
            while rq and rq[0][0] < epoch - 60.0:
                rq.popleft()

            unique_regs = {item[2] for item in rq}
            unique_devs = {item[1] for item in rq}

            max_regs = self.policy.get("thresholds", {}).get("recon_max_unique_registers_per_min", 50)
            max_devs = self.policy.get("thresholds", {}).get("recon_max_target_devices_per_min", 3)

            if len(unique_regs) > max_regs or (len(unique_regs) > 20 and len(unique_devs) >= max_devs):
                key = ("S8_protocol_recon", src_ip, "recon")
                if epoch - self.recent_alerts.get(key, 0) > self.dedup_cooldown_seconds:
                    self.recent_alerts[key] = epoch
                    alert = {
                        "time": now_iso,
                        "severity": "medium",
                        "scenario": "S8_protocol_recon",
                        "device": "plant_network",
                        "source": src_ip,
                        "reason": f"{src_ip} read {len(unique_regs)} distinct registers across {len(unique_devs)} devices in one minute; normal is 12",
                        "attack_technique": "T0846",  # MITRE ATT&CK for ICS: Remote System Discovery
                        "evidence": [f"recon_window:{len(unique_regs)}_unique_regs_scanned"]
                    }
                    alerts.append(alert)
                    rq.clear()

        # Dispatch callbacks
        for a in alerts:
            if self.on_alert:
                self.on_alert(a)

        return alerts
