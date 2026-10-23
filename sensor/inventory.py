"""
SQLite-backed Device Inventory and Behavioral Role Inference Engine.
High-performance in-memory caching with persistent WAL SQLite storage.
Tracks: IP, MAC, protocols, inferred role, first_seen, last_seen, approved flag.
Infers roles dynamically from observed traffic patterns.
Raises immediate plain-language alerts when an unapproved device appears (Scenario S1).
"""
import sqlite3
import threading
import yaml
import os
from typing import Optional, Callable
from sim.common import iso_utc_now

class DeviceInventory:
    def __init__(self, db_path: str = "data/inventory.db", policy_path: str = "config/policy.yaml", on_new_device_alert: Optional[Callable] = None):
        self.db_path = db_path
        self.policy_path = policy_path
        self.on_new_device_alert = on_new_device_alert
        self._lock = threading.Lock()
        self._cache = {}
        self._uncommitted_count = 0

        # Load approved whitelist from policy
        self.approved_map = {}
        if os.path.exists(self.policy_path):
            with open(self.policy_path, "r", encoding="utf-8") as f:
                policy = yaml.safe_load(f)
                for dev in policy.get("inventory", {}).get("approved_devices", []):
                    self.approved_map[dev["ip"]] = dev

        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                protocols TEXT,
                inferred_role TEXT,
                approved INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                packet_count INTEGER DEFAULT 1,
                notes TEXT
            )
        """)
        self.conn.commit()

        # Load into RAM cache
        cursor.execute("SELECT ip, mac, hostname, protocols, inferred_role, approved, first_seen, last_seen, packet_count FROM devices")
        for row in cursor.fetchall():
            self._cache[row[0]] = {
                "ip": row[0],
                "mac": row[1],
                "hostname": row[2],
                "protocols": set(row[3].split(",")) if row[3] else set(),
                "inferred_role": row[4],
                "approved": row[5],
                "first_seen": row[6],
                "last_seen": row[7],
                "packet_count": row[8]
            }

    def update_from_event(self, event: dict) -> tuple[Optional[dict], bool]:
        """Process event using in-memory cache and sync to SQLite."""
        now = event.get("time") or iso_utc_now()
        src_ip = event["src_ip"]
        src_mac = event.get("src_mac", "00:00:00:00:00:00")
        dst_ip = event.get("dst_ip")
        dst_mac = event.get("dst_mac", "00:00:00:00:00:00")
        protocol = event.get("protocol", "UNKNOWN")
        func = event.get("function", "")
        addr = event.get("address")

        alert_to_raise = None
        new_device_found = False

        with self._lock:
            # 1. Check Source IP in RAM cache
            if src_ip not in self._cache:
                new_device_found = True
                is_approved = 1 if src_ip in self.approved_map else 0
                initial_role = self._infer_initial_role(src_ip, protocol, func, addr, is_client=True)
                protos_set = {protocol}

                self._cache[src_ip] = {
                    "ip": src_ip,
                    "mac": src_mac,
                    "hostname": self.approved_map.get(src_ip, {}).get("name", "unknown"),
                    "protocols": protos_set,
                    "inferred_role": initial_role,
                    "approved": is_approved,
                    "first_seen": now,
                    "last_seen": now,
                    "packet_count": 1
                }

                # Direct write to SQLite for new device
                self.conn.execute("""
                    INSERT OR REPLACE INTO devices (ip, mac, hostname, protocols, inferred_role, approved, first_seen, last_seen, packet_count, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """, (src_ip, src_mac, self._cache[src_ip]["hostname"], protocol, initial_role, is_approved, now, now, "Discovered passively"))
                self.conn.commit()

                # If not approved, trigger S1 Alert
                if is_approved == 0:
                    alert_to_raise = {
                        "time": now,
                        "severity": "high",
                        "scenario": "S1_rogue_device",
                        "device": src_ip,
                        "source": src_ip,
                        "reason": f"New device {src_ip} (MAC {src_mac}) appeared on the control network and has not been approved",
                        "attack_technique": "T0886",
                        "evidence": [f"inventory_event:{event.get('raw_summary', 'packet_seen')}"]
                    }
            else:
                entry = self._cache[src_ip]
                entry["packet_count"] += 1
                entry["last_seen"] = now
                if src_mac != "00:00:00:00:00:00" and entry["mac"] == "00:00:00:00:00:00":
                    entry["mac"] = src_mac
                entry["protocols"].add(protocol)
                entry["inferred_role"] = self._evolve_role(entry["inferred_role"], src_ip, protocol, func, addr, is_client=True)

                self._uncommitted_count += 1
                if self._uncommitted_count >= 500:
                    self._flush_cache_to_db()

            # 2. Check Destination IP in RAM cache
            if dst_ip and dst_ip not in ("255.255.255.255", "0.0.0.0"):
                if dst_ip not in self._cache:
                    is_app = 1 if dst_ip in self.approved_map else 0
                    dst_role = self._infer_initial_role(dst_ip, protocol, func, addr, is_client=False)
                    self._cache[dst_ip] = {
                        "ip": dst_ip,
                        "mac": dst_mac,
                        "hostname": self.approved_map.get(dst_ip, {}).get("name", "unknown"),
                        "protocols": {protocol},
                        "inferred_role": dst_role,
                        "approved": is_app,
                        "first_seen": now,
                        "last_seen": now,
                        "packet_count": 1
                    }
                    self.conn.execute("""
                        INSERT OR REPLACE INTO devices (ip, mac, hostname, protocols, inferred_role, approved, first_seen, last_seen, packet_count, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """, (dst_ip, dst_mac, self._cache[dst_ip]["hostname"], protocol, dst_role, is_app, now, now, "Target of observed session"))
                    self.conn.commit()
                else:
                    d_entry = self._cache[dst_ip]
                    d_entry["packet_count"] += 1
                    d_entry["last_seen"] = now
                    d_entry["inferred_role"] = self._evolve_role(d_entry["inferred_role"], dst_ip, protocol, func, addr, is_client=False)

        if alert_to_raise and self.on_new_device_alert:
            self.on_new_device_alert(alert_to_raise)

        return alert_to_raise, new_device_found

    def _flush_cache_to_db(self):
        for ip, e in self._cache.items():
            self.conn.execute("""
                UPDATE devices
                SET mac = ?, protocols = ?, inferred_role = ?, last_seen = ?, packet_count = ?
                WHERE ip = ?
            """, (e["mac"], ",".join(sorted(e["protocols"])), e["inferred_role"], e["last_seen"], e["packet_count"], ip))
        self.conn.commit()
        self._uncommitted_count = 0

    def _infer_initial_role(self, ip: str, protocol: str, func: str, addr: Optional[int], is_client: bool) -> str:
        if ip in self.approved_map:
            return self.approved_map[ip].get("role", "Field_Device")
        if is_client:
            if "WRITE" in func and addr == 101:
                return "PPC"
            elif "READ" in func:
                return "SCADA"
            elif "IEC104" in protocol:
                return "Grid_Master"
            elif protocol in ("ARP", "ICMP"):
                return "Scanning_Host"
            return "Client_Host"
        else:
            if protocol == "MODBUS_TCP":
                return "Inverter" if ip in ("10.10.1.11", "10.10.1.12", "10.10.1.13") else "Modbus_Server"
            elif protocol == "IEC_104":
                return "IEC104_Outstation"
            return "Server_Host"

    def _evolve_role(self, current_role: str, ip: str, protocol: str, func: str, addr: Optional[int], is_client: bool) -> str:
        if current_role in ("PPC", "SCADA", "Inverter", "PLC", "IEC104_Outstation", "Grid_Master", "Vendor_Gateway"):
            return current_role
        if is_client:
            if "WRITE" in func and addr == 101:
                return "PPC"
            elif "READ" in func:
                return "SCADA"
            elif "IEC104" in protocol:
                return "Grid_Master"
        return current_role

    def get_all_devices(self) -> list[dict]:
        with self._lock:
            self._flush_cache_to_db()
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip, mac, hostname, protocols, inferred_role, approved, first_seen, last_seen, packet_count, notes FROM devices ORDER BY approved DESC, ip ASC")
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, r)) for r in cursor.fetchall()]

    def get_device(self, ip: str) -> Optional[dict]:
        with self._lock:
            if ip in self._cache:
                e = self._cache[ip]
                return {
                    "ip": e["ip"],
                    "mac": e["mac"],
                    "hostname": e["hostname"],
                    "protocols": ",".join(sorted(e["protocols"])),
                    "inferred_role": e["inferred_role"],
                    "approved": e["approved"],
                    "first_seen": e["first_seen"],
                    "last_seen": e["last_seen"],
                    "packet_count": e["packet_count"]
                }
            return None

    def close(self):
        with self._lock:
            self._flush_cache_to_db()
            self.conn.close()
