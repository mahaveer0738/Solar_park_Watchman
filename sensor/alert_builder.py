"""
Alert Builder and Formatter for Solar Park Watchman Sensor.
Enforces the exact required JSON Lines schema:
{
  "time": "...",
  "severity": "...",
  "scenario": "...",
  "device": "...",
  "source": "...",
  "reason": "...",
  "attack_technique": "...",
  "evidence": [...]
}
Appends to runs/alerts.jsonl and forwards downstream.
"""
import json
import os
import threading
from typing import Optional, Callable
from sim.common import iso_utc_now

REQUIRED_FIELDS = [
    "time", "severity", "scenario", "device",
    "source", "reason", "attack_technique", "evidence"
]

class AlertBuilder:
    def __init__(self, alerts_path: str = "runs/alerts.jsonl", on_alert_published: Optional[Callable] = None):
        self.alerts_path = alerts_path
        self.on_alert_published = on_alert_published
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.alerts_path) or ".", exist_ok=True)

    def build_and_publish(
        self,
        severity: str,
        scenario: str,
        device: str,
        source: str,
        reason: str,
        attack_technique: str,
        evidence: list[str],
        alert_time: Optional[str] = None,
        confidence: Optional[float] = None
    ) -> dict:
        """Construct, validate, record, and publish a standardized security alert."""
        record = {
            "time": alert_time or iso_utc_now(),
            "severity": severity,
            "scenario": scenario,
            "device": device,
            "source": source,
            "reason": reason,
            "attack_technique": attack_technique,
            "evidence": evidence or []
        }
        if confidence is not None:
            record["confidence"] = confidence

        # Validate required fields
        for field in REQUIRED_FIELDS:
            if field not in record:
                raise ValueError(f"Alert missing required field: {field}")

        line = json.dumps(record)
        with self._lock:
            with open(self.alerts_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

        if self.on_alert_published:
            self.on_alert_published(record)

        return record

    def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        """Read recent alerts from JSON Lines log."""
        if not os.path.exists(self.alerts_path):
            return []
        alerts = []
        with self._lock:
            with open(self.alerts_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except Exception:
                            pass
        return alerts[-limit:]
