"""
Common scenario runner utilities and attack execution logging.
Logs each attack run to runs/attack_log.jsonl.
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from sim.common import iso_utc_now

ATTACK_LOG_FILE = "runs/attack_log.jsonl"

def get_standalone_pipeline():
    """Return a WatchmanSensorEngine writing directly to runs/alerts.jsonl."""
    from sensor.engine import WatchmanSensorEngine
    return WatchmanSensorEngine(
        db_path="data/inventory.db",
        alerts_path="runs/alerts.jsonl"
    )

def log_attack_run(
    scenario: str,
    source_ip: str,
    target_ip: str,
    description: str,
    start_time: str,
    end_time: str,
    run_id: Optional[str] = None
) -> dict:
    """Record attack execution to runs/attack_log.jsonl."""
    os.makedirs(os.path.dirname(ATTACK_LOG_FILE) or ".", exist_ok=True)
    record = {
        "run_id": run_id or f"{scenario}-{uuid.uuid4().hex[:8]}",
        "scenario": scenario,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "start_time": start_time,
        "end_time": end_time,
        "description": description
    }
    with open(ATTACK_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record
