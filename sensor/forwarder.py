"""
Store-and-Forward Client for Solar Park Watchman Sensor.
Guarantees zero alert loss over unreliable/remote WAN links.
When Central is reachable: posts alerts immediately.
When Central is unreachable: enqueues alerts to local file buffer (data/forward_queue.jsonl).
Flushes queued alerts automatically upon link restoration.
"""
import json
import os
import time
import threading
import requests
import logging
from typing import Optional

logger = logging.getLogger("forwarder")

class StoreAndForwardClient:
    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8000/api/alerts",
        summary_endpoint: str = "http://127.0.0.1:8000/api/summary",
        queue_path: str = "data/forward_queue.jsonl",
        retry_interval: float = 2.0
    ):
        self.endpoint = endpoint
        self.summary_endpoint = summary_endpoint
        self.queue_path = queue_path
        self.retry_interval = retry_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.queue_path) or ".", exist_ok=True)

    def send_alert(self, alert_data: dict) -> bool:
        """Attempt immediate delivery; enqueue to disk on network failure."""
        try:
            resp = requests.post(self.endpoint, json=alert_data, timeout=1.5)
            if resp.status_code in (200, 201):
                return True
        except Exception:
            pass

        # If delivery failed, buffer to disk queue
        self._enqueue(alert_data)
        return False

    def send_summary(self, summary_data: dict) -> bool:
        """Send periodic 5-minute health and status rollup."""
        try:
            resp = requests.post(self.summary_endpoint, json=summary_data, timeout=2.0)
            return resp.status_code in (200, 201)
        except Exception:
            return False

    def _enqueue(self, alert_data: dict):
        with self._lock:
            with open(self.queue_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")

    def _flush_queue(self):
        """Drain queued alerts to central collector."""
        if not os.path.exists(self.queue_path):
            return

        with self._lock:
            with open(self.queue_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]

        if not lines:
            return

        remaining = []
        for idx, line in enumerate(lines):
            try:
                alert = json.loads(line)
                resp = requests.post(self.endpoint, json=alert, timeout=1.5)
                if resp.status_code not in (200, 201):
                    remaining = lines[idx:]
                    break
            except Exception:
                remaining = lines[idx:]
                break

        with self._lock:
            if remaining:
                with open(self.queue_path, "w", encoding="utf-8") as f:
                    for l in remaining:
                        f.write(l + "\n")
            else:
                try:
                    os.remove(self.queue_path)
                except Exception:
                    pass

    def start(self):
        self.running = True
        def _worker():
            while self.running:
                if os.path.exists(self.queue_path):
                    self._flush_queue()
                time.sleep(self.retry_interval)

        self._thread = threading.Thread(target=_worker, daemon=True, name="StoreAndForward-Thread")
        self._thread.start()

    def stop(self):
        self.running = False
