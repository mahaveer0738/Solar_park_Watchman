"""
Central Alert Collector and 5-Minute Summary Service (B7 Stretch & Central Monitoring).
Runs HTTP server on port 8000 collecting plain-language alerts and summary telemetry.
Tracks upstream bandwidth consumption (Bytes and KB/hour).
"""
import json
import time
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from typing import Optional
from sim.common import PORT_CENTRAL

class CentralStorage:
    def __init__(self, log_path: str = "runs/central_alerts.jsonl"):
        self.log_path = log_path
        self.alerts = []
        self.summaries = []
        self.total_bytes_received = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)

    def record_alert(self, alert_data: dict, raw_length: int):
        with self._lock:
            self.alerts.append(alert_data)
            self.total_bytes_received += raw_length
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")

    def record_summary(self, summary_data: dict, raw_length: int):
        with self._lock:
            self.summaries.append(summary_data)
            self.total_bytes_received += raw_length

    def get_metrics(self) -> dict:
        with self._lock:
            elapsed_hours = max((time.time() - self.start_time) / 3600.0, 0.0001)
            kb_total = self.total_bytes_received / 1024.0
            kb_per_hour = kb_total / elapsed_hours
            return {
                "total_alerts": len(self.alerts),
                "total_summaries": len(self.summaries),
                "total_bytes_received": self.total_bytes_received,
                "total_kb_received": round(kb_total, 2),
                "kb_per_hour": round(kb_per_hour, 2),
                "elapsed_seconds": round(time.time() - self.start_time, 1)
            }

storage = CentralStorage()

class CentralRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logger

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "Solar Park Watchman Central"})
        elif parsed.path == "/api/metrics":
            self._send_json(200, storage.get_metrics())
        elif parsed.path == "/api/alerts":
            with storage._lock:
                self._send_json(200, {"alerts": storage.alerts})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        if parsed.path == "/api/alerts":
            storage.record_alert(payload, len(raw_body))
            self._send_json(201, {"status": "alert_received", "id": len(storage.alerts)})
        elif parsed.path == "/api/summary":
            storage.record_summary(payload, len(raw_body))
            self._send_json(200, {"status": "summary_received"})
        else:
            self._send_json(404, {"error": "Not Found"})


class CentralServer:
    def __init__(self, host: str = "0.0.0.0", port: int = PORT_CENTRAL):
        self.host = host
        self.port = port
        self.httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self.httpd = HTTPServer((self.host, self.port), CentralRequestHandler)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="CentralServer-Thread")
        self._thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

if __name__ == "__main__":
    server = CentralServer()
    server.start()
    print(f"Central Collector running on port {server.port}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
