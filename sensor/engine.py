"""
Master Watchman Sensor Engine.
Integrates:
- Passive Capture (Rx only)
- Event Normaliser
- Device Inventory (SQLite)
- Deterministic Rule Engine (policy.yaml)
- ML Anomaly Detector (Isolation Forest & Physics Consistency)
- Plain-Language Alert Builder (alerts.jsonl)
- Store-and-Forward Client
"""
import os
import time
import logging
from typing import Optional
from sensor.capture import PassiveSensorCapture
from sensor.normaliser import EventNormaliser
from sensor.inventory import DeviceInventory
from sensor.rule_engine import RuleEngine
from sensor.ml_detector import MLAnomalyDetector
from sensor.alert_builder import AlertBuilder
from sensor.forwarder import StoreAndForwardClient

logger = logging.getLogger("sensor_engine")

class WatchmanSensorEngine:
    def __init__(
        self,
        db_path: str = "data/inventory.db",
        policy_path: str = "config/policy.yaml",
        alerts_path: str = "runs/alerts.jsonl",
        ml_model_path: str = "data/isolation_forest.joblib",
        forward_queue_path: str = "data/forward_queue.jsonl",
        central_endpoint: str = "http://127.0.0.1:8000/api/alerts",
        central_summary_endpoint: str = "http://127.0.0.1:8000/api/summary"
    ):
        self.alerts_generated = []

        # 1. Alert Builder
        self.alert_builder = AlertBuilder(
            alerts_path=alerts_path,
            on_alert_published=self._on_alert_generated
        )

        # 2. Store-and-Forward Client
        self.forwarder = StoreAndForwardClient(
            endpoint=central_endpoint,
            summary_endpoint=central_summary_endpoint,
            queue_path=forward_queue_path
        )

        # 3. Device Inventory
        self.inventory = DeviceInventory(
            db_path=db_path,
            policy_path=policy_path,
            on_new_device_alert=self._handle_inventory_alert
        )

        # 4. Deterministic Rule Engine
        self.rule_engine = RuleEngine(
            policy_path=policy_path,
            on_alert_callback=self._handle_rule_alert
        )

        # 5. ML Detector
        self.ml_detector = MLAnomalyDetector(
            model_path=ml_model_path,
            on_ml_alert_callback=self._handle_ml_alert
        )

        # 6. Passive Capture Engine
        self.capture = PassiveSensorCapture(
            on_event_callback=self.process_raw_event
        )

    def _on_alert_generated(self, alert: dict):
        self.alerts_generated.append(alert)
        self.forwarder.send_alert(alert)

    def _handle_inventory_alert(self, alert_data: dict):
        self.alert_builder.build_and_publish(
            severity=alert_data["severity"],
            scenario=alert_data["scenario"],
            device=alert_data["device"],
            source=alert_data["source"],
            reason=alert_data["reason"],
            attack_technique=alert_data["attack_technique"],
            evidence=alert_data["evidence"],
            alert_time=alert_data.get("time")
        )

    def _handle_rule_alert(self, alert_data: dict):
        self.alert_builder.build_and_publish(
            severity=alert_data["severity"],
            scenario=alert_data["scenario"],
            device=alert_data["device"],
            source=alert_data["source"],
            reason=alert_data["reason"],
            attack_technique=alert_data["attack_technique"],
            evidence=alert_data["evidence"],
            alert_time=alert_data.get("time")
        )

    def _handle_ml_alert(self, alert_data: dict):
        self.alert_builder.build_and_publish(
            severity=alert_data["severity"],
            scenario=alert_data["scenario"],
            device=alert_data["device"],
            source=alert_data["source"],
            reason=alert_data["reason"],
            attack_technique=alert_data["attack_technique"],
            evidence=alert_data["evidence"],
            alert_time=alert_data.get("time"),
            confidence=alert_data.get("confidence")
        )

    def process_raw_event(self, event: dict, current_time_override=None):
        """Pass event through all sensor processing stages."""
        # 1. Update inventory
        self.inventory.update_from_event(event)

        # 2. Evaluate deterministic rules (primary)
        self.rule_engine.evaluate_event(event, current_time_override=current_time_override)

        # 3. Evaluate ML & physical consistency (secondary)
        self.ml_detector.ingest_event(event)

    def start(self):
        """Start background capture and forwarding."""
        self.forwarder.start()
        self.capture.start_live()

    def stop(self):
        """Stop background capture and forwarding."""
        self.capture.stop()
        self.forwarder.stop()

if __name__ == "__main__":
    engine = WatchmanSensorEngine()
    print("Watchman Sensor Engine initialized successfully.")
