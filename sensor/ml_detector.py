"""
Machine Learning Anomaly Detector for Solar Park Watchman Sensor.
Uses Scikit-Learn Isolation Forest trained on clean baseline traffic.
Extracts per-device per-minute feature vectors:
[packet_rate, byte_volume, unique_registers, write_ratio, iec104_rate, power_variance, irradiance_residual].
Enforces physical consistency check for S7 (frozen/spoofed telemetry).
Rules remain primary; ML supplements S5, S7, S8 with confidence scores.
"""
import os
import time
import math
import joblib
import numpy as np
from collections import defaultdict, deque
from typing import Optional, Callable
from sklearn.ensemble import IsolationForest
from sim.common import iso_utc_now

FEATURE_NAMES = [
    "packet_rate",
    "byte_volume",
    "unique_registers",
    "write_ratio",
    "iec104_rate",
    "power_variance",
    "irradiance_residual"
]

class MLAnomalyDetector:
    def __init__(
        self,
        model_path: str = "data/isolation_forest.joblib",
        contamination: float = 0.01,
        random_state: int = 42,
        on_ml_alert_callback: Optional[Callable] = None
    ):
        self.model_path = model_path
        self.contamination = contamination
        self.random_state = random_state
        self.on_ml_alert = on_ml_alert_callback

        self.model: Optional[IsolationForest] = None
        self._load_or_init_model()

        # Rolling 60s window for feature aggregation per device IP
        # device_ip -> deque of event records
        self.device_windows = defaultdict(deque)

        # Telemetry history for S7 frozen power vs irradiance check
        # inverter_ip -> deque of (timestamp, power_kw, irradiance_w_m2)
        self.telemetry_history = defaultdict(deque)
        self.latest_plc_irradiance: float = 800.0

    def _load_or_init_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception:
                self._train_default_baseline()
        else:
            self._train_default_baseline()

    def _train_default_baseline(self):
        """Train baseline model with synthetic normal OT traffic distributions."""
        np.random.seed(self.random_state)
        # Normal traffic features:
        # packet_rate: 15-30/min
        # byte_volume: 800-2500 bytes/min
        # unique_registers: 4-15
        # write_ratio: 0.01-0.08
        # iec104_rate: 2-10/min
        # power_variance: 10-250
        # irradiance_residual: 5-30
        n_samples = 2000
        normal_data = np.zeros((n_samples, len(FEATURE_NAMES)))
        normal_data[:, 0] = np.random.normal(24.0, 4.0, n_samples)      # packet_rate
        normal_data[:, 1] = np.random.normal(1500.0, 300.0, n_samples) # byte_volume
        normal_data[:, 2] = np.random.normal(10.0, 2.0, n_samples)     # unique_registers
        normal_data[:, 3] = np.random.uniform(0.0, 0.08, n_samples)    # write_ratio
        normal_data[:, 4] = np.random.normal(5.0, 1.5, n_samples)      # iec104_rate
        normal_data[:, 5] = np.random.normal(50.0, 15.0, n_samples)    # power_variance
        normal_data[:, 6] = np.random.normal(15.0, 5.0, n_samples)     # irradiance_residual

        # Clip bounds
        normal_data[:, 0] = np.clip(normal_data[:, 0], 5, 45)
        normal_data[:, 2] = np.clip(normal_data[:, 2], 1, 20)
        normal_data[:, 3] = np.clip(normal_data[:, 3], 0.0, 0.15)
        normal_data[:, 4] = np.clip(normal_data[:, 4], 0, 15)

        clf = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state
        )
        clf.fit(normal_data)
        self.model = clf
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def train_on_features(self, feature_matrix: np.ndarray):
        """Fit model on genuine baseline features generated from simulation."""
        clf = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state
        )
        clf.fit(feature_matrix)
        self.model = clf
        joblib.dump(self.model, self.model_path)

    def extract_features(self, device_ip: str, now_epoch: float) -> np.ndarray:
        """Extract 7-dimensional feature vector from 60-second window."""
        q = self.device_windows[device_ip]
        while q and q[0]["epoch"] < now_epoch - 60.0:
            q.popleft()

        packet_rate = float(len(q))
        byte_volume = float(sum(item.get("bytes", 64) for item in q))
        regs = {item["address"] for item in q if item.get("address") is not None}
        unique_registers = float(len(regs))
        writes = sum(1 for item in q if "WRITE" in item.get("func", ""))
        write_ratio = float(writes / len(q)) if q else 0.0
        iec104_rate = float(sum(1 for item in q if item.get("proto") == "IEC_104"))

        # Inverter physical features
        th = self.telemetry_history[device_ip]
        while th and th[0][0] < now_epoch - 300.0:
            th.popleft()

        powers = [item[1] for item in th]
        power_variance = float(np.var(powers)) if len(powers) >= 3 else 50.0

        irrs = [item[2] for item in th]
        if powers and irrs:
            # Expected power = (Irr / 1000) * 1000 kW * 0.98
            expected_power = (irrs[-1] / 1000.0) * 980.0
            irradiance_residual = float(abs(powers[-1] - expected_power))
        else:
            irradiance_residual = 15.0

        vec = np.array([
            packet_rate,
            byte_volume,
            unique_registers,
            write_ratio,
            iec104_rate,
            power_variance,
            irradiance_residual
        ]).reshape(1, -1)

        return vec

    def ingest_event(self, event: dict) -> list[dict]:
        """
        Ingest event, update feature windows, evaluate ML model,
        and run S7 physical consistency check.
        """
        alerts = []
        epoch = event.get("timestamp_epoch", time.time())
        src_ip = event["src_ip"]
        dst_ip = event.get("dst_ip", "")
        proto = event.get("protocol", "")
        func = event.get("function", "")
        addr = event.get("address")
        val = event.get("value")
        now_iso = event.get("time") or iso_utc_now()

        # Track PLC irradiance
        if src_ip == "10.10.1.20" and addr == 201 and val is not None:
            self.latest_plc_irradiance = float(val)

        # Track inverter power
        if dst_ip in ("10.10.1.11", "10.10.1.12", "10.10.1.13") and addr == 102 and val is not None:
            power_val = float(val if isinstance(val, (int, float)) else val[0])
            self.telemetry_history[dst_ip].append((epoch, power_val, self.latest_plc_irradiance))

        # Add to window
        self.device_windows[src_ip].append({
            "epoch": epoch,
            "proto": proto,
            "func": func,
            "address": addr,
            "bytes": 64
        })

        # --- S7: Frozen / Spoofed Telemetry Physical Consistency Check ---
        for inv_ip in ("10.10.1.11", "10.10.1.12", "10.10.1.13"):
            th = self.telemetry_history[inv_ip]
            if len(th) >= 10:
                recent_powers = [item[1] for item in th]
                recent_irrs = [item[2] for item in th]
                # Power variance is near 0 while irradiance varied significantly
                power_spread = max(recent_powers) - min(recent_powers)
                irr_spread = max(recent_irrs) - min(recent_irrs)

                if power_spread <= 0.001 and irr_spread >= 40.0:
                    dev_name = "inverter-1" if inv_ip == "10.10.1.11" else ("inverter-2" if inv_ip == "10.10.1.12" else "inverter-3")
                    alert = {
                        "time": now_iso,
                        "severity": "medium",
                        "scenario": "S7_frozen_telemetry",
                        "device": dev_name,
                        "source": inv_ip,
                        "reason": f"{dev_name} reported identical power for 20 minutes while irradiance varied (power spread={power_spread:.1f} kW, irradiance spread={irr_spread:.1f} W/m^2)",
                        "attack_technique": "T0830",  # MITRE ATT&CK for ICS: Spoof Reporting Message
                        "confidence": 0.88,
                        "evidence": [f"telemetry_variance:power_std=0.0_while_irr_delta={irr_spread:.1f}"]
                    }
                    alerts.append(alert)
                    th.clear()  # reset after alerting

        # --- ML Evaluation on Feature Vector ---
        if self.model:
            feat = self.extract_features(src_ip, epoch)
            pred = self.model.predict(feat)[0]  # -1 is anomaly, 1 is normal
            score = self.model.decision_function(feat)[0]  # lower is more abnormal

            if pred == -1:
                confidence = round(min(0.99, max(0.50, float(-score * 2.5 + 0.5))), 2)
                p_rate = feat[0, 0]
                u_regs = feat[0, 2]
                iec_r = feat[0, 4]

                ml_scenario = None
                reason = None
                technique = None

                if iec_r > 30:
                    ml_scenario = "S5_iec104_flood"
                    reason = f"ML detector: abnormal IEC-104 frame rate ({int(iec_r)}/min) from {src_ip} deviates from baseline"
                    technique = "T0814"
                elif u_regs > 35:
                    ml_scenario = "S8_protocol_recon"
                    reason = f"ML detector: anomalous register access pattern ({int(u_regs)} distinct registers) from {src_ip}"
                    technique = "T0846"
                elif p_rate > 50:
                    ml_scenario = "S5_traffic_flood"
                    reason = f"ML detector: volumetric anomaly ({int(p_rate)} packets/min) from {src_ip}"
                    technique = "T0814"

                if ml_scenario:
                    alert = {
                        "time": now_iso,
                        "severity": "medium",
                        "scenario": ml_scenario,
                        "device": src_ip,
                        "source": src_ip,
                        "reason": reason,
                        "attack_technique": technique,
                        "confidence": confidence,
                        "evidence": [f"isolation_forest:anomaly_score={score:.3f}_features={feat.tolist()[0]}"]
                    }
                    alerts.append(alert)

        for a in alerts:
            if self.on_ml_alert:
                self.on_ml_alert(a)

        return alerts
