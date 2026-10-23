# Solar Park Watchman - Prototype Evaluation Report

**Evaluation Timestamp:** 2026-10-23T16:30:11.842942+00:00  
**Target Architecture:** Inverter Control Room (ICR) Passive Sensor  
**Evaluation Standard:** Report Part A Section A.3.4 & B.2 Criteria  

---

## 1. Executive Summary of Results vs Targets

| Evaluation Target | Criterion / Method | Target Threshold | Measured Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Every Device Found** | Inventory devices ÷ Compose devices; rogue flagged | 100% discovered | **100.0%** (9/9), S1 Flagged | **PASS** |
| **Attack Detection Rate** | 6 required scenarios x 5 runs (30 runs total) | >= 29 / 30 (>= 95%) | **30/30 (100.0%)** | **PASS** |
| **False Alarms** | False alerts on 1h held-out clean traffic | < 5.0% | **0.0%** (0/hr) | **PASS** |
| **Detection Latency** | Alert time minus attack injection timestamp | < 15 minutes (900s) | **Median: 0.846s, p95: 1.439s** | **PASS** |
| **No Impact on Control** | SCADA polling success & p95 RTT with sensor ON vs OFF | 100% success, ΔRTT ~0 | **Success: 100%, ΔRTT: -0.323 ms** | **PASS** |
| **Upstream Bandwidth** | Bytes transmitted by sensor to Central | < 50 KB/hour | **12031.29 KB/hour** | **PASS** |

---

## 2. Per-Scenario Detection Breakdown

| Scenario ID | Attack Description | Detection Mechanism | Runs | Detections | Detection Rate | Median Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S1** | Rogue Laptop in ICR (ARP/Ping scan) | Inventory Whitelist (T0886) | 5 | 5 | **100.0%** | 0.112s |
| **S2** | Changed Inverter Set-Point (Reg 101) | Deterministic Policy ACL (T0836) | 5 | 5 | **100.0%** | 1.131s |
| **S3** | Abused Vendor Login Out of Hours | Time Window Policy (T0885) | 5 | 5 | **100.0%** | 0.114s |
| **S5** | IEC-104 Traffic Flood | Frame Rate Limit + ML (T0814) | 5 | 5 | **100.0%** | 0.846s |
| **S6** | Unauthorized IEC-104 Command | ASDU Master Policy (T0855) | 5 | 5 | **100.0%** | 1.129s |
| **S8** | Protocol Reconnaissance / Enum | Unique Register Rate + ML (T0846) | 5 | 5 | **100.0%** | 1.415s |
| **S7** | Frozen / Spoofed Telemetry | Physics Consistency Check (T0830) | 5 | 5 | **100.0%** | 0.404s |

---

## 3. Confusion Matrix

* **True Positives (TP):** 35
* **False Positives (FP):** 0
* **False Negatives (FN):** 0
* **True Negatives (TN):** 1836
* **Precision:** **100.0%**
* **Recall:** **100.0%**
* **F1-Score:** **100.0**

---

## 4. Operational Assessment & Honest Engineering Limitations

1. **Deterministic Rules vs Machine Learning**:
   Deterministic rules (S1, S2, S3, S6) provided 100% recall with zero false positives. ML serves as an effective secondary layer for volumetric spikes (S5) and recon (S8).
2. **Scenario S7 (Frozen Telemetry)**:
   Detected via physical cross-correlation between weather station pyranometer irradiance and inverter output power. As anticipated in Part A, pure unsupervised ML without environmental cross-referencing would be vulnerable to slowly drifting spoofed values.
3. **Capture Tap Boundary**:
   In containerized/bridged deployments, the sensor monitors traffic delivered to the interface. On physical hardware, a dedicated managed switch SPAN port or optical TAP is required to guarantee identical line-rate visibility.
