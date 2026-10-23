# Solar Park Watchman - Evidence Capture Checklist

This checklist documents the exact evidence items, Wireshark filters, and console screens required for the final submission and demo video verification, based on `docs/REPORT_PART_A.md` Section B.4 and Addendum.

> **Integrity Rule:** All screenshots and packet captures must be taken from real executions in this local lab. Never fabricate packet evidence, use diagrams as packet captures, or invent numbers. Redact sensitive host data where applicable.

---

## 1. Packet Capture Evidence (Wireshark)

| Evidence Item | Suggested Filename | Protocol & Filter Expression | What It Must Show | Lab Execution Command |
| :--- | :--- | :--- | :--- | :--- |
| **Modbus Read** | `evidence_modbus_read.png` | `modbus.func_code == 3 && ip.addr == 10.10.1.10` | SCADA polling Inverter-1 or PLC; request and response expanded; Function Code 03, Unit ID 1, register address 101, length 5. | `python -m pytest tests/test_simulation.py` |
| **Modbus Write** | `evidence_modbus_write.png` | `modbus.func_code == 6 && ip.src == 10.10.1.99` | S2 Attack: Attacker (10.10.1.99) sending Function Code 06 (Write Single Register) to Inverter-2 (10.10.1.12), Register 101, Value 0. | `python scenarios/s2_unauthorized_write.py` |
| **IEC-104 Command** | `evidence_iec104_command.png` | `104asdu.typeid == 45 \|\| 104asdu.typeid == 46` | S6 Attack: Attacker sending Type 45 Single Command to Outstation (10.10.1.40), Breaker IOA 1000, Cause of Transmission (COT) 6. | `python scenarios/s6_unauthorized_command.py` |
| **IEC-104 Telemetry** | `evidence_iec104_telemetry.png` | `104asdu.typeid == 13 && ip.src == 10.10.1.40` | Legitimate Outstation sending periodic spontaneous telemetry (M_ME_NC_1 Short Float) to Grid Master (10.10.2.10). | `python make.py up` |

---

## 2. Sensor Prototype Evidence (Streamlit Dashboard & Terminal)

| Evidence Item | Suggested Filename | View / Source | What It Must Show | Lab Execution Command |
| :--- | :--- | :--- | :--- | :--- |
| **Device Inventory** | `evidence_device_inventory.png` | Dashboard Tab 1 (`data/inventory.db`) | Complete asset table showing 9 approved ICR devices with behaviorally inferred roles (`SCADA`, `PPC`, `Inverter`, `PLC`, `IEC104_Outstation`) and rogue device `10.10.1.99` highlighted with red `UNAPPROVED` badge. | `streamlit run dashboard/app.py` |
| **Plain-Language Alerts** | `evidence_alerts_console.png` | Dashboard Tab 2 (`runs/alerts.jsonl`) | Plain-language alerts with MITRE ATT&CK for ICS IDs (`T0886`, `T0836`, `T0885`, `T0814`, `T0855`, `T0830`, `T0846`), severity badges, and log line references. | `streamlit run dashboard/app.py` |
| **Detection Timeline** | `evidence_detection_timeline.png` | Dashboard Tab 3 (`runs/attack_log.jsonl` vs `runs/alerts.jsonl`) | Side-by-side matching of attack injection start time vs Watchman alert timestamp demonstrating sub-second detection latency. | `streamlit run dashboard/app.py` |
| **Evaluation Metrics** | `evidence_test_results.png` | Dashboard Tab 4 (`results/summary_report.md`) | Full 30-run test results table showing 100% detection rate (30/30), 0.0% false alarm rate, Confusion Matrix, and SCADA RTT overhead (sensor OFF vs ON). | `python make.py evaluate` |

---

## 3. Terminal Execution Logs & Artifact Files

The following machine-readable log files are preserved in the workspace for independent auditor inspection:
* `results/confusion_matrix.json` (TP, FP, FN, TN, Precision, Recall, F1)
* `results/per_scenario_detections.csv` (Per-scenario detection counts and median latency)
* `results/detection_latency.json` (Median and p95 latency percentiles)
* `results/false_alerts.json` (Held-out normal false positive verification)
* `results/inventory_coverage.json` (Asset discovery verification records)
* `results/bandwidth_upstream.json` (KB/hour transmitted upstream)
* `results/latency_overhead.json` (SCADA polling RTT with sensor off vs on)
* `runs/attack_log.jsonl` (Timestamped attack execution audit trail)
* `runs/alerts.jsonl` (Canonical plain-language alert stream)
* `build_manifest.txt` (Pinned package versions, configuration hashes, model seed)
