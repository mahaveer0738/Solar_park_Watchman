# Solar Park Watchman: Inverter Control Room (ICR) Passive Network Sensor

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/pytest-20%20passed-brightgreen.svg)]()
[![Evaluation](https://img.shields.io/badge/attack%20detection-30%2F30%20(100%25)-success.svg)]()
[![Compliance](https://img.shields.io/badge/CEA%202026-Ready-green.svg)]()
[![Repository](https://img.shields.io/badge/GitHub-mahaveer0738%2FSolar__park__Watchman-181717.svg?logo=github)](https://github.com/mahaveer0738/Solar_park_Watchman)

> **Part B Engineering Prototype · Cognton AI Full-Time Hiring Exercise**  
> Baseline Reference Design: [`docs/REPORT_PART_A.md`](docs/REPORT_PART_A.md) · Specification: [`docs/ASSIGNMENT_SPEC.md`](docs/ASSIGNMENT_SPEC.md) · GitHub: [mahaveer0738/Solar_park_Watchman](https://github.com/mahaveer0738/Solar_park_Watchman)

---

## 1. System Architecture

The **Solar Park Watchman** is a passive edge network sensor designed for Inverter Control Rooms (ICR) in utility-scale solar parks (e.g. western Gujarat). It passively monitors Modbus TCP and IEC 60870-5-104 control traffic, dynamically discovers and classifies assets into an SQLite inventory, enforces deterministic security policies, runs unsupervised anomaly detection on per-device feature vectors, and streams structured plain-language alerts to a central dashboard.

```mermaid
graph TD
    subgraph Grid Network [10.10.2.0/24]
        GC[Grid Control Centre Master<br/>10.10.2.10]
    end

    subgraph ICR Control Network [10.10.1.0/24]
        SCADA[Plant SCADA Poller<br/>10.10.1.10]
        PPC[Plant Power Controller<br/>10.10.1.30]
        VGW[Vendor Support Gateway<br/>10.10.1.50]
        PLC[Plant Master PLC<br/>10.10.1.20]
        WTH[Weather Sensor Feed<br/>10.10.1.25]
        INV1[Solar Inverter 1<br/>10.10.1.11]
        INV2[Solar Inverter 2<br/>10.10.1.12]
        INV3[Solar Inverter 3<br/>10.10.1.13]
        RTU[Substation RTU Outstation<br/>10.10.1.40]
        ATK[Adversary Node<br/>10.10.1.99]
    end

    subgraph Monitoring & Central
        SW[(Switch Mirror / TAP)]
        SENSOR[Passive Sensor<br/>Watchman Core]
        CENTRAL[Central Collector<br/>10.10.1.5:8000]
        DASH[Streamlit Dashboard<br/>:8501]
    end

    GC <-->|IEC-104 Telemetry / Commands| RTU
    WTH -->|Irradiance / Temp| PLC
    SCADA -->|Cyclic Modbus Polls 2-5s| INV1 & INV2 & INV3 & PLC
    PPC -->|Authorized Writes Reg 101| INV1 & INV2 & INV3
    VGW -.->|Routine Maint Reads 10:00-16:00| INV1 & PLC
    ATK -.->|Hostile Scenarios S1-S8| ICR Control Network

    ICR Control Network -.->|Promiscuous Copy / SPAN| SW
    SW -->|Passive Rx Only| SENSOR
    SENSOR -->|Store & Forward Alerts| CENTRAL
    CENTRAL --> DASH
```

---

## 2. Quick Start & Execution

All workflows can be executed using `make`, `make.bat` (Windows), or `python make.py`:

```bash
# 1. Start simulated plant devices and background services
make up
# Or on Windows CMD / PowerShell:
# make.bat up  OR  python make.py up

# 2. Run all attack scenarios live
make attacks
# Or: python make.py attacks

# 3. Execute the full 30-run quantitative evaluation suite against B.2 criteria
make evaluate
# Or: python make.py evaluate

# 4. Launch the interactive Streamlit operator console
make demo
# Or: python make.py demo (opens http://localhost:8501)

# 5. Stop all background services
make down
# Or: python make.py down
```

### Running Unit & Integration Tests (pytest)
```bash
python -m pytest tests/ -v
```
All 20 test cases pass with 100% success rate:
* `tests/test_simulation.py`: Modbus servers, physical solar curve, SCADA polling, PPC writes, IEC-104 outstation.
* `tests/test_normaliser.py`: MBAP dissection, IEC-104 APDU/ASDU parsing, event normalization.
* `tests/test_inventory.py`: SQLite asset discovery, behavioral role inference, S1 rogue device alerts.
* `tests/test_rules.py`: Deterministic policy enforcement (S2 setpoint ACLs, S3 vendor windows, S5 floods, S6 commands, S8 recon).
* `tests/test_ml.py`: Scikit-Learn Isolation Forest and S7 physical consistency checker.
* `tests/test_forwarder.py`: JSON Lines schema validation and store-and-forward resilience.

---

## 3. Attack Scenarios & Detection Logic

Every attack script logs its exact start and end timestamps to `runs/attack_log.jsonl`. Plain-language alerts are recorded to `runs/alerts.jsonl`.

| Scenario ID | Attack Description | MITRE ATT&CK for ICS | Detection Mechanism | Plain-Language Alert Reason |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | **Rogue Laptop in ICR**: Adversary plugs unapproved device (`10.10.1.99`) into ICR switch and performs network discovery scan. | **T0886** (Remote System Discovery) | Dynamic SQLite inventory whitelist comparison | `New device 10.10.1.99 (MAC 02:42:0a:0a:01:99) appeared on the control network and has not been approved` |
| **S2** | **Unauthorized Set-Point Write**: Attacker writes 0 kW to Inverter-2 register 101 to curtail power generation. | **T0836** (Modify Parameter) | Deterministic register ACL (`config/policy.yaml`) | `inverter-2 set-point written by 10.10.1.99; only 10.10.1.30 is allowed to write it` |
| **S3** | **Vendor Login Out-of-Hours**: Vendor gateway (`10.10.1.50`) sends a write command at 02:10 outside maintenance hours. | **T0885** (Commonly Used Port / Unauthorized Access) | Time-window policy evaluation (Approved: 10:00–16:00) | `Vendor gateway sent writes at 02:10; its approved window is 10:00 to 16:00` |
| **S5** | **IEC-104 Traffic Flood**: Adversary bursts 50+ frames within 2 seconds to Substation RTU (`10.10.1.40`). | **T0814** (Denial of Service) | Sliding 60-second rate limiter + Isolation Forest | `IEC-104 outstation received 40x its normal packet rate in 60 seconds from 10.10.1.99` |
| **S6** | **Unauthorized IEC-104 Command**: Attacker transmits Type 45 Single Command to trip substation breaker point 1000. | **T0855** (Unauthorized Command Message) | ASDU Master authorization policy | `Control command to breaker point 1000 came from 10.10.1.99; only the grid control centre master 10.10.2.10 may send commands` |
| **S8** | **Protocol Reconnaissance**: Attacker scans unit IDs and reads 60+ registers sequentially across inverters and PLC. | **T0846** (Remote System Discovery) | Unique register threshold (>50/min) + ML | `10.10.1.99 read 60 distinct registers across 4 devices in one minute; normal is 12` |
| **S7** | **Frozen / Spoofed Telemetry**: Inverter-1 reports constant 850 kW while solar pyranometer irradiance rises from 500 to 950 W/m². | **T0830** (Spoof Reporting Message) | Unsupervised ML + Physical cross-correlation consistency check | `inverter-1 reported identical power for 20 minutes while irradiance varied` |

---

## 4. Quantitative Results against B.2 Acceptance Criteria

All numbers below were measured during real test harness execution (`python make.py evaluate`) and are saved in `results/`:

| Acceptance Target (B.2) | Evaluation Method | Target Criteria | Measured Lab Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Every Device Found** | Inventory devices ÷ Compose devices; rogue device flagged | 100% discovered | **100.0%** (9/9 plant assets discovered), Rogue `10.10.1.99` flagged | **PASS** |
| **Attack Detection Rate** | 6 required scenarios x 5 runs (30 runs) + S7 (5 runs) | >= 29 / 30 (>= 95%) | **30 / 30 (100.0%)** on required scenarios; **35 / 35 (100.0%)** total | **PASS** |
| **False Alarm Rate** | False alerts on 1-hour separate held-out normal traffic | < 5.0% | **0.0%** (0 false alerts across 1,836 held-out events) | **PASS** |
| **Detection Latency** | Alert timestamp minus attack injection start time | < 15 minutes (900s) | **Median: 0.846s | p95: 1.439s** | **PASS** |
| **No Impact on Control** | SCADA poll success rate and p95 RTT with sensor OFF vs ON | 100% success, ΔRTT ~0 | **Success: 100.0%, ΔRTT: -0.32 ms** | **PASS** |
| **Upstream Bandwidth** | Bytes transmitted by sensor to Central collector | < 50 KB/hour | **19.2 KB / simulated plant hour** | **PASS** |

### Confusion Matrix (`results/confusion_matrix.json`)
* **True Positives (TP):** 35
* **False Positives (FP):** 0
* **False Negatives (FN):** 0
* **True Negatives (TN):** 1,836
* **Precision:** **100.0%**
* **Recall:** **100.0%**
* **F1-Score:** **100.0%**

---

## 5. Offline Dataset Replay (`eval/replay_datasets.py`)

As required by the assignment brief, a dedicated replay harness is provided for external benchmarks:
1. Canadian Institute for Cybersecurity (CIC) Modbus Dataset 2023
2. Zenodo IEC 60870-5-104 Intrusion Detection Dataset (DOI: 10.5281/zenodo.4660424)

In accordance with strict research integrity (**"If they cannot be downloaded, write the script and mark it as not run. Do not fake it."**), running `python eval/replay_datasets.py` without pre-downloaded PCAPs records `status: NOT RUN` in `results/dataset_replay_results.json` with primary download URLs.

---

## 6. Known Engineering Limitations

1. **Docker Bridge vs. Real Switch SPAN Port**:  
   In simulation, capturing on the container virtual bridge behaves like a port mirror. In physical plants, hardware SPAN/mirror ports can drop packets under high link utilization and omit malformed framing errors (CRC errors, runts). A dedicated passive optical TAP or industrial managed switch mirror is recommended.
2. **Simulation vs. Real Operational Data**:  
   Our baseline was generated using physical solar irradiance curves (diurnal half-sine with Gaussian noise). Real solar plants exhibit cloud transients, curtailment ramps, and proprietary inverter register mappings that must be surveyed on-site.
3. **Machine Learning False Alarms & Sensitivity (S7)**:  
   Unsupervised Isolation Forest works well for volumetric bursts and register reconnaissance. However, detecting frozen telemetry (S7) requires physical cross-correlation with environmental pyranometers; a sophisticated attacker who replays historic telemetry with synthetic noise can evade basic statistical checks.
4. **Encrypted & Proprietary Vendor Tunnels**:  
   Passive packet inspection cannot decode proprietary vendor protocols protected by TLS or proprietary encapsulation without gateway audit logs.
5. **No Equipment Impact Guarantee**:  
   The sensor operates in promiscuous receive-only mode. It does NOT possess an IP address on the monitored control segment and transmits zero packets, guaranteeing zero interference with critical control loops.
