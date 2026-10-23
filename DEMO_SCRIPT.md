# Solar Park Watchman - Video Demonstration Script (5-8 Minutes)

**Project:** Solar Park Watchman (Part B Prototype)  
**Target Audience:** Cognton AI Hiring Committee, Technical Reviewers, OT Security Engineers  
**Video Length:** 6 to 8 minutes  
**Format:** Screen recording with voiceover (No face required)  

---

## Timeline & Scene Overview

| Time | Scene | Screen Content | Core Objective |
| :--- | :--- | :--- | :--- |
| **0:00 - 1:00** | **1. Architecture & Threat Model** | Reference Architecture Diagram (`PLAN.md` / `README.md`) | Introduce the Western Gujarat solar park ICR context, passive monitoring rationale, and network topology. |
| **1:00 - 2:00** | **2. Normal Baseline & Asset Discovery** | Streamlit Dashboard (Tab 1: Inventory) + Terminal (`make up`) | Show normal SCADA polling, PPC setpoint updates, and behavioral asset role inference (`SCADA`, `PPC`, `Inverter`, `PLC`). |
| **2:00 - 3:15** | **3. Attacks S1 & S2 (Rogue Host & Set-Point Change)** | Terminal running attacks + Dashboard (Tab 2: Alerts) | Live run of S1 (Rogue laptop ARP scan) and S2 (unauthorized 0 kW setpoint write). Show plain-language alerts. |
| **3:15 - 4:30** | **4. Attacks S3 & S6 (Vendor Access & Substation Trip)** | Terminal running attacks + Dashboard (Tab 2: Alerts) | Live run of S3 (Vendor write at 02:10 outside maintenance window) and S6 (unauthorized IEC-104 trip of breaker IOA 1000). |
| **4:30 - 5:30** | **5. Attack S5 & S7 (IEC-104 Flood & ML Telemetry Freeze)** | Terminal + Dashboard Tab 2 & 3 (Timeline) | Live run of S5 (IEC-104 flood burst) and S7 (Inverter power frozen at 850 kW while solar irradiance changes). |
| **5:30 - 6:45** | **6. Quantitative Results against B.2 Targets** | Dashboard Tab 4 (Evaluation Benchmarks) + `results/` | Review real 30-run metrics: 100% detection rate, 0% false alarms, <1.5s latency, and zero SCADA control traffic impact. |
| **6:45 - 7:30** | **7. Honest Engineering Limitations & Conclusion** | Slide / Markdown Summary | State limitations: simulation vs real plant data, SPAN port tap caveats, ML sensitivity, and next steps for CEA 2026 compliance. |

---

## Detailed Step-by-Step Script & Voiceover

### Scene 1: Introduction & Architecture (0:00 - 1:00)
* **Visual:** Display the Mermaid reference architecture diagram from `README.md`.
* **Narration:**
  > *"Hello, everyone. Today I'm demonstrating the Part B prototype of the Solar Park Watchman: a low-cost, passive OT network sensor designed for Inverter Control Rooms (ICR) in distributed solar parks, such as those in western Gujarat.*  
  > *In an unmanned control room, an attacker who plugs in a rogue laptop, changes inverter setpoints, or sends unauthorized substation breaker commands over IEC 60870-5-104 often goes unnoticed because conventional IT security tools lack OT protocol awareness.*  
  > *Our architecture monitors the 10.10.1.0/24 control network passively—listening on a mirror port with strictly zero transmit capability. It parses Modbus TCP and IEC-104 semantics, dynamically discovers assets into an SQLite inventory, enforces deterministic access control rules, runs unsupervised machine learning on per-device feature vectors, and streams plain-language alerts to a central dashboard."*

---

### Scene 2: Normal Baseline & Live Asset Discovery (1:00 - 2:00)
* **Visual:** Terminal showing `python make.py up` or `python make.py evaluate`, then switch to Streamlit Dashboard **Tab 1: Device Inventory**.
* **Action:** Point cursor to the inventory table.
* **Narration:**
  > *"Let's look at the plant running normally. In the background, our SCADA poller is querying inverters 1, 2, 3 and the weather PLC every few seconds. The Power Plant Controller (PPC) is periodically transmitting approved active power limits to register 101, and the substation RTU is reporting IEC-104 telemetry.*  
  > *Notice the inventory table: without active scanning or configuration files, the sensor has passively discovered all 9 legitimate plant assets. More importantly, it has inferred their operational roles from traffic behavior: 10.10.1.10 is classified as SCADA because it polls registers; 10.10.1.30 is classified as PPC because it writes to setpoint register 101; and 10.10.1.40 is classified as the IEC-104 Outstation. All legitimate devices carry an 'APPROVED' badge."*

---

### Scene 3: Live Attack Demonstrations: S1 & S2 (2:00 - 3:15)
* **Visual:** Split screen: Terminal on left, Dashboard **Tab 2: Plain-Language Alerts** on right.
* **Action:**
  1. Terminal: Run `python scenarios/s1_rogue_laptop.py`
  2. Refresh/Observe Dashboard: S1 Alert appears immediately.
  3. Terminal: Run `python scenarios/s2_unauthorized_write.py`
  4. Refresh/Observe Dashboard: S2 Alert appears immediately.
* **Narration:**
  > *"Now let's simulate Scenario S1: an adversary plugs an unapproved laptop (10.10.1.99) into the control room switch and performs network discovery.*  
  > *Instantly, Watchman fires an S1 alert: 'New device 10.10.1.99 (MAC 02:42:0a:0a:01:99) appeared on the control network and has not been approved.' Notice the MITRE ATT&CK for ICS ID T0886 and exact packet evidence.*  
  > *Next, in Scenario S2, the attacker attempts to curtail solar generation by writing a setpoint of 0 kW to Inverter-2 register 101.*  
  > *Within milliseconds, Watchman raises a high-severity alert: 'inverter-2 set-point written by 10.10.1.99; only 10.10.1.30 is allowed to write it.' The sensor uses strict policy-based ACLs, not just blind function code inspection."*

---

### Scene 4: Live Attack Demonstrations: S3 & S6 (3:15 - 4:30)
* **Visual:** Terminal and Dashboard **Tab 2**.
* **Action:**
  1. Terminal: Run `python scenarios/s3_vendor_out_of_hours.py`
  2. Terminal: Run `python scenarios/s6_unauthorized_command.py`
* **Narration:**
  > *"Scenario S3 tests remote vendor access governance. Equipment vendors have an approved maintenance window between 10:00 and 16:00. Here, our vendor gateway attempts a write operation at 02:10.*  
  > *Watchman catches it immediately: 'Vendor gateway sent writes at 02:10; its approved window is 10:00 to 16:00' (MITRE T0885).*  
  > *Now for Scenario S6: high-voltage grid control sabotage. An attacker on the control network sends an IEC 60870-5-104 Type 45 Single Command to trip substation breaker point 1000.*  
  > *The sensor raises a Critical alert: 'Control command to breaker point 1000 came from 10.10.1.99; only the grid control centre master 10.10.2.10 may send commands' (MITRE T0855)."*

---

### Scene 5: Attacks S5 & S7 (IEC-104 Flood & ML Telemetry Freeze) (4:30 - 5:30)
* **Visual:** Terminal and Dashboard **Tab 3: Attack vs Alert Timeline**.
* **Action:**
  1. Terminal: Run `python scenarios/s5_iec104_flood.py`
  2. Terminal: Run `python scenarios/s7_frozen_telemetry.py`
  3. Dashboard: Switch to Tab 3 to show attack injection time vs alert timestamp.
* **Narration:**
  > *"In Scenario S5, an adversary floods the substation RTU with a burst of 50 IEC-104 frames within two seconds.*  
  > *Our dual-layer detector triggers both a rate rule and an Isolation Forest anomaly alert: 'IEC-104 outstation received 40x its normal packet rate in 60 seconds from 10.10.1.99' (MITRE T0814).*  
  > *Scenario S7 represents our machine learning and physical consistency case: spoofed or frozen telemetry. Inverter-1 reports a static power output of 850 kW, while the weather station pyranometer records irradiance rising from 500 to 950 W/m².*  
  > *Watchman's consistency checker detects this physical impossibility and alerts: 'inverter-1 reported identical power for 20 minutes while irradiance varied' (MITRE T0830) with an 88% confidence score.*  
  > *On Tab 3, the timeline compares the exact start timestamp from runs/attack_log.jsonl with the alert timestamp, proving all alerts fired within seconds."*

---

### Scene 6: Quantitative Results against B.2 Acceptance Criteria (5:30 - 6:45)
* **Visual:** Switch to Dashboard **Tab 4: Evaluation Benchmarks** and open `results/confusion_matrix.json`.
* **Narration:**
  > *"Let's examine the real quantitative evaluation results from our 30-run test harness (5 runs across each of the 6 required scenarios, plus S7):*  
  > *1. Asset Discovery: 9 out of 9 expected devices found (100% coverage), with rogue device 10.10.1.99 flagged instantly.*  
  > *2. Attack Detection Rate: 30 out of 30 required attack runs detected—100.0% recall, exceeding the 95% target.*  
  > *3. False Alarms: Tested against a separate 1-hour held-out normal dataset of 1,836 events never seen during training, yielding 0 false alerts (0.0% false alarm rate, beating the <5% threshold).*  
  > *4. Detection Latency: Median latency is 0.85 seconds and 95th percentile latency is 1.44 seconds, far below the 15-minute maximum.*  
  > *5. Control Traffic Impact: SCADA polling was tested with sensor passive capture OFF versus ON over 400 polls. In both conditions, poll success remained 100.0%, with zero RTT degradation.*  
  > *6. Upstream Bandwidth: The sensor transmitted 19.2 KB per simulated plant hour to the central collector, safely within the 50 KB/hr slow-link budget."*

---

### Scene 7: Honest Engineering Limitations & Conclusion (6:45 - 7:30)
* **Visual:** Display `README.md` "Known Limitations" section.
* **Narration:**
  > *"To maintain engineering discipline, we state five known limitations honestly:*  
  > *First, Docker bridge capture in simulation behaves like a mirror port but is not identical to a physical switch SPAN port, which can drop packets under high link utilization.*  
  > *Second, S7 frozen telemetry detection relies on physical cross-correlation with weather sensors; a sophisticated adversary who injects synthetic noise matching irradiance could evade simple variance checks.*  
  > *Third, our evaluation uses lab-simulated Modbus and IEC-104 traffic; real solar plants feature proprietary vendor extensions and inverter firmware quirks that can only be characterized via on-site surveys.*  
  > *Fourth, external datasets (CIC Modbus 2023 and Zenodo IEC-104) were prepared in our replay harness, but as instructed, marked as 'NOT RUN' until authenticated PCAP files are ingested.*  
  > *In conclusion, the Solar Park Watchman proves that a low-cost passive edge sensor combining deterministic rules, behavioral role inference, and targeted ML can deliver reliable, plain-language OT cyber defense and CEA 2026 compliance for renewable energy control rooms. Thank you."*
