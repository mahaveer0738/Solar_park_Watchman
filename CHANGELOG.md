# Solar Park Watchman - Engineering Changelog

All notable changes, bug fixes, test runs, and milestone verifications will be documented in this file.

---

## [Milestone 6] - Plain-Language Alert Builder, Central Collector & Store-and-Forward (B4, B7) - Verified PASS
### Added
- Completed `sensor/alert_builder.py` strictly enforcing the JSON Lines alert format (`time`, `severity`, `scenario`, `device`, `source`, `reason`, `attack_technique`, `evidence`).
- Completed `central/app.py` HTTP service with `/api/alerts`, `/api/summary`, and `/api/metrics` tracking alert counts and cumulative bandwidth (KB/hour).
- Completed `sensor/forwarder.py` store-and-forward client with disk queue buffer (`data/forward_queue.jsonl`) guaranteeing zero alert drop during WAN connection outages.
- Authored and verified `tests/test_forwarder.py` with 100% pass rate (`2 passed in 4.11s`).

---

## [Milestone 5] - Machine Learning Detector & Feature Pipeline (B4) - Verified PASS
### Added
- Completed `sensor/ml_detector.py` implementing Scikit-Learn `IsolationForest` pipeline and rolling 60-second feature engineering (packet rate, byte volume, unique registers, write ratio, iec104 rate, power variance, irradiance residual).
- Implemented physical cross-correlation consistency checker for S7 (frozen/spoofed telemetry): detects static inverter power outputs when PLC environmental irradiance fluctuates > 40 W/m^2.
- Emitted plain-language reasons and confidence levels on all ML anomaly alerts.
- Maintained rules as primary and ML as secondary detection layer.
- Authored and verified `tests/test_ml.py` with 100% pass rate (`3 passed in 3.30s`).

---

## [Milestone 4] - Deterministic Rule Engine & Policy Definition (B4) - Verified PASS
### Added
- Completed `sensor/rule_engine.py` evaluating normalized events against `config/policy.yaml`.
- Implemented deterministic rule S2: Inverter setpoint writes (reg 101) restricted to PPC (`10.10.1.30`) only; raises high-severity alert with MITRE `T0836`.
- Implemented deterministic rule S3: Vendor remote gateway maintenance window restriction (10:00 - 16:00); flags out-of-hours writes with MITRE `T0885`.
- Implemented deterministic rule S6: IEC-104 control commands (Types 45/46/50) restricted to Grid Master (`10.10.2.10`) only; flags non-master control commands with MITRE `T0855`.
- Implemented deterministic rule S5: IEC-104 rate limiter flagging bursts > 40 frames/min with MITRE `T0814`.
- Implemented deterministic rule S8: Protocol reconnaissance & register enumeration detection with sliding 60-second window tracking unique registers and targets with MITRE `T0846`.
- Authored and verified `tests/test_rules.py` with 100% pass rate (`5 passed in 0.10s`).

---

## [Milestone 3] - Device Inventory & Behavioral Role Inference (B3) - Verified PASS
### Added
- Completed `sensor/inventory.py` SQLite engine with automatic schema generation and thread-safe CRUD.
- Implemented behavioral role classification inferring `SCADA`, `PPC`, `Inverter`, `PLC`, `IEC104_Outstation`, and `Grid_Master` roles based on observed function codes, register targets, and port flows.
- Implemented unapproved device detection raising S1 alert (`T0886`) immediately when an unknown IP/MAC appears.
- Authored and verified `tests/test_inventory.py` with 100% pass rate (`2 passed in 0.12s`).

---

## [Milestone 2] - Sensor Capture, Parsing & Event Normalization (B2) - Verified PASS
### Added
- Completed `sensor/parsers/modbus_parser.py` extracting MBAP headers, FC codes (01, 02, 03, 04, 05, 06, 16), addresses, and register values.
- Completed `sensor/parsers/iec104_parser.py` dissecting APDU U-format (STARTDT, TESTFR), S-format, and I-format with ASDU Types (1, 13, 30, 36, 45, 46, 50, 100), Cause of Transmission (COT), and IOAs.
- Completed `sensor/normaliser.py` generating canonical telemetry records: `(time, src_ip, dst_ip, protocol, function, address, value)`.
- Completed `sensor/capture.py` implementing zero-transmission passive capture supporting both live Scapy sniffing and offline PCAP ingestion.
- Authored and verified `tests/test_normaliser.py` with 100% pass rate (`5 passed in 1.15s`).

---

## [Milestone 1] - Foundation, Simulation & Protocols (B1) - Verified PASS
### Added
- Completed `sim/common.py` with physical constants, register mappings, and IEC-104 ASDU/IOA definitions.
- Completed `sim/weather.py` with diurnal irradiance model (Gujarat solar profile) and manual override capability.
- Completed `sim/plc.py` with Modbus TCP server hosting weather registers 201-205.
- Completed `sim/inverters.py` with Modbus TCP servers for inverters 1, 2, 3 (registers 101-105) and S7 telemetry freeze injection.
- Completed `sim/ppc.py` (Plant Power Controller) for periodic authorized setpoint writes to register 101.
- Completed `sim/scada.py` polling all field devices cyclically and tracking poll success rate and RTT latencies.
- Completed `sim/iec104.py` pure-Python IEC 60870-5-104 Outstation and Client with Breaker Point IOA 1000 and command support (Types 45/46/50).
- Completed `sim/vendor_gw.py` simulating maintenance gateway reads.
- Authored and verified `tests/test_simulation.py` with 100% pass rate (`3 passed in 4.09s`).

### Fixed
- Fixed datastore index referencing in `sim/plc.py` and `sim/inverters.py` for compatibility with `pymodbus 3.16.1` by accessing `store.simdevice.simdata[2][0].values`.
- Handled async event loop shutdown cleanly during thread termination to eliminate runtime unhandled thread warnings.
