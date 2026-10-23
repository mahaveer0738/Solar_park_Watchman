"""
Offline Dataset Replay Harness for External Benchmarks.
Datasets targeted:
1. Canadian Institute for Cybersecurity (CIC) Modbus Dataset 2023
2. Radoglou-Grammatikis et al., IEC 60870-5-104 Intrusion Detection Dataset (Zenodo)
Adheres strictly to the rule: If datasets are not present locally and cannot be downloaded,
mark as NOT RUN. Never fabricate data or replay results.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from sim.common import iso_utc_now
from sensor.engine import WatchmanSensorEngine

logger = logging.getLogger("replay")

CIC_MODBUS_PATH = "data/external/cic_modbus_2023.pcap"
ZENODO_IEC104_PATH = "data/external/zenodo_iec104.pcap"
RESULTS_FILE = "results/dataset_replay_results.json"

def run_replay():
    os.makedirs("results", exist_ok=True)
    os.makedirs("data/external", exist_ok=True)

    report = {
        "timestamp": iso_utc_now(),
        "datasets": {
            "CIC_Modbus_2023": {
                "file_path": CIC_MODBUS_PATH,
                "status": "NOT RUN",
                "reason": "Dataset archive not available locally in offline test environment. Download source: Canadian Institute for Cybersecurity (CIC).",
                "packets_processed": 0,
                "alerts_raised": 0
            },
            "Zenodo_IEC104": {
                "file_path": ZENODO_IEC104_PATH,
                "status": "NOT RUN",
                "reason": "Zenodo IEC 60870-5-104 capture archive not available locally. Download source: Zenodo DOI: 10.5281/zenodo.4660424.",
                "packets_processed": 0,
                "alerts_raised": 0
            }
        },
        "pipeline_status": "Ready for offline PCAP ingestion via PassiveSensorCapture.ingest_pcap()"
    }

    # If CIC Modbus PCAP is present, replay it
    if os.path.exists(CIC_MODBUS_PATH):
        engine = WatchmanSensorEngine()
        alerts_before = len(engine.alerts_generated)
        events = engine.capture.ingest_pcap(CIC_MODBUS_PATH)
        alerts_raised = len(engine.alerts_generated) - alerts_before
        report["datasets"]["CIC_Modbus_2023"]["status"] = "COMPLETED"
        report["datasets"]["CIC_Modbus_2023"]["packets_processed"] = len(events)
        report["datasets"]["CIC_Modbus_2023"]["alerts_raised"] = alerts_raised

    # If Zenodo IEC-104 PCAP is present, replay it
    if os.path.exists(ZENODO_IEC104_PATH):
        engine = WatchmanSensorEngine()
        alerts_before = len(engine.alerts_generated)
        events = engine.capture.ingest_pcap(ZENODO_IEC104_PATH)
        alerts_raised = len(engine.alerts_generated) - alerts_before
        report["datasets"]["Zenodo_IEC104"]["status"] = "COMPLETED"
        report["datasets"]["Zenodo_IEC104"]["packets_processed"] = len(events)
        report["datasets"]["Zenodo_IEC104"]["alerts_raised"] = alerts_raised

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    run_replay()
