"""
SCADA poller reading all inverters and PLC cyclically every 2-5 seconds.
Tracks polling success rate and round-trip time (RTT) for performance impact evaluation.
"""
import time
import threading
import statistics
import logging
from pymodbus.client import ModbusTcpClient
from sim.common import (
    PORT_PLC, PORT_INVERTER_1, PORT_INVERTER_2, PORT_INVERTER_3,
    REG_ACTIVE_POWER_LIMIT, REG_PLC_IRRADIANCE
)

logger = logging.getLogger("scada")

class SCADAPoller:
    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval
        self.devices = [
            {"name": "inverter-1", "host": "127.0.0.1", "port": PORT_INVERTER_1, "reg": REG_ACTIVE_POWER_LIMIT, "count": 5},
            {"name": "inverter-2", "host": "127.0.0.1", "port": PORT_INVERTER_2, "reg": REG_ACTIVE_POWER_LIMIT, "count": 5},
            {"name": "inverter-3", "host": "127.0.0.1", "port": PORT_INVERTER_3, "reg": REG_ACTIVE_POWER_LIMIT, "count": 5},
            {"name": "plc", "host": "127.0.0.1", "port": PORT_PLC, "reg": REG_PLC_IRRADIANCE, "count": 5},
        ]
        self.running = False
        self._thread = None
        self.stats = {
            "total_polls": 0,
            "successful_polls": 0,
            "failed_polls": 0,
            "rtt_ms": []
        }
        self._lock = threading.Lock()

    def poll_once(self) -> dict:
        """Perform one round of polling across all devices and measure RTT."""
        round_results = {}
        for dev in self.devices:
            t0 = time.perf_counter()
            success = False
            rtt = 0.0
            val = None
            try:
                client = ModbusTcpClient(dev["host"], port=dev["port"], timeout=1.0)
                if client.connect():
                    res = client.read_holding_registers(dev["reg"], count=dev["count"])
                    rtt = (time.perf_counter() - t0) * 1000.0  # ms
                    if not res.isError():
                        success = True
                        val = res.registers
                    client.close()
            except Exception:
                success = False

            with self._lock:
                self.stats["total_polls"] += 1
                if success:
                    self.stats["successful_polls"] += 1
                    self.stats["rtt_ms"].append(rtt)
                    if len(self.stats["rtt_ms"]) > 10000:
                        self.stats["rtt_ms"] = self.stats["rtt_ms"][-5000:]
                else:
                    self.stats["failed_polls"] += 1

            round_results[dev["name"]] = {"success": success, "rtt_ms": rtt, "values": val}

        return round_results

    def get_metrics(self) -> dict:
        """Calculate success rate and latency percentiles."""
        with self._lock:
            total = self.stats["total_polls"]
            succ = self.stats["successful_polls"]
            rtts = list(self.stats["rtt_ms"])

        success_rate = (succ / total * 100.0) if total > 0 else 100.0
        p95_rtt = float(statistics.quantiles(rtts, n=100)[94]) if len(rtts) >= 10 else (statistics.mean(rtts) if rtts else 0.0)
        median_rtt = statistics.median(rtts) if rtts else 0.0

        return {
            "total_polls": total,
            "successful_polls": succ,
            "failed_polls": total - succ,
            "success_rate_pct": round(success_rate, 2),
            "median_rtt_ms": round(median_rtt, 3),
            "p95_rtt_ms": round(p95_rtt, 3),
        }

    def start(self):
        self.running = True
        def _loop():
            while self.running:
                self.poll_once()
                for _ in range(int(self.poll_interval * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)

        self._thread = threading.Thread(target=_loop, daemon=True, name="SCADA-Thread")
        self._thread.start()

    def stop(self):
        self.running = False
