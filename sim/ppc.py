"""
Plant Power Controller (PPC) simulation.
The ONLY legitimate sender authorized to write active-power-limit setpoints
(register 101) to inverters 1, 2, 3.
"""
import time
import threading
import logging
from pymodbus.client import ModbusTcpClient
from sim.common import (
    PORT_INVERTER_1, PORT_INVERTER_2, PORT_INVERTER_3,
    REG_ACTIVE_POWER_LIMIT, IP_PPC
)

logger = logging.getLogger("ppc")

class PlantPowerController:
    def __init__(self, inverters: list[dict] = None, interval_seconds: float = 60.0):
        self.inverters = inverters or [
            {"name": "inverter-1", "host": "127.0.0.1", "port": PORT_INVERTER_1},
            {"name": "inverter-2", "host": "127.0.0.1", "port": PORT_INVERTER_2},
            {"name": "inverter-3", "host": "127.0.0.1", "port": PORT_INVERTER_3},
        ]
        self.interval_seconds = interval_seconds
        self.running = False
        self._thread = None

    def send_approved_setpoints(self, target_kw: int = 1000):
        """Send approved set-point update to all plant inverters."""
        results = {}
        for inv in self.inverters:
            try:
                client = ModbusTcpClient(inv["host"], port=inv["port"])
                if client.connect():
                    res = client.write_register(REG_ACTIVE_POWER_LIMIT, target_kw)
                    results[inv["name"]] = not res.isError()
                    client.close()
                else:
                    results[inv["name"]] = False
            except Exception as e:
                results[inv["name"]] = False
        return results

    def start(self):
        self.running = True
        def _loop():
            while self.running:
                self.send_approved_setpoints(1000)
                # Sleep interval
                for _ in range(int(self.interval_seconds * 10)):
                    if not self.running:
                        break
                    time.sleep(0.1)

        self._thread = threading.Thread(target=_loop, daemon=True, name="PPC-Thread")
        self._thread.start()

    def stop(self):
        self.running = False
