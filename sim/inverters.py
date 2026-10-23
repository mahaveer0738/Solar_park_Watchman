"""
Simulated Solar Inverters 1, 2, 3 (Modbus TCP Servers).
Features:
- Register 101: Active power limit set-point (kW, default 1000)
- Register 102: Active power (kW, follows irradiance curve + noise, capped by reg 101)
- Register 103: AC Voltage (V, nominal 690V)
- Register 104: Inverter Status (1: Running, 2: Standby, 3: Fault, 4: Curtailed)
- Register 105: Firmware Version (0x0102)
- S7 Telemetry freeze injection support
"""
import asyncio
import threading
import time
import random
import logging
from typing import Optional
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusDeviceContext, ModbusServerContext
from sim.common import (
    PORT_INVERTER_1, PORT_INVERTER_2, PORT_INVERTER_3,
    REG_ACTIVE_POWER_LIMIT, REG_ACTIVE_POWER, REG_VOLTAGE,
    REG_STATUS, REG_FIRMWARE_VER
)
from sim.weather import WeatherStation

logging.getLogger("pymodbus").setLevel(logging.ERROR)

class SolarInverter:
    def __init__(
        self,
        name: str,
        host: str = "0.0.0.0",
        port: int = PORT_INVERTER_1,
        nominal_capacity_kw: float = 1000.0,
        firmware_ver: int = 0x0102,
        weather_station: Optional[WeatherStation] = None
    ):
        self.name = name
        self.host = host
        self.port = port
        self.nominal_capacity_kw = nominal_capacity_kw
        self.firmware_ver = firmware_ver
        self.weather = weather_station or WeatherStation()
        self.running = False
        self._loop = None

        # S7 Fault injection: Frozen telemetry
        self.frozen_telemetry: bool = False
        self.frozen_power_kw: float = 850.0

        # Register datastore (1..400)
        self.data_block = ModbusSequentialDataBlock(1, [0] * 400)
        self.store = ModbusDeviceContext(
            di=self.data_block, co=self.data_block,
            hr=self.data_block, ir=self.data_block
        )
        self.context = ModbusServerContext(devices=self.store, single=True)

        self._set_holding(REG_ACTIVE_POWER_LIMIT, int(nominal_capacity_kw))
        self._set_holding(REG_ACTIVE_POWER, 0)
        self._set_holding(REG_VOLTAGE, 690)
        self._set_holding(REG_STATUS, 1)
        self._set_holding(REG_FIRMWARE_VER, firmware_ver)

    def _set_holding(self, address: int, val: int):
        self.store.simdevice.simdata[2][0].values[address] = int(val)

    def _get_holding(self, address: int) -> int:
        return self.store.simdevice.simdata[2][0].values[address]

    def update_physics(self):
        """Update active power generation from irradiance and active limit."""
        limit_kw = self._get_holding(REG_ACTIVE_POWER_LIMIT)

        if self.frozen_telemetry:
            power_kw = self.frozen_power_kw
            voltage = 690
            status = 1
        else:
            weather_data = self.weather.read_metrics()
            irradiance = weather_data["irradiance"]

            if irradiance > 20.0:
                raw_power = (irradiance / 1000.0) * self.nominal_capacity_kw * 0.98
                noise = random.gauss(0, 3.0)
                gen_power = max(0.0, raw_power + noise)
                power_kw = min(float(limit_kw), gen_power)
                voltage = int(690 + random.gauss(0, 2.0))
                status = 4 if (gen_power > limit_kw) else 1
            else:
                power_kw = 0.0
                voltage = 0
                status = 2  # Standby / Night

        self._set_holding(REG_ACTIVE_POWER, int(power_kw))
        self._set_holding(REG_VOLTAGE, voltage)
        self._set_holding(REG_STATUS, status)

    def start(self):
        self.running = True
        self.update_physics()

        def _thread_target():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            async def _bg_loop():
                server_coro = StartAsyncTcpServer(
                    context=self.context,
                    address=(self.host, self.port)
                )

                async def _updater():
                    while self.running:
                        self.update_physics()
                        await asyncio.sleep(1.0)

                await asyncio.gather(server_coro, _updater())

            try:
                self._loop.run_until_complete(_bg_loop())
            except (asyncio.CancelledError, RuntimeError):
                pass
            finally:
                try:
                    self._loop.close()
                except Exception:
                    pass

        self._thread = threading.Thread(target=_thread_target, daemon=True, name=f"{self.name}-Thread")
        self._thread.start()
        time.sleep(0.3)

    def stop(self):
        self.running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)


class InverterCluster:
    """Manages all 3 plant inverters as a cluster."""
    def __init__(self, weather_station: Optional[WeatherStation] = None, host: str = "0.0.0.0"):
        self.weather = weather_station or WeatherStation()
        self.inverters = {
            "inverter-1": SolarInverter("inverter-1", host=host, port=PORT_INVERTER_1, weather_station=self.weather),
            "inverter-2": SolarInverter("inverter-2", host=host, port=PORT_INVERTER_2, weather_station=self.weather),
            "inverter-3": SolarInverter("inverter-3", host=host, port=PORT_INVERTER_3, weather_station=self.weather),
        }

    def start_all(self):
        for inv in self.inverters.values():
            inv.start()

    def stop_all(self):
        for inv in self.inverters.values():
            inv.stop()

if __name__ == "__main__":
    cluster = InverterCluster()
    cluster.start_all()
    print("Inverters 1, 2, 3 running on ports 5021, 5022, 5023. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cluster.stop_all()
