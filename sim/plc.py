"""
Plant Master PLC simulation (Modbus TCP Server).
Aggregates weather station feeds and plant-level sensor registers.
"""
import asyncio
import threading
import time
import logging
from typing import Optional
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusDeviceContext, ModbusServerContext
from sim.common import (
    PORT_PLC, REG_PLC_IRRADIANCE, REG_PLC_AMBIENT_TEMP,
    REG_PLC_MODULE_TEMP, REG_PLC_WIND_SPEED, REG_PLC_STATUS
)
from sim.weather import WeatherStation

logging.getLogger("pymodbus").setLevel(logging.ERROR)

class PlantPLC:
    def __init__(self, host: str = "0.0.0.0", port: int = PORT_PLC, weather_station: Optional[WeatherStation] = None):
        self.host = host
        self.port = port
        self.weather = weather_station or WeatherStation()
        self.running = False
        self._loop = None

        # Modbus register space (1-indexed base 1, size 400)
        self.data_block = ModbusSequentialDataBlock(1, [0] * 400)
        self.store = ModbusDeviceContext(
            di=self.data_block, co=self.data_block,
            hr=self.data_block, ir=self.data_block
        )
        self.context = ModbusServerContext(devices=self.store, single=True)
        self._set_holding(REG_PLC_STATUS, 1)

    def _set_holding(self, address: int, val: int):
        self.store.simdevice.simdata[2][0].values[address] = int(val)

    def _get_holding(self, address: int) -> int:
        return self.store.simdevice.simdata[2][0].values[address]

    def update_sensors(self):
        """Update PLC datastore with current weather readings."""
        data = self.weather.read_metrics()
        irr = int(data["irradiance"])
        amb = int(data["ambient_temp"] * 10)
        mod = int(data["module_temp"] * 10)
        wind = int(data["wind_speed"] * 10)

        self._set_holding(REG_PLC_IRRADIANCE, irr)
        self._set_holding(REG_PLC_AMBIENT_TEMP, amb)
        self._set_holding(REG_PLC_MODULE_TEMP, mod)
        self._set_holding(REG_PLC_WIND_SPEED, wind)
        self._set_holding(REG_PLC_STATUS, 1)

    def start(self):
        """Start the PLC server in a background daemon thread."""
        self.running = True
        self.update_sensors()

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
                        self.update_sensors()
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

        self._thread = threading.Thread(target=_thread_target, daemon=True, name="PlantPLC-Thread")
        self._thread.start()
        time.sleep(0.3)

    def stop(self):
        self.running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    plc = PlantPLC()
    plc.start()
    print(f"Plant PLC running on port {plc.port}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        plc.stop()
