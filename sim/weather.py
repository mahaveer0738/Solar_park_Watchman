"""
Weather simulation service providing simulated irradiance, ambient temperature,
module temperature, and wind speed for the solar park.
"""
import time
import math
import random
from typing import Optional
from sim.common import calculate_solar_irradiance

class WeatherStation:
    """Simulates physical environmental conditions at the solar park."""
    def __init__(self, start_sim_hour: float = 8.0, speedup: float = 1.0):
        self.start_sim_hour = start_sim_hour
        self.speedup = speedup
        self.start_real_time = time.time()
        self._manual_override_irradiance: Optional[float] = None

    def set_override_irradiance(self, value: Optional[float]):
        """Manually force irradiance (used for controlled test cases like S7)."""
        self._manual_override_irradiance = value

    def get_current_sim_hour(self) -> float:
        elapsed_seconds = (time.time() - self.start_real_time) * self.speedup
        sim_hours_passed = elapsed_seconds / 3600.0
        return (self.start_sim_hour + sim_hours_passed) % 24.0

    def read_metrics(self) -> dict:
        """Read instantaneous weather telemetry."""
        sim_hour = self.get_current_sim_hour()
        irr, amb, mod = calculate_solar_irradiance(sim_hour)

        if self._manual_override_irradiance is not None:
            irr = self._manual_override_irradiance
            mod = amb + (irr * 0.025)

        wind_speed = 3.5 + random.gauss(0, 0.5)

        return {
            "sim_hour": sim_hour,
            "irradiance": round(irr, 1),
            "ambient_temp": round(amb, 1),
            "module_temp": round(mod, 1),
            "wind_speed": round(max(0.2, wind_speed), 1),
            "status": 1
        }

if __name__ == "__main__":
    station = WeatherStation(start_sim_hour=10.0, speedup=60.0)
    for _ in range(5):
        print(station.read_metrics())
        time.sleep(0.5)
