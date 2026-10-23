"""
Common simulation constants, IP mappings, register specifications, and models.
"""
import time
import math
import random
from datetime import datetime, timezone

# Network IP Configuration (as specified in Report Part A)
IP_CENTRAL = "10.10.1.5"
IP_SCADA = "10.10.1.10"
IP_INVERTER_1 = "10.10.1.11"
IP_INVERTER_2 = "10.10.1.12"
IP_INVERTER_3 = "10.10.1.13"
IP_PLC = "10.10.1.20"
IP_WEATHER = "10.10.1.25"
IP_PPC = "10.10.1.30"
IP_IEC104_OUTSTATION = "10.10.1.40"
IP_VENDOR_GW = "10.10.1.50"
IP_ATTACKER = "10.10.1.99"
IP_GRID_CENTRE = "10.10.2.10"

# Host Port Mapping for Local Native Execution (when not running inside Docker bridge)
PORT_CENTRAL = 8000
PORT_PLC = 5020
PORT_INVERTER_1 = 5021
PORT_INVERTER_2 = 5022
PORT_INVERTER_3 = 5023
PORT_IEC104 = 2404
PORT_DASHBOARD = 8501

DEVICE_PORT_MAP = {
    IP_PLC: PORT_PLC,
    IP_INVERTER_1: PORT_INVERTER_1,
    IP_INVERTER_2: PORT_INVERTER_2,
    IP_INVERTER_3: PORT_INVERTER_3,
    IP_IEC104_OUTSTATION: PORT_IEC104,
}

PORT_DEVICE_MAP = {v: k for k, v in DEVICE_PORT_MAP.items()}

# Inverter Modbus Register Map
REG_ACTIVE_POWER_LIMIT = 101  # Holding Register (kW, default 1000)
REG_ACTIVE_POWER = 102        # Holding Register (kW, dynamic irradiance * derating)
REG_VOLTAGE = 103             # Holding Register (V, nominal 690V)
REG_STATUS = 104              # Holding Register (1: Running, 2: Standby, 3: Fault)
REG_FIRMWARE_VER = 105        # Holding Register (e.g. 0x0102 for v1.2)

# PLC Modbus Register Map
REG_PLC_IRRADIANCE = 201      # Holding Register (W/m^2, 0 - 1200)
REG_PLC_AMBIENT_TEMP = 202    # Holding Register (x10 °C, e.g. 350 = 35.0°C)
REG_PLC_MODULE_TEMP = 203     # Holding Register (x10 °C, e.g. 520 = 52.0°C)
REG_PLC_WIND_SPEED = 204      # Holding Register (x10 m/s)
REG_PLC_STATUS = 205          # Holding Register (1: OK, 2: Warning)

# IEC 60870-5-104 Definitions
IOA_BREAKER_POINT = 1000      # Substation Grid Breaker Control Point
ASDU_M_SP_NA_1 = 1            # Single-point information
ASDU_M_ME_NC_1 = 13           # Measured value, short floating point
ASDU_M_SP_TB_1 = 30           # Single-point with CP56Time2a timestamp
ASDU_C_SC_NA_1 = 45           # Single command
ASDU_C_DC_NA_1 = 46           # Double command
ASDU_C_SE_NC_1 = 50           # Set-point command, short floating point
ASDU_C_IC_NA_1 = 100          # Interrogation command

def iso_utc_now() -> str:
    """Return formatted ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()

def calculate_solar_irradiance(sim_time_hours: float) -> tuple[float, float, float]:
    """
    Calculate realistic diurnal solar irradiance (W/m^2) and ambient/module temp.
    sim_time_hours: 0.0 to 24.0.
    Returns: (irradiance_w_m2, ambient_temp_c, module_temp_c)
    """
    # Sun rises at ~06:00, peaks at ~12:30, sets at ~18:30 (typical Gujarat solar site)
    if 6.0 <= sim_time_hours <= 18.5:
        progress = (sim_time_hours - 6.0) / (18.5 - 6.0)
        # Half-sine curve peaking around 1000 W/m^2
        raw_irr = 1020.0 * math.sin(progress * math.pi)
        noise = random.gauss(0, 15.0)
        irradiance = max(0.0, min(1200.0, raw_irr + noise))
        ambient = 24.0 + 16.0 * math.sin(progress * math.pi) + random.gauss(0, 0.5)
        module_temp = ambient + (irradiance * 0.025) + random.gauss(0, 0.8)
    else:
        # Nighttime
        irradiance = 0.0
        ambient = 22.0 + random.gauss(0, 0.4)
        module_temp = ambient

    return irradiance, ambient, module_temp
