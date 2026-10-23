"""
Milestone 1 Verification Tests: Simulation, Modbus Devices, SCADA, PPC, and IEC-104.
"""
import time
import pytest
from sim.weather import WeatherStation
from sim.plc import PlantPLC
from sim.inverters import SolarInverter, InverterCluster
from sim.ppc import PlantPowerController
from sim.scada import SCADAPoller
from sim.iec104 import IEC104Outstation, IEC104Client
from sim.vendor_gw import VendorGateway
from sim.common import (
    PORT_PLC, PORT_INVERTER_1, PORT_INVERTER_2, PORT_INVERTER_3,
    REG_ACTIVE_POWER_LIMIT, REG_ACTIVE_POWER, REG_PLC_IRRADIANCE,
    IOA_BREAKER_POINT
)

def test_weather_station():
    station = WeatherStation(start_sim_hour=12.0)
    metrics = station.read_metrics()
    assert "irradiance" in metrics
    assert "ambient_temp" in metrics
    assert metrics["irradiance"] > 500.0  # Midday solar irradiance in Gujarat

def test_plc_and_inverters_cluster():
    weather = WeatherStation(start_sim_hour=11.5)
    plc = PlantPLC(port=PORT_PLC, weather_station=weather)
    cluster = InverterCluster(weather_station=weather)

    try:
        plc.start()
        cluster.start_all()
        time.sleep(1.0)

        # Test SCADA polling
        scada = SCADAPoller()
        poll_res = scada.poll_once()
        assert poll_res["plc"]["success"] is True
        assert poll_res["inverter-1"]["success"] is True
        assert poll_res["inverter-2"]["success"] is True
        assert poll_res["inverter-3"]["success"] is True

        metrics = scada.get_metrics()
        assert metrics["success_rate_pct"] == 100.0
        assert metrics["total_polls"] == 4

        # Test PPC setpoint write
        ppc = PlantPowerController()
        ppc_res = ppc.send_approved_setpoints(target_kw=900)
        assert ppc_res["inverter-1"] is True
        assert ppc_res["inverter-2"] is True
        assert ppc_res["inverter-3"] is True

        # Test Vendor Gateway diagnostic read
        v_gw = VendorGateway(target_port=PORT_INVERTER_1)
        assert v_gw.perform_normal_maintenance_read() is True

    finally:
        plc.stop()
        cluster.stop_all()

def test_iec104_outstation_and_client():
    outstation = IEC104Outstation()
    client = IEC104Client()

    try:
        outstation.start()
        time.sleep(0.5)

        connected = client.connect()
        assert connected is True, "IEC-104 client failed to handshake with STARTDT"

        # Send Type 45 single command to breaker IOA 1000 (0 = Open)
        sent = client.send_command_type45(ioa=IOA_BREAKER_POINT, command_val=0)
        assert sent is True
        time.sleep(0.5)
        assert outstation.breaker_state == 0

        # Close breaker again (1 = Closed)
        client.send_command_type45(ioa=IOA_BREAKER_POINT, command_val=1)
        time.sleep(0.5)
        assert outstation.breaker_state == 1

    finally:
        client.close()
        outstation.stop()
