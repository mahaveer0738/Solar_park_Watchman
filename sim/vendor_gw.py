"""
Vendor Remote Support Gateway simulation.
Vendor gateway is a known device (10.10.1.50) with an approved maintenance window
(10:00 - 16:00). In normal operation it performs only health/diagnostic reads.
"""
import time
import logging
from pymodbus.client import ModbusTcpClient
from sim.common import (
    PORT_INVERTER_1, REG_FIRMWARE_VER, REG_ACTIVE_POWER_LIMIT,
    IP_VENDOR_GW
)

logger = logging.getLogger("vendor_gw")

class VendorGateway:
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = PORT_INVERTER_1):
        self.target_host = target_host
        self.target_port = target_port

    def perform_normal_maintenance_read(self) -> bool:
        """Perform legitimate diagnostic read of firmware and status."""
        try:
            client = ModbusTcpClient(self.target_host, port=self.target_port, timeout=2.0)
            if client.connect():
                res = client.read_holding_registers(REG_FIRMWARE_VER, count=1)
                client.close()
                return not res.isError()
        except Exception:
            pass
        return False

    def perform_unauthorized_write(self, register: int = REG_ACTIVE_POWER_LIMIT, value: int = 500) -> bool:
        """Attempt a write (violates policy if outside maintenance window)."""
        try:
            client = ModbusTcpClient(self.target_host, port=self.target_port, timeout=2.0)
            if client.connect():
                res = client.write_register(register, value)
                client.close()
                return not res.isError()
        except Exception:
            pass
        return False
