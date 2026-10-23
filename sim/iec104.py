"""
Pure-Python IEC 60870-5-104 Outstation and Master.
Implements:
- Standard APDU Framing (0x68 <len> <4 control bytes>)
- U-Format (STARTDT, STOPDT, TESTFR)
- S-Format (Supervisory)
- I-Format with ASDU:
  - Type 1: M_SP_NA_1 (Single Point Information)
  - Type 13: M_ME_NC_1 (Measured Value Short Float)
  - Type 45: C_SC_NA_1 (Single Command)
  - Type 46: C_DC_NA_1 (Double Command)
  - Type 50: C_SE_NC_1 (Setpoint Command Float)
  - Type 100: C_IC_NA_1 (General Interrogation)
- Information Object Address (IOA) 1000: Substation Breaker Point
"""
import socket
import struct
import threading
import time
import logging
from typing import Optional, Callable
from sim.common import (
    PORT_IEC104, IOA_BREAKER_POINT,
    ASDU_M_SP_NA_1, ASDU_M_ME_NC_1, ASDU_C_SC_NA_1,
    ASDU_C_DC_NA_1, ASDU_C_SE_NC_1, ASDU_C_IC_NA_1
)

logger = logging.getLogger("iec104")

def build_apdu_u(u_type: str) -> bytes:
    """Build U-format APDU (STARTDT, TESTFR, etc.)."""
    u_map = {
        "STARTDT_ACT": b"\x07\x00\x00\x00",
        "STARTDT_CON": b"\x0b\x00\x00\x00",
        "STOPDT_ACT":  b"\x13\x00\x00\x00",
        "STOPDT_CON":  b"\x23\x00\x00\x00",
        "TESTFR_ACT":  b"\x43\x00\x00\x00",
        "TESTFR_CON":  b"\x83\x00\x00\x00",
    }
    ctrl = u_map[u_type]
    return b"\x68\x04" + ctrl

def build_apdu_s(rx_seq: int) -> bytes:
    """Build S-format APDU."""
    ctrl = struct.pack("<HH", 0x01, (rx_seq & 0x7FFF) << 1)
    return b"\x68\x04" + ctrl

def build_apdu_i(tx_seq: int, rx_seq: int, asdu_payload: bytes) -> bytes:
    """Build I-format APDU carrying ASDU payload."""
    ctrl = struct.pack("<HH", (tx_seq & 0x7FFF) << 1, (rx_seq & 0x7FFF) << 1)
    length = 4 + len(asdu_payload)
    return b"\x68" + struct.pack("B", length) + ctrl + asdu_payload

def build_asdu_type1(ioa: int, val: int, cot: int = 3, ca: int = 1) -> bytes:
    """ASDU Type 1: Single-point information M_SP_NA_1."""
    header = struct.pack("BBHH", ASDU_M_SP_NA_1, 1, cot, ca)
    ioa_bytes = struct.pack("<I", ioa)[:3]
    siq = struct.pack("B", 1 if val else 0)
    return header + ioa_bytes + siq

def build_asdu_type13(ioa: int, val_float: float, cot: int = 3, ca: int = 1) -> bytes:
    """ASDU Type 13: Measured value, short floating point M_ME_NC_1."""
    header = struct.pack("BBHH", ASDU_M_ME_NC_1, 1, cot, ca)
    ioa_bytes = struct.pack("<I", ioa)[:3]
    val_bytes = struct.pack("<fB", val_float, 0)
    return header + ioa_bytes + val_bytes

def build_asdu_type45(ioa: int, command_state: int, cot: int = 6, ca: int = 1) -> bytes:
    """ASDU Type 45: Single command C_SC_NA_1."""
    header = struct.pack("BBHH", ASDU_C_SC_NA_1, 1, cot, ca)
    ioa_bytes = struct.pack("<I", ioa)[:3]
    sco = struct.pack("B", 1 if command_state else 0)
    return header + ioa_bytes + sco

def build_asdu_type46(ioa: int, double_command_state: int, cot: int = 6, ca: int = 1) -> bytes:
    """ASDU Type 46: Double command C_DC_NA_1 (1=OFF/Open, 2=ON/Close)."""
    header = struct.pack("BBHH", ASDU_C_DC_NA_1, 1, cot, ca)
    ioa_bytes = struct.pack("<I", ioa)[:3]
    dco = struct.pack("B", double_command_state)
    return header + ioa_bytes + dco


class IEC104Outstation:
    """Simulated IEC 60870-5-104 Outstation (Substation RTU)."""
    def __init__(self, host: str = "0.0.0.0", port: int = PORT_IEC104):
        self.host = host
        self.port = port
        self.running = False
        self.breaker_state = 1  # 1 = Closed, 0 = Open
        self.active_power_mw = 2.85
        self.total_packets_received = 0
        self.on_command_callback: Optional[Callable] = None
        self._server_sock = None
        self._clients = []
        self._lock = threading.Lock()

    def start(self):
        self.running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(10)
        self._server_sock.settimeout(0.5)

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True, name="IEC104-Accept")
        self._accept_thread.start()

        self._telemetry_thread = threading.Thread(target=self._telemetry_loop, daemon=True, name="IEC104-Telemetry")
        self._telemetry_thread.start()

    def stop(self):
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        with self._lock:
            for c in self._clients:
                try:
                    c.close()
                except Exception:
                    pass
            self._clients.clear()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self._server_sock.accept()
                with self._lock:
                    self._clients.append(client_sock)
                t = threading.Thread(target=self._client_handler, args=(client_sock, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    time.sleep(0.1)

    def _client_handler(self, client_sock: socket.socket, addr):
        tx_seq = 0
        rx_seq = 0
        data_started = False

        while self.running:
            try:
                header = client_sock.recv(2)
                if not header or len(header) < 2:
                    break
                if header[0] != 0x68:
                    continue

                length = header[1]
                payload = b""
                while len(payload) < length:
                    chunk = client_sock.recv(length - len(payload))
                    if not chunk:
                        break
                    payload += chunk

                if len(payload) < length:
                    break

                with self._lock:
                    self.total_packets_received += 1

                ctrl0 = payload[0]

                # U-format
                if (ctrl0 & 0x03) == 0x03:
                    if ctrl0 == 0x07:  # STARTDT_ACT
                        data_started = True
                        client_sock.sendall(build_apdu_u("STARTDT_CON"))
                    elif ctrl0 == 0x43:  # TESTFR_ACT
                        client_sock.sendall(build_apdu_u("TESTFR_CON"))
                # S-format
                elif (ctrl0 & 0x03) == 0x01:
                    pass
                # I-format
                elif (ctrl0 & 0x01) == 0x00:
                    rx_seq += 1
                    client_sock.sendall(build_apdu_s(rx_seq))
                    asdu = payload[4:]
                    if len(asdu) >= 6:
                        type_id = asdu[0]
                        cot = struct.unpack("<H", asdu[2:4])[0]
                        ca = struct.unpack("<H", asdu[4:6])[0]
                        ioa = struct.unpack("<I", asdu[6:9] + b"\x00")[0] if len(asdu) >= 9 else 0

                        # Type 45 Single Command / Type 46 Double Command
                        if type_id in (ASDU_C_SC_NA_1, ASDU_C_DC_NA_1):
                            cmd_val = asdu[9] if len(asdu) > 9 else 0
                            if ioa == IOA_BREAKER_POINT:
                                self.breaker_state = 1 if (cmd_val in (1, 2)) else 0
                            if self.on_command_callback:
                                self.on_command_callback(addr[0], type_id, ioa, cmd_val)
                            # Activation Confirmation (COT 7)
                            conf_asdu = struct.pack("BBHH", type_id, 1, 7, ca) + asdu[6:]
                            client_sock.sendall(build_apdu_i(tx_seq, rx_seq, conf_asdu))
                            tx_seq += 1

                        elif type_id == ASDU_C_IC_NA_1:
                            # Interrogation activation confirmation
                            act_conf = struct.pack("BBHH", ASDU_C_IC_NA_1, 1, 7, ca) + asdu[6:]
                            client_sock.sendall(build_apdu_i(tx_seq, rx_seq, act_conf))
                            tx_seq += 1
                            # Send breaker point
                            t1 = build_asdu_type1(IOA_BREAKER_POINT, self.breaker_state, cot=20, ca=ca)
                            client_sock.sendall(build_apdu_i(tx_seq, rx_seq, t1))
                            tx_seq += 1
                            # Interrogation termination (COT 10)
                            act_term = struct.pack("BBHH", ASDU_C_IC_NA_1, 1, 10, ca) + asdu[6:]
                            client_sock.sendall(build_apdu_i(tx_seq, rx_seq, act_term))
                            tx_seq += 1

            except Exception:
                break

        with self._lock:
            if client_sock in self._clients:
                self._clients.remove(client_sock)
        try:
            client_sock.close()
        except Exception:
            pass

    def _telemetry_loop(self):
        tx_seq = 0
        while self.running:
            time.sleep(2.0)
            with self._lock:
                active_clients = list(self._clients)

            if not active_clients:
                continue

            # Periodic spontaneous telemetry
            asdu_power = build_asdu_type13(1001, self.active_power_mw, cot=3, ca=1)
            frame_power = build_apdu_i(tx_seq, 0, asdu_power)
            tx_seq += 1

            asdu_breaker = build_asdu_type1(IOA_BREAKER_POINT, self.breaker_state, cot=3, ca=1)
            frame_breaker = build_apdu_i(tx_seq, 0, asdu_breaker)
            tx_seq += 1

            for sock in active_clients:
                try:
                    sock.sendall(frame_power + frame_breaker)
                except Exception:
                    pass


class IEC104Client:
    """Client for connecting to IEC-104 Outstation."""
    def __init__(self, host: str = "127.0.0.1", port: int = PORT_IEC104):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.tx_seq = 0
        self.rx_seq = 0

    def connect(self, timeout: float = 3.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((self.host, self.port))
        # Send STARTDT_ACT
        self.sock.sendall(build_apdu_u("STARTDT_ACT"))
        resp = self.sock.recv(6)
        return resp == build_apdu_u("STARTDT_CON")

    def send_command_type45(self, ioa: int = IOA_BREAKER_POINT, command_val: int = 1) -> bool:
        """Send Single Command Type 45 to target IOA."""
        if not self.sock:
            return False
        asdu = build_asdu_type45(ioa, command_val, cot=6, ca=1)
        apdu = build_apdu_i(self.tx_seq, self.rx_seq, asdu)
        self.tx_seq += 1
        self.sock.sendall(apdu)
        return True

    def send_command_type46(self, ioa: int = IOA_BREAKER_POINT, double_cmd_val: int = 1) -> bool:
        """Send Double Command Type 46 to target IOA."""
        if not self.sock:
            return False
        asdu = build_asdu_type46(ioa, double_cmd_val, cot=6, ca=1)
        apdu = build_apdu_i(self.tx_seq, self.rx_seq, asdu)
        self.tx_seq += 1
        self.sock.sendall(apdu)
        return True

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
