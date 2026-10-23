"""
Passive Packet Capture and Ingestion Engine for Solar Park Watchman.
Guarantees:
- Zero transmission on the monitored network segment (listen-only SPAN/mirror tap).
- Modular ingestion from live network interfaces, virtual loopbacks, or raw PCAP files.
- Dispatches normalized events directly to downstream detection components.
"""
import time
import threading
import logging
from typing import Optional, Callable
from scapy.all import sniff, rdpcap, Packet, IP, TCP, ARP, ICMP
from sensor.normaliser import EventNormaliser

logger = logging.getLogger("capture")

class PassiveSensorCapture:
    def __init__(self, interface: str = "any", on_event_callback: Optional[Callable] = None):
        self.interface = interface
        self.on_event = on_event_callback
        self.running = False
        self._thread = None
        self.total_packets_captured = 0

    def process_packet(self, pkt: Packet) -> Optional[dict]:
        """Process a single intercepted Scapy packet and normalize it."""
        self.total_packets_captured += 1
        src_ip = None
        dst_ip = None
        src_mac = pkt.src if hasattr(pkt, "src") else "00:00:00:00:00:00"
        dst_mac = pkt.dst if hasattr(pkt, "dst") else "00:00:00:00:00:00"
        epoch = float(pkt.time) if hasattr(pkt, "time") else time.time()

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            event = EventNormaliser.normalise(
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                protocol="ARP",
                payload=b"",
                src_mac=arp.hwsrc,
                dst_mac=arp.hwdst,
                timestamp=epoch
            )
            if event and self.on_event:
                self.on_event(event)
            return event

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(ICMP):
                event = EventNormaliser.normalise(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="ICMP",
                    payload=b"",
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    timestamp=epoch
                )
                if event and self.on_event:
                    self.on_event(event)
                return event

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                payload = bytes(tcp.payload)
                if not payload:
                    return None

                dst_port = tcp.dport
                src_port = tcp.sport

                # Determine protocol by port or payload heuristics
                proto = "RAW_TCP"
                target_port = dst_port
                if dst_port in (502, 5020, 5021, 5022, 5023) or src_port in (502, 5020, 5021, 5022, 5023):
                    proto = "MODBUS_TCP"
                    target_port = 502
                elif dst_port == 2404 or src_port == 2404:
                    proto = "IEC_104"
                    target_port = 2404

                event = EventNormaliser.normalise(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto,
                    payload=payload,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    timestamp=epoch,
                    dst_port=target_port
                )

                if event and self.on_event:
                    self.on_event(event)
                return event

        return None

    def ingest_pcap(self, pcap_path: str):
        """Offline ingestion and processing of a PCAP file."""
        packets = rdpcap(pcap_path)
        events = []
        for pkt in packets:
            evt = self.process_packet(pkt)
            if evt:
                events.append(evt)
        return events

    def start_live(self):
        """Start live promiscuous sniffing in background thread."""
        self.running = True
        def _sniff_worker():
            try:
                sniff(
                    iface=None if self.interface in ("any", "") else self.interface,
                    prn=self.process_packet,
                    stop_filter=lambda p: not self.running,
                    store=0
                )
            except Exception as e:
                logger.error(f"Sniffer terminated: {e}")

        self._thread = threading.Thread(target=_sniff_worker, daemon=True, name="PassiveSensorSniffer")
        self._thread.start()

    def stop(self):
        self.running = False
