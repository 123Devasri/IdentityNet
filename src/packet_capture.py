import threading
import time
from typing import Optional

try:
    from scapy.all import sniff, AsyncSniffer
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    AsyncSniffer = None

class PacketCapturer:
    """
    Live Packet Capture Engine for IdentityNet.
    Uses Scapy AsyncSniffer to capture live network traffic on specified network interfaces.
    """
    def __init__(self, interface: str = "any", bpf_filter: str = "ip", packet_handler=None, logger=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_handler = packet_handler
        self.logger = logger
        
        self._sniffer: Optional[Any] = None
        self._running = False

    def start(self):
        """
        Start live packet capture in background thread.
        """
        if self._running:
            return

        if not SCAPY_AVAILABLE:
            if self.logger:
                self.logger.log_system("WARN", "Scapy package is not installed. Live packet capture requires 'scapy'. Run setup.sh first.")
            return

        self._running = True
        if self.logger:
            self.logger.log_system("INFO", f"Starting live packet capture on interface '{self.interface}' (BPF: '{self.bpf_filter}')...")

        try:
            # Configure Scapy AsyncSniffer
            if self.interface == "any":
                self._sniffer = AsyncSniffer(
                    filter=self.bpf_filter,
                    prn=self._on_packet,
                    store=False
                )
            else:
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._on_packet,
                    store=False
                )
            self._sniffer.start()
        except Exception as e:
            self._running = False
            if self.logger:
                self.logger.log_system("WARN", f"Failed to start packet sniffer on '{self.interface}': {e}")
                self.logger.log_system("INFO", "Make sure you run IdentityNet as root (sudo python3 src/main.py).")

    def stop(self):
        """
        Stop packet capture cleanly.
        """
        if not self._running:
            return

        self._running = False
        if self._sniffer and getattr(self._sniffer, "running", False):
            try:
                self._sniffer.stop()
            except Exception:
                pass
        
        if self.logger:
            self.logger.log_system("INFO", "Stopped packet capture engine.")

    def is_running(self) -> bool:
        return self._running

    def _on_packet(self, packet):
        """
        Internal packet callback dispatcher.
        """
        if not self._running:
            return
            
        try:
            if self.packet_handler:
                self.packet_handler(packet)
        except Exception as e:
            if self.logger:
                self.logger.log_system("WARN", f"Error processing captured packet: {e}")
