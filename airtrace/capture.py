"""Packet capture lifecycle manager and worker threads.

Implements the Sliced Sniffing Pattern to guarantee clean, non-blocking stops,
and uses an idempotent CaptureController singleton with atomic locks to prevent
duplicate background workers during Streamlit UI reruns.
"""

import logging
import queue
import random
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from airtrace.config import (
    QUEUE_MAX_SIZE,
    SLICED_SNIFF_TIMEOUT,
)
from airtrace.decoder import decode_packet
from airtrace.interfaces import DEMO_INTERFACE_ID
from airtrace.models import CaptureState, PacketRecord

logger = logging.getLogger(__name__)


class CaptureWorker:
    """Background worker executing the capture loop."""

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        stop_event: threading.Event,
        bpf_filter: Optional[str] = None,
        packet_limit: Optional[int] = None,
        duration_limit: Optional[float] = None,
    ):
        self.interface = interface
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.bpf_filter = bpf_filter.strip() if bpf_filter else ""
        self.packet_limit = packet_limit
        self.duration_limit = duration_limit
        self.packet_counter = 0
        self.start_time = time.monotonic()
        self.error: Optional[str] = None

    def run(self):
        """Worker loop entry point."""
        logger.info(f"Capture worker starting on interface: {self.interface}")
        if self.interface == DEMO_INTERFACE_ID:
            self._run_synthetic_simulation()
        else:
            self._run_live_sniff()

    def _process_scapy_packet(self, pkt):
        """Callback for incoming raw packets."""
        if self.stop_event.is_set():
            return

        self.packet_counter += 1
        record = decode_packet(pkt, self.packet_counter)
        if record is not None:
            try:
                self.packet_queue.put_nowait(record)
            except queue.Full:
                pass  # Queue bounded to prevent memory saturation

        if self.packet_limit and self.packet_counter >= self.packet_limit:
            self.stop_event.set()

    def _run_live_sniff(self):
        """Live capture loop using sliced sniffing to ensure clean, responsive stopping."""
        while not self.stop_event.is_set():
            # Check duration limit
            if self.duration_limit and (time.monotonic() - self.start_time) >= self.duration_limit:
                self.stop_event.set()
                break

            try:
                # Sliced sniff with small timeout ensures stop_event is checked regularly
                # even if no packets are received on the wire.
                sniff(
                    iface=self.interface,
                    prn=self._process_scapy_packet,
                    store=False,
                    timeout=SLICED_SNIFF_TIMEOUT,
                    filter=self.bpf_filter or "",
                )
            except Exception as e:
                self.error = f"Capture error on interface '{self.interface}': {e}"
                logger.error(self.error)
                self.stop_event.set()
                break

    def _run_synthetic_simulation(self):
        """Synthetic packet generator for offline testing, demos, and systems without Npcap."""
        # Simulated endpoints
        endpoints = [
            ("192.168.1.100", "93.184.216.34", 443, "TCP", "SA"),       # HTTPS
            ("192.168.1.100", "1.1.1.1", 53, "UDP", None),              # Cloudflare DNS
            ("192.168.1.100", "8.8.8.8", 53, "UDP", None),              # Google DNS
            ("192.168.1.100", "142.250.190.46", 443, "TCP", "PA"),      # Google HTTPS
            ("192.168.1.100", "151.101.65.140", 80, "TCP", "A"),        # Reddit HTTP
            ("192.168.1.100", "1.1.1.1", None, "ICMP", None),           # Ping
            ("192.168.1.100", "224.0.0.22", None, "OTHER", None),        # IGMP
        ]

        # Use explicit MACs to prevent Scapy from attempting layer-2 ARP/getmacbyip lookups without WinPcap
        default_ether = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

        while not self.stop_event.is_set():
            if self.duration_limit and (time.monotonic() - self.start_time) >= self.duration_limit:
                self.stop_event.set()
                break

            # Generate 1 to 4 packets per burst
            burst_size = random.randint(1, 4)
            for _ in range(burst_size):
                if self.stop_event.is_set():
                    break

                src, dst, dport, proto, flags = random.choice(endpoints)

                if proto == "TCP":
                    sport = random.randint(49152, 65535)
                    pkt = default_ether / IP(src=src, dst=dst, ttl=random.choice([64, 128])) / TCP(
                        sport=sport, dport=dport, flags=flags or "PA", seq=random.randint(1000, 90000)
                    )
                elif proto == "UDP":
                    sport = random.randint(49152, 65535)
                    pkt = default_ether / IP(src=src, dst=dst, ttl=random.choice([64, 128])) / UDP(
                        sport=sport, dport=dport
                    )
                elif proto == "ICMP":
                    pkt = default_ether / IP(src=src, dst=dst, ttl=64) / ICMP(type=8, code=0, id=1, seq=random.randint(1, 100))
                else:
                    pkt = default_ether / IP(src=src, dst=dst, proto=2, ttl=1)

                self._process_scapy_packet(pkt)

            # Sleep briefly to simulate normal traffic pace (100ms - 250ms)
            time.sleep(random.uniform(0.1, 0.25))


class CaptureController:
    """
    Singleton capture lifecycle controller.
    Protects against duplicate worker spawning across Streamlit UI reruns using atomic re-entrancy locks.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._worker: Optional[CaptureWorker] = None
        self._queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)
        self._state: CaptureState = CaptureState.IDLE
        self._selected_interface: Optional[str] = None
        self._start_monotonic: float = 0.0
        self._error_message: Optional[str] = None

    @property
    def state(self) -> CaptureState:
        with self._lock:
            return self._state

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._state == CaptureState.CAPTURING

    @property
    def selected_interface(self) -> Optional[str]:
        with self._lock:
            return self._selected_interface

    @property
    def error_message(self) -> Optional[str]:
        with self._lock:
            return self._error_message

    def get_elapsed_seconds(self) -> float:
        with self._lock:
            if self._state == CaptureState.CAPTURING:
                return time.monotonic() - self._start_monotonic
            return 0.0

    def start_capture(
        self,
        interface: str,
        bpf_filter: Optional[str] = None,
        packet_limit: Optional[int] = None,
        duration_limit: Optional[float] = None,
    ) -> bool:
        """
        Atomically initiate packet capture.
        Idempotent: If capture is already active, this is a safe no-op.
        """
        with self._lock:
            if self._state == CaptureState.CAPTURING:
                logger.warning("Capture already in progress. Ignoring duplicate start request.")
                return False

            self._selected_interface = interface
            self._error_message = None
            self._stop_event.clear()

            # Empty any lingering items in the queue
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break

            self._worker = CaptureWorker(
                interface=interface,
                packet_queue=self._queue,
                stop_event=self._stop_event,
                bpf_filter=bpf_filter,
                packet_limit=packet_limit,
                duration_limit=duration_limit,
            )

            self._worker_thread = threading.Thread(
                target=self._run_worker_wrapper,
                name="AirtraceCaptureWorker",
                daemon=True,
            )
            self._state = CaptureState.CAPTURING
            self._start_monotonic = time.monotonic()
            self._worker_thread.start()
            logger.info(f"Capture successfully started on {interface}.")
            return True

    def _run_worker_wrapper(self):
        """Wrapper to monitor worker termination and update state."""
        try:
            self._worker.run()
        except Exception as e:
            logger.error(f"Worker uncaught exception: {e}")
            with self._lock:
                self._error_message = str(e)
                self._state = CaptureState.ERROR
        finally:
            with self._lock:
                if self._worker and self._worker.error:
                    self._error_message = self._worker.error
                    self._state = CaptureState.ERROR
                elif self._state == CaptureState.CAPTURING or self._state == CaptureState.STOPPING:
                    self._state = CaptureState.IDLE

    def stop_capture(self, timeout: float = 2.0) -> bool:
        """
        Atomically stop active packet capture.
        Signals stop_event and joins the worker thread cleanly.
        """
        with self._lock:
            if self._state != CaptureState.CAPTURING:
                return True

            self._state = CaptureState.STOPPING
            self._stop_event.set()

        # Join outside the lock to prevent deadlock
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

        with self._lock:
            self._state = CaptureState.IDLE
            logger.info("Capture cleanly stopped.")
            return True

    def drain_packets(self, max_count: int = 500) -> list[PacketRecord]:
        """
        Drain decoded packets from the thread-safe queue.
        Safely callable from UI refresh cycles.
        """
        records: list[PacketRecord] = []
        count = 0
        while count < max_count and not self._queue.empty():
            try:
                record = self._queue.get_nowait()
                records.append(record)
                count += 1
            except queue.Empty:
                break
        return records
