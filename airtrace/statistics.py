"""Statistics aggregation and rolling rate calculation engine."""

import threading
import time
from collections import Counter, deque
from typing import Optional

from airtrace.config import MAX_PACKETS_HISTORY, RATE_WINDOW_SECONDS
from airtrace.models import CaptureStatisticsSnapshot, PacketRecord, ProtocolType


class StatisticsEngine:
    """
    Thread-safe real-time statistics aggregator.
    Maintains total counters, a sliding time-window for PPS/BPS rate calculation,
    top talker IP counters, and a bounded ring buffer of recent packet records.
    """

    def __init__(
        self,
        max_history: int = MAX_PACKETS_HISTORY,
        rate_window_seconds: float = RATE_WINDOW_SECONDS,
    ):
        self._lock = threading.RLock()
        self._max_history = max_history
        self._rate_window_seconds = rate_window_seconds

        # Counters
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counts: Counter[str] = Counter()
        self._top_sources: Counter[str] = Counter()
        self._top_destinations: Counter[str] = Counter()

        # Rolling rate window: entries of (epoch_time, bytes)
        self._rate_window: deque[tuple[float, int]] = deque()

        # Bounded packet history
        self._history: deque[PacketRecord] = deque(maxlen=self._max_history)

    def add_packet(self, record: PacketRecord):
        """Thread-safely ingest a single decoded PacketRecord."""
        with self._lock:
            self._total_packets += 1
            self._total_bytes += record.packet_size_bytes

            self._protocol_counts[record.protocol] += 1
            if record.source_ip:
                self._top_sources[record.source_ip] += 1
            if record.destination_ip:
                self._top_destinations[record.destination_ip] += 1

            now = time.monotonic()
            self._rate_window.append((now, record.packet_size_bytes))
            self._prune_rate_window(now)

            self._history.append(record)

    def add_packets(self, records: list[PacketRecord]):
        """Batch-ingest packet records."""
        with self._lock:
            now = time.monotonic()
            for record in records:
                self._total_packets += 1
                self._total_bytes += record.packet_size_bytes
                self._protocol_counts[record.protocol] += 1
                if record.source_ip:
                    self._top_sources[record.source_ip] += 1
                if record.destination_ip:
                    self._top_destinations[record.destination_ip] += 1
                self._rate_window.append((now, record.packet_size_bytes))
                self._history.append(record)
            self._prune_rate_window(now)

    def _prune_rate_window(self, now: float):
        """Evict rate window samples older than rate_window_seconds."""
        cutoff = now - self._rate_window_seconds
        while self._rate_window and self._rate_window[0][0] < cutoff:
            self._rate_window.popleft()

    def get_snapshot(self) -> CaptureStatisticsSnapshot:
        """Return an immutable snapshot of all computed metrics for UI display."""
        with self._lock:
            now = time.monotonic()
            self._prune_rate_window(now)

            # Compute rolling rates
            window_len = len(self._rate_window)
            if window_len > 1:
                oldest_time = self._rate_window[0][0]
                elapsed = max(now - oldest_time, 0.001)
                window_bytes = sum(b for _, b in self._rate_window)
                pps = window_len / elapsed
                bps = window_bytes / elapsed
            elif window_len == 1:
                pps = 1.0
                bps = float(self._rate_window[0][1])
            else:
                pps = 0.0
                bps = 0.0

            avg_size = (
                self._total_bytes / self._total_packets
                if self._total_packets > 0
                else 0.0
            )

            return CaptureStatisticsSnapshot(
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                tcp_count=self._protocol_counts.get(ProtocolType.TCP.value, 0),
                udp_count=self._protocol_counts.get(ProtocolType.UDP.value, 0),
                icmp_count=self._protocol_counts.get(ProtocolType.ICMP.value, 0),
                other_count=self._protocol_counts.get(ProtocolType.OTHER.value, 0),
                packets_per_second=pps,
                bytes_per_second=bps,
                average_packet_size=avg_size,
                top_sources=self._top_sources.most_common(5),
                top_destinations=self._top_destinations.most_common(5),
            )

    def get_history(self) -> list[PacketRecord]:
        """Return a copy of all retained packet records in history."""
        with self._lock:
            return list(self._history)

    def reset(self):
        """Reset all statistical counters and purge packet history."""
        with self._lock:
            self._total_packets = 0
            self._total_bytes = 0
            self._protocol_counts.clear()
            self._top_sources.clear()
            self._top_destinations.clear()
            self._rate_window.clear()
            self._history.clear()
