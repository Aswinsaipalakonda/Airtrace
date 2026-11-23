"""Data models and enumerated types for Airtrace."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ProtocolType(str, Enum):
    """Protocol classification categories."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class CaptureState(str, Enum):
    """Lifecycle state machine for packet capture engine."""
    IDLE = "Idle"
    CAPTURING = "Capturing"
    STOPPING = "Stopping"
    ERROR = "Error"


@dataclass(slots=True)
class PacketRecord:
    """Normalized metadata representation of a single captured network packet."""
    packet_number: int
    timestamp: str              # ISO 8601 formatted timestamp (e.g. 2026-11-23T21:15:30.123456)
    epoch_time: float           # Numeric timestamp for rate calculations
    protocol: str               # Protocol classification: TCP, UDP, ICMP, OTHER
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_size_bytes: int = 0  # Captured wire length
    ip_total_length: Optional[int] = None
    ttl: Optional[int] = None
    ip_identification: Optional[int] = None
    ip_flags: Optional[str] = None
    fragment_offset: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_sequence: Optional[int] = None
    tcp_acknowledgment: Optional[int] = None
    tcp_window: Optional[int] = None
    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_checksum: Optional[int] = None
    icmp_id: Optional[int] = None
    icmp_seq: Optional[int] = None


@dataclass(slots=True)
class InterfaceInfo:
    """Network interface metadata."""
    name: str                   # Human-readable name (e.g. Wi-Fi, Ethernet)
    description: str            # Adapter description / chip name
    device_id: str              # Internal OS identifier or Scapy name
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    is_loopback: bool = False


@dataclass(slots=True)
class TrafficRateStats:
    """Real-time traffic rate statistics over a rolling time window."""
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    window_duration_seconds: float = 5.0


@dataclass(slots=True)
class CaptureStatisticsSnapshot:
    """Thread-safe snapshot of capture statistics for UI presentation."""
    total_packets: int = 0
    total_bytes: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    other_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    average_packet_size: float = 0.0
    top_sources: list[tuple[str, int]] = None
    top_destinations: list[tuple[str, int]] = None

    def __post_init__(self):
        if self.top_sources is None:
            self.top_sources = []
        if self.top_destinations is None:
            self.top_destinations = []
