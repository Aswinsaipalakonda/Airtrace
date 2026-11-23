"""Protocol decoder engine for IPv4, TCP, UDP, ICMP, and fallback traffic."""

from datetime import datetime, timezone
from typing import Optional
import scapy.packet
from scapy.layers.inet import IP, TCP, UDP, ICMP

from airtrace.models import PacketRecord, ProtocolType

# Flag mapping for TCP header flags
_TCP_FLAGS_MAP = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


def format_tcp_flags(flags_val) -> Optional[str]:
    """Format numeric or string TCP flags into a clear, comma-separated string."""
    if flags_val is None:
        return None

    # Scapy flags can be int or FlagValue object
    try:
        numeric_val = int(flags_val)
    except (ValueError, TypeError):
        return str(flags_val)

    active_flags = [name for mask, name in _TCP_FLAGS_MAP if numeric_val & mask]
    return ", ".join(active_flags) if active_flags else "None"


def format_ip_flags(ip_layer: IP) -> Optional[str]:
    """Extract and format IPv4 fragmentation flags."""
    flags = []
    if ip_layer.flags is not None:
        try:
            val = int(ip_layer.flags)
            if val & 0x02:
                flags.append("DF")
            if val & 0x01:
                flags.append("MF")
        except (ValueError, TypeError):
            flags.append(str(ip_layer.flags))
    return ", ".join(flags) if flags else "None"


def decode_packet(scapy_pkt: scapy.packet.Packet, packet_number: int) -> Optional[PacketRecord]:
    """
    Decode a raw Scapy packet into a normalized PacketRecord.
    
    Classification order:
    1. Only IPv4 packets are currently processed (returns None for non-IPv4 frames).
    2. TCP (if TCP layer present)
    3. UDP (if UDP layer present)
    4. ICMP (if ICMP layer present)
    5. OTHER (IPv4 packets with other transport protocols like IGMP, GRE, ESP)
    """
    if scapy_pkt is None or not scapy_pkt.haslayer(IP):
        return None

    ip_layer: IP = scapy_pkt.getlayer(IP)
    epoch_time = float(getattr(scapy_pkt, "time", datetime.now().timestamp()))
    dt = datetime.fromtimestamp(epoch_time, tz=timezone.utc)
    timestamp_str = dt.isoformat(timespec="microseconds")

    wire_length = len(scapy_pkt)
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    ttl = int(ip_layer.ttl) if ip_layer.ttl is not None else None
    ip_proto = int(ip_layer.proto) if ip_layer.proto is not None else None
    ip_len = int(ip_layer.len) if ip_layer.len is not None else None
    ip_id = int(ip_layer.id) if ip_layer.id is not None else None
    ip_flags = format_ip_flags(ip_layer)
    frag_offset = int(ip_layer.frag) if ip_layer.frag is not None else None

    # Classification
    if scapy_pkt.haslayer(TCP):
        tcp_layer: TCP = scapy_pkt.getlayer(TCP)
        return PacketRecord(
            packet_number=packet_number,
            timestamp=timestamp_str,
            epoch_time=epoch_time,
            protocol=ProtocolType.TCP.value,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=int(tcp_layer.sport),
            destination_port=int(tcp_layer.dport),
            packet_size_bytes=wire_length,
            ip_total_length=ip_len,
            ttl=ttl,
            ip_identification=ip_id,
            ip_flags=ip_flags,
            fragment_offset=frag_offset,
            tcp_flags=format_tcp_flags(tcp_layer.flags),
            tcp_sequence=int(tcp_layer.seq),
            tcp_acknowledgment=int(tcp_layer.ack) if tcp_layer.ack is not None else None,
            tcp_window=int(tcp_layer.window) if tcp_layer.window is not None else None,
        )

    if scapy_pkt.haslayer(UDP):
        udp_layer: UDP = scapy_pkt.getlayer(UDP)
        udp_len = int(udp_layer.len) if udp_layer.len is not None else len(udp_layer)
        return PacketRecord(
            packet_number=packet_number,
            timestamp=timestamp_str,
            epoch_time=epoch_time,
            protocol=ProtocolType.UDP.value,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=int(udp_layer.sport),
            destination_port=int(udp_layer.dport),
            packet_size_bytes=wire_length,
            ip_total_length=ip_len,
            ttl=ttl,
            ip_identification=ip_id,
            ip_flags=ip_flags,
            fragment_offset=frag_offset,
            udp_length=udp_len,
            udp_checksum=int(udp_layer.chksum) if udp_layer.chksum is not None else None,
        )

    if scapy_pkt.haslayer(ICMP):
        icmp_layer: ICMP = scapy_pkt.getlayer(ICMP)
        icmp_id = getattr(icmp_layer, "id", None)
        icmp_seq = getattr(icmp_layer, "seq", None)
        return PacketRecord(
            packet_number=packet_number,
            timestamp=timestamp_str,
            epoch_time=epoch_time,
            protocol=ProtocolType.ICMP.value,
            source_ip=src_ip,
            destination_ip=dst_ip,
            packet_size_bytes=wire_length,
            ip_total_length=ip_len,
            ttl=ttl,
            ip_identification=ip_id,
            ip_flags=ip_flags,
            fragment_offset=frag_offset,
            icmp_type=int(icmp_layer.type) if icmp_layer.type is not None else None,
            icmp_code=int(icmp_layer.code) if icmp_layer.code is not None else None,
            icmp_checksum=int(icmp_layer.chksum) if icmp_layer.chksum is not None else None,
            icmp_id=int(icmp_id) if icmp_id is not None else None,
            icmp_seq=int(icmp_seq) if icmp_seq is not None else None,
        )

    # IPv4 OTHER
    return PacketRecord(
        packet_number=packet_number,
        timestamp=timestamp_str,
        epoch_time=epoch_time,
        protocol=ProtocolType.OTHER.value,
        source_ip=src_ip,
        destination_ip=dst_ip,
        packet_size_bytes=wire_length,
        ip_total_length=ip_len,
        ttl=ttl,
        ip_identification=ip_id,
        ip_flags=ip_flags,
        fragment_offset=frag_offset,
    )
