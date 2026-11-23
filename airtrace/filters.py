"""Search, filtering, and BPF validation routines."""

from typing import Optional
from airtrace.models import PacketRecord


def filter_records(
    records: list[PacketRecord],
    protocol: str = "ALL",
    search_query: str = "",
) -> list[PacketRecord]:
    """
    Non-destructive filtering of packet records for UI display.
    Does not modify underlying statistics.
    
    :param records: List of PacketRecord objects
    :param protocol: "ALL", "TCP", "UDP", "ICMP", or "OTHER"
    :param search_query: Search string to match in source/dest IP or ports
    """
    filtered = records

    # Protocol filter
    proto_clean = protocol.strip().upper()
    if proto_clean and proto_clean != "ALL":
        filtered = [r for r in filtered if r.protocol.upper() == proto_clean]

    # Search filter (case-insensitive substring match)
    query_clean = search_query.strip().lower()
    if query_clean:
        filtered = [
            r for r in filtered
            if (
                query_clean in r.source_ip.lower()
                or query_clean in r.destination_ip.lower()
                or (r.source_port is not None and query_clean in str(r.source_port))
                or (r.destination_port is not None and query_clean in str(r.destination_port))
            )
        ]

    return filtered


def validate_bpf_filter(bpf_string: str) -> tuple[bool, str]:
    """
    Validate a Berkeley Packet Filter (BPF) string.
    Returns (is_valid, error_or_success_message).
    """
    clean_bpf = bpf_string.strip()
    if not clean_bpf:
        return True, "Filter is empty (captures all traffic)."

    try:
        # Check syntax using scapy's compile_filter if available
        from scapy.arch.common import compile_filter
        compile_filter(clean_bpf)
        return True, "Valid BPF filter."
    except Exception as e:
        # Fallback heuristic checks if compile_filter fails due to missing pcap library
        common_tokens = {"ip", "tcp", "udp", "icmp", "port", "host", "src", "dst", "and", "or", "not"}
        tokens = set(clean_bpf.lower().replace("(", " ").replace(")", " ").split())
        if tokens.intersection(common_tokens):
            return True, "BPF filter syntax accepted."
        return False, f"Invalid BPF filter syntax: {e}"
