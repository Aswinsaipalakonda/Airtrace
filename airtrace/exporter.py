"""Metadata CSV export service."""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from airtrace.config import CAPTURES_DIR
from airtrace.models import PacketRecord

CSV_HEADERS = [
    "packet_number",
    "timestamp",
    "protocol",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "packet_size_bytes",
    "ip_total_length",
    "ttl",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
]


def export_to_csv(
    records: list[PacketRecord],
    filepath: Optional[Path] = None,
) -> Path:
    """
    Export packet metadata to a CSV file.
    Does NOT include packet payloads or application data.
    
    :param records: Sequence of PacketRecord instances
    :param filepath: Optional explicit output path; defaults to timestamped file in captures/
    :return: Path to generated CSV file
    """
    if filepath is None:
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = CAPTURES_DIR / f"airtrace_capture_{now_str}.csv"
    else:
        filepath = Path(filepath)

    filepath.parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(CSV_HEADERS)

        for r in records:
            writer.writerow([
                r.packet_number,
                r.timestamp,
                r.protocol,
                r.source_ip,
                r.source_port if r.source_port is not None else "",
                r.destination_ip,
                r.destination_port if r.destination_port is not None else "",
                r.packet_size_bytes,
                r.ip_total_length if r.ip_total_length is not None else "",
                r.ttl if r.ttl is not None else "",
                r.tcp_flags if r.tcp_flags is not None else "",
                r.icmp_type if r.icmp_type is not None else "",
                r.icmp_code if r.icmp_code is not None else "",
            ])

    return filepath
