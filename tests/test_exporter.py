"""Unit tests for CSV metadata exporter."""

import csv
import pytest
from airtrace.exporter import export_to_csv, CSV_HEADERS
from airtrace.models import PacketRecord, ProtocolType


def test_export_to_csv(tmp_path):
    records = [
        PacketRecord(
            packet_number=1,
            timestamp="2026-11-23T21:15:00.123456Z",
            epoch_time=100.0,
            protocol=ProtocolType.TCP.value,
            source_ip="192.168.1.10",
            destination_ip="142.250.190.46",
            source_port=49152,
            destination_port=443,
            packet_size_bytes=64,
            ip_total_length=60,
            ttl=64,
            tcp_flags="SYN, ACK",
        ),
        PacketRecord(
            packet_number=2,
            timestamp="2026-11-23T21:15:01.654321Z",
            epoch_time=101.0,
            protocol=ProtocolType.ICMP.value,
            source_ip="192.168.1.10",
            destination_ip="1.1.1.1",
            packet_size_bytes=84,
            ttl=128,
            icmp_type=8,
            icmp_code=0,
        ),
    ]

    export_file = tmp_path / "test_capture.csv"
    result_path = export_to_csv(records, filepath=export_file)

    assert result_path.exists()

    with open(result_path, mode="r", newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 3  # Header + 2 data rows
        assert reader[0] == CSV_HEADERS

        # Verify TCP row
        tcp_row = reader[1]
        assert tcp_row[0] == "1"
        assert tcp_row[2] == "TCP"
        assert tcp_row[3] == "192.168.1.10"
        assert tcp_row[4] == "49152"
        assert tcp_row[10] == "SYN, ACK"
        assert tcp_row[11] == ""  # ICMP type should be empty for TCP

        # Verify ICMP row
        icmp_row = reader[2]
        assert icmp_row[0] == "2"
        assert icmp_row[2] == "ICMP"
        assert icmp_row[4] == ""  # Source port should be empty for ICMP
        assert icmp_row[11] == "8"
        assert icmp_row[12] == "0"
