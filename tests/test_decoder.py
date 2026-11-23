"""Unit tests for the protocol decoder engine."""

import pytest
from airtrace.decoder import decode_packet, format_tcp_flags, format_ip_flags
from airtrace.models import ProtocolType


def test_decode_tcp_packet(synthetic_tcp_packet):
    record = decode_packet(synthetic_tcp_packet, packet_number=1)
    assert record is not None
    assert record.packet_number == 1
    assert record.protocol == ProtocolType.TCP.value
    assert record.source_ip == "192.168.1.100"
    assert record.destination_ip == "93.184.216.34"
    assert record.source_port == 54321
    assert record.destination_port == 443
    assert record.ttl == 64
    assert record.ip_identification == 1024
    assert record.ip_flags == "DF"
    assert "SYN" in record.tcp_flags
    assert "ACK" in record.tcp_flags
    assert record.tcp_sequence == 1000
    assert record.tcp_acknowledgment == 2000
    assert record.tcp_window == 65535
    assert record.packet_size_bytes > 0


def test_decode_udp_packet(synthetic_udp_packet):
    record = decode_packet(synthetic_udp_packet, packet_number=2)
    assert record is not None
    assert record.packet_number == 2
    assert record.protocol == ProtocolType.UDP.value
    assert record.source_ip == "10.0.0.1"
    assert record.destination_ip == "1.1.1.1"
    assert record.source_port == 61234
    assert record.destination_port == 53
    assert record.ttl == 128
    assert record.udp_length is not None
    assert record.tcp_flags is None


def test_decode_icmp_packet(synthetic_icmp_packet):
    record = decode_packet(synthetic_icmp_packet, packet_number=3)
    assert record is not None
    assert record.packet_number == 3
    assert record.protocol == ProtocolType.ICMP.value
    assert record.source_ip == "192.168.1.1"
    assert record.destination_ip == "8.8.8.8"
    assert record.icmp_type == 8
    assert record.icmp_code == 0
    assert record.icmp_id == 123
    assert record.icmp_seq == 1
    assert record.source_port is None
    assert record.destination_port is None


def test_decode_other_packet(synthetic_other_packet):
    record = decode_packet(synthetic_other_packet, packet_number=4)
    assert record is not None
    assert record.packet_number == 4
    assert record.protocol == ProtocolType.OTHER.value
    assert record.source_ip == "192.168.1.50"
    assert record.destination_ip == "224.0.0.1"
    assert record.source_port is None
    assert record.destination_port is None


def test_decode_non_ip_packet_returns_none(synthetic_non_ip_packet):
    record = decode_packet(synthetic_non_ip_packet, packet_number=5)
    assert record is None


def test_format_tcp_flags():
    assert format_tcp_flags(0x02) == "SYN"
    assert format_tcp_flags(0x12) == "SYN, ACK"
    assert format_tcp_flags(0x18) == "PSH, ACK"
    assert format_tcp_flags(0x11) == "FIN, ACK"
    assert format_tcp_flags(0x04) == "RST"
    assert format_tcp_flags(0) == "None"
    assert format_tcp_flags(None) is None
