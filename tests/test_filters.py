"""Unit tests for filtering and search routines."""

import pytest
from airtrace.filters import filter_records, validate_bpf_filter
from airtrace.models import PacketRecord, ProtocolType


@pytest.fixture
def test_packet_list():
    return [
        PacketRecord(
            packet_number=1,
            timestamp="2026-11-23T21:00:00Z",
            epoch_time=0.0,
            protocol=ProtocolType.TCP.value,
            source_ip="192.168.1.50",
            destination_ip="93.184.216.34",
            source_port=50001,
            destination_port=443,
        ),
        PacketRecord(
            packet_number=2,
            timestamp="2026-11-23T21:00:01Z",
            epoch_time=1.0,
            protocol=ProtocolType.UDP.value,
            source_ip="192.168.1.50",
            destination_ip="1.1.1.1",
            source_port=60002,
            destination_port=53,
        ),
        PacketRecord(
            packet_number=3,
            timestamp="2026-11-23T21:00:02Z",
            epoch_time=2.0,
            protocol=ProtocolType.ICMP.value,
            source_ip="10.0.0.5",
            destination_ip="192.168.1.1",
        ),
    ]


def test_filter_by_protocol(test_packet_list):
    tcp_only = filter_records(test_packet_list, protocol="TCP")
    assert len(tcp_only) == 1
    assert tcp_only[0].protocol == "TCP"

    udp_only = filter_records(test_packet_list, protocol="UDP")
    assert len(udp_only) == 1
    assert udp_only[0].protocol == "UDP"

    all_records = filter_records(test_packet_list, protocol="ALL")
    assert len(all_records) == 3


def test_filter_by_search_query(test_packet_list):
    # Match by destination port 53
    dns_match = filter_records(test_packet_list, protocol="ALL", search_query="53")
    assert len(dns_match) == 1
    assert dns_match[0].packet_number == 2

    # Match by partial IP
    ip_match = filter_records(test_packet_list, protocol="ALL", search_query="192.168.1")
    assert len(ip_match) == 3

    # Match by specific IP
    specific_ip = filter_records(test_packet_list, protocol="ALL", search_query="10.0.0.5")
    assert len(specific_ip) == 1
    assert specific_ip[0].packet_number == 3


def test_validate_bpf_filter():
    valid, _ = validate_bpf_filter("tcp port 80")
    assert valid is True

    valid_empty, _ = validate_bpf_filter("")
    assert valid_empty is True
