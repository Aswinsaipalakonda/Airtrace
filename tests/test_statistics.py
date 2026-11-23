"""Unit tests for the StatisticsEngine."""

import time
import pytest
from airtrace.models import PacketRecord, ProtocolType
from airtrace.statistics import StatisticsEngine


@pytest.fixture
def sample_records():
    return [
        PacketRecord(
            packet_number=1,
            timestamp="2026-11-23T21:00:00.000000Z",
            epoch_time=time.time(),
            protocol=ProtocolType.TCP.value,
            source_ip="192.168.1.10",
            destination_ip="1.1.1.1",
            source_port=12345,
            destination_port=443,
            packet_size_bytes=100,
        ),
        PacketRecord(
            packet_number=2,
            timestamp="2026-11-23T21:00:01.000000Z",
            epoch_time=time.time(),
            protocol=ProtocolType.UDP.value,
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            source_port=54321,
            destination_port=53,
            packet_size_bytes=200,
        ),
        PacketRecord(
            packet_number=3,
            timestamp="2026-11-23T21:00:02.000000Z",
            epoch_time=time.time(),
            protocol=ProtocolType.ICMP.value,
            source_ip="10.0.0.1",
            destination_ip="1.1.1.1",
            packet_size_bytes=84,
        ),
    ]


def test_statistics_engine_counters(sample_records):
    engine = StatisticsEngine(max_history=10, rate_window_seconds=5.0)
    engine.add_packets(sample_records)

    snap = engine.get_snapshot()
    assert snap.total_packets == 3
    assert snap.total_bytes == 384
    assert snap.tcp_count == 1
    assert snap.udp_count == 1
    assert snap.icmp_count == 1
    assert snap.other_count == 0
    assert snap.average_packet_size == 128.0
    assert len(snap.top_sources) >= 1
    assert snap.top_sources[0][0] == "192.168.1.10"
    assert snap.top_sources[0][1] == 2


def test_statistics_engine_history_limit(sample_records):
    engine = StatisticsEngine(max_history=2)
    engine.add_packets(sample_records)

    history = engine.get_history()
    assert len(history) == 2
    # Should retain the last two packets (#2 and #3)
    assert history[0].packet_number == 2
    assert history[1].packet_number == 3


def test_statistics_engine_reset(sample_records):
    engine = StatisticsEngine()
    engine.add_packets(sample_records)
    assert engine.get_snapshot().total_packets == 3

    engine.reset()
    snap = engine.get_snapshot()
    assert snap.total_packets == 0
    assert snap.total_bytes == 0
    assert len(engine.get_history()) == 0
