"""Pytest fixtures for generating synthetic Scapy packets without live network access."""

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether


@pytest.fixture
def synthetic_tcp_packet():
    """A standard TCP SYN-ACK packet fixture."""
    return Ether() / IP(src="192.168.1.100", dst="93.184.216.34", ttl=64, id=1024, flags="DF") / TCP(
        sport=54321, dport=443, flags="SA", seq=1000, ack=2000, window=65535
    )


@pytest.fixture
def synthetic_udp_packet():
    """A standard UDP DNS query packet fixture."""
    return Ether() / IP(src="10.0.0.1", dst="1.1.1.1", ttl=128, id=2048) / UDP(
        sport=61234, dport=53
    )


@pytest.fixture
def synthetic_icmp_packet():
    """An ICMP Echo Request packet fixture."""
    return Ether() / IP(src="192.168.1.1", dst="8.8.8.8", ttl=64, id=3000) / ICMP(
        type=8, code=0, id=123, seq=1
    )


@pytest.fixture
def synthetic_other_packet():
    """An IPv4 packet carrying IGMP (proto=2) to test OTHER classification."""
    return Ether() / IP(src="192.168.1.50", dst="224.0.0.1", proto=2, ttl=1)


@pytest.fixture
def synthetic_non_ip_packet():
    """An ARP packet fixture (non-IPv4)."""
    from scapy.layers.l2 import ARP
    return Ether() / ARP(op=1, pdst="192.168.1.1")
