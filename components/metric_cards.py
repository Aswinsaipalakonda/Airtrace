"""High-precision KPI metric cards component."""

import streamlit as st
from airtrace.models import CaptureStatisticsSnapshot


def format_bytes(byte_count: int | float) -> str:
    """Format bytes into readable engineering units."""
    b = float(byte_count)
    if b >= 1024 ** 3:
        return f"{b / (1024 ** 3):.2f} GB"
    if b >= 1024 ** 2:
        return f"{b / (1024 ** 2):.2f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{int(b)} B"


def format_rate_bps(bps: float) -> str:
    """Format bytes-per-second into human-readable throughput."""
    bits_per_sec = bps * 8.0
    if bits_per_sec >= 1_000_000:
        return f"{bits_per_sec / 1_000_000:.2f} Mbps"
    if bits_per_sec >= 1_000:
        return f"{bits_per_sec / 1_000:.1f} Kbps"
    return f"{bits_per_sec:.0f} bps"


def render_metric_cards(snap: CaptureStatisticsSnapshot):
    """Render 4 compact, high-density KPI tiles."""
    c1, c2, c3, c4 = st.columns(4)

    card_style = """
        <div style="background: #151C2C; border: 1px solid #232F48; border-radius: 8px; padding: 14px 16px;">
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: #94A3B8;">{title}</div>
            <div style="font-size: 24px; font-weight: 800; color: #F8FAFC; font-family: monospace; margin: 4px 0;">{value}</div>
            <div style="font-size: 11px; color: {sub_color}; font-weight: 500;">{subtitle}</div>
        </div>
    """

    with c1:
        st.markdown(
            card_style.format(
                title="Total Packets",
                value=f"{snap.total_packets:,}",
                subtitle=f"{snap.packets_per_second:.1f} pkt/s (rolling 5s)",
                sub_color="#00C8FF",
            ),
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            card_style.format(
                title="Captured Volume",
                value=format_bytes(snap.total_bytes),
                subtitle=format_rate_bps(snap.bytes_per_second),
                sub_color="#00E676",
            ),
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            card_style.format(
                title="Avg Packet Size",
                value=f"{int(snap.average_packet_size)} B",
                subtitle="Calculated wire length",
                sub_color="#94A3B8",
            ),
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            card_style.format(
                title="Active Protocols",
                value=f"{sum(1 for c in [snap.tcp_count, snap.udp_count, snap.icmp_count, snap.other_count] if c > 0)} / 4",
                subtitle=f"TCP: {snap.tcp_count} | UDP: {snap.udp_count}",
                sub_color="#00D2FF",
            ),
            unsafe_allow_html=True,
        )
