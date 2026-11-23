"""High-precision KPI metric cards component with modern rounded styling."""

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
    """Render 4 compact, high-density KPI tiles with modern rounded design."""
    c1, c2, c3, c4 = st.columns(4)

    card_style = """
        <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 16px 20px; box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.35); transition: transform 0.2s ease;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: #94A3B8;">{title}</span>
                <span style="font-size: 12px; color: {accent_color};">●</span>
            </div>
            <div style="font-size: 26px; font-weight: 800; color: #FFFFFF; font-family: monospace; letter-spacing: -0.5px; margin: 4px 0 6px 0;">{value}</div>
            <div style="font-size: 11px; color: {sub_color}; font-weight: 600; display: flex; align-items: center; gap: 4px;">
                <span>{subtitle}</span>
            </div>
        </div>
    """

    with c1:
        st.markdown(
            card_style.format(
                title="Total Packets",
                value=f"{snap.total_packets:,}",
                subtitle=f"⚡ {snap.packets_per_second:.1f} pkt/s (rolling 5s)",
                accent_color="#00C8FF",
                sub_color="#00C8FF",
            ),
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            card_style.format(
                title="Captured Volume",
                value=format_bytes(snap.total_bytes),
                subtitle=f"📶 {format_rate_bps(snap.bytes_per_second)} throughput",
                accent_color="#00E676",
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
                accent_color="#B388FF",
                sub_color="#94A3B8",
            ),
            unsafe_allow_html=True,
        )

    with c4:
        active_protos = sum(1 for c in [snap.tcp_count, snap.udp_count, snap.icmp_count, snap.other_count] if c > 0)
        st.markdown(
            card_style.format(
                title="Active Protocols",
                value=f"{active_protos} / 4",
                subtitle=f"TCP: {snap.tcp_count} | UDP: {snap.udp_count} | ICMP: {snap.icmp_count}",
                accent_color="#FFB300",
                sub_color="#38BDF8",
            ),
            unsafe_allow_html=True,
        )
