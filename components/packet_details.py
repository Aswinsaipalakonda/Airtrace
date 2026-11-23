"""Packet detail inspector drawer component."""

import streamlit as st
from airtrace.models import PacketRecord


def render_packet_details(record: PacketRecord | None):
    """Render expanded inspection card for a single selected packet."""
    if not record:
        return

    with st.expander(f"🔍 Packet #{record.packet_number} Deep Inspection — {record.protocol} ({record.packet_size_bytes} wire bytes)", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown(
                f"""
                <div style="background: #0B0F19; border: 1px solid #232F48; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px;">
                    <div style="color: #00C8FF; font-weight: 700; margin-bottom: 6px;">IP LAYER (IPv4)</div>
                    <div>Source IP: <span style="color: #F8FAFC;">{record.source_ip}</span></div>
                    <div>Dest IP:   <span style="color: #F8FAFC;">{record.destination_ip}</span></div>
                    <div>TTL:       <span style="color: #F8FAFC;">{record.ttl}</span></div>
                    <div>Total Len: <span style="color: #F8FAFC;">{record.ip_total_length or '—'} bytes</span></div>
                    <div>IP ID:     <span style="color: #F8FAFC;">{record.ip_identification or '—'}</span></div>
                    <div>Flags:     <span style="color: #F8FAFC;">{record.ip_flags or '—'}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            transport_title = f"{record.protocol} TRANSPORT LAYER"
            content = ""
            if record.protocol == "TCP":
                content = f"""
                    <div>Source Port: <span style="color: #F8FAFC;">{record.source_port}</span></div>
                    <div>Dest Port:   <span style="color: #F8FAFC;">{record.destination_port}</span></div>
                    <div>TCP Flags:   <span style="color: #00E676; font-weight: 700;">{record.tcp_flags or 'None'}</span></div>
                    <div>Seq Number:  <span style="color: #F8FAFC;">{record.tcp_sequence}</span></div>
                    <div>Ack Number:  <span style="color: #F8FAFC;">{record.tcp_acknowledgment or '—'}</span></div>
                    <div>Window Size: <span style="color: #F8FAFC;">{record.tcp_window or '—'}</span></div>
                """
            elif record.protocol == "UDP":
                content = f"""
                    <div>Source Port: <span style="color: #F8FAFC;">{record.source_port}</span></div>
                    <div>Dest Port:   <span style="color: #F8FAFC;">{record.destination_port}</span></div>
                    <div>UDP Length:  <span style="color: #F8FAFC;">{record.udp_length or '—'} bytes</span></div>
                    <div>Checksum:    <span style="color: #F8FAFC;">{hex(record.udp_checksum) if record.udp_checksum else '—'}</span></div>
                """
            elif record.protocol == "ICMP":
                content = f"""
                    <div>ICMP Type:   <span style="color: #B388FF; font-weight: 700;">{record.icmp_type}</span></div>
                    <div>ICMP Code:   <span style="color: #F8FAFC;">{record.icmp_code}</span></div>
                    <div>Checksum:    <span style="color: #F8FAFC;">{hex(record.icmp_checksum) if record.icmp_checksum else '—'}</span></div>
                    <div>Identifier:  <span style="color: #F8FAFC;">{record.icmp_id or '—'}</span></div>
                    <div>Sequence:    <span style="color: #F8FAFC;">{record.icmp_seq or '—'}</span></div>
                """
            else:
                content = f"""
                    <div>Protocol:    <span style="color: #94A3B8;">{record.protocol}</span></div>
                    <div>Wire Length: <span style="color: #F8FAFC;">{record.packet_size_bytes} bytes</span></div>
                """

            st.markdown(
                f"""
                <div style="background: #0B0F19; border: 1px solid #232F48; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px;">
                    <div style="color: #00E676; font-weight: 700; margin-bottom: 6px;">{transport_title}</div>
                    {content}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f"""
                <div style="background: #0B0F19; border: 1px solid #232F48; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12px;">
                    <div style="color: #B388FF; font-weight: 700; margin-bottom: 6px;">METADATA & TIMING</div>
                    <div>Packet No:   <span style="color: #F8FAFC;">#{record.packet_number}</span></div>
                    <div>Timestamp:   <span style="color: #F8FAFC;">{record.timestamp}</span></div>
                    <div>Epoch Time:  <span style="color: #F8FAFC;">{record.epoch_time:.6f}</span></div>
                    <div>Payload:     <span style="color: #94A3B8; font-style: italic;">Omitted (Privacy Protected)</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )
