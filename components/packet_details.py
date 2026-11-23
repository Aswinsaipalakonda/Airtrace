"""Packet detail inspector drawer component with rounded cards."""

import streamlit as st
from airtrace.models import PacketRecord


def render_packet_details(record: PacketRecord | None):
    """Render expanded inspection card for a single selected packet with rounded panels."""
    if not record:
        return

    with st.expander(f"🔍 Packet #{record.packet_number} Deep Inspection — {record.protocol} ({record.packet_size_bytes} wire bytes)", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown(
                f"""
                <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(0, 200, 255, 0.25); border-radius: 12px; padding: 14px 16px; font-family: monospace; font-size: 12px;">
                    <div style="color: #00C8FF; font-weight: 700; margin-bottom: 8px; letter-spacing: 0.5px;">🌐 IP LAYER (IPv4)</div>
                    <div style="margin: 3px 0;">Source IP: <span style="color: #F8FAFC; font-weight: 600;">{record.source_ip}</span></div>
                    <div style="margin: 3px 0;">Dest IP:   <span style="color: #F8FAFC; font-weight: 600;">{record.destination_ip}</span></div>
                    <div style="margin: 3px 0;">TTL:       <span style="color: #F8FAFC;">{record.ttl}</span></div>
                    <div style="margin: 3px 0;">Total Len: <span style="color: #F8FAFC;">{record.ip_total_length or '—'} bytes</span></div>
                    <div style="margin: 3px 0;">IP ID:     <span style="color: #F8FAFC;">{record.ip_identification or '—'}</span></div>
                    <div style="margin: 3px 0;">Flags:     <span style="color: #F8FAFC;">{record.ip_flags or '—'}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c2:
            transport_title = f"⚡ {record.protocol} TRANSPORT LAYER"
            content = ""
            if record.protocol == "TCP":
                content = f"""
                    <div style="margin: 3px 0;">Source Port: <span style="color: #F8FAFC; font-weight: 600;">{record.source_port}</span></div>
                    <div style="margin: 3px 0;">Dest Port:   <span style="color: #F8FAFC; font-weight: 600;">{record.destination_port}</span></div>
                    <div style="margin: 3px 0;">TCP Flags:   <span style="color: #00E676; font-weight: 700; background: rgba(0, 230, 118, 0.1); padding: 2px 6px; border-radius: 6px;">{record.tcp_flags or 'None'}</span></div>
                    <div style="margin: 3px 0;">Seq Number:  <span style="color: #F8FAFC;">{record.tcp_sequence}</span></div>
                    <div style="margin: 3px 0;">Ack Number:  <span style="color: #F8FAFC;">{record.tcp_acknowledgment or '—'}</span></div>
                    <div style="margin: 3px 0;">Window Size: <span style="color: #F8FAFC;">{record.tcp_window or '—'}</span></div>
                """
            elif record.protocol == "UDP":
                content = f"""
                    <div style="margin: 3px 0;">Source Port: <span style="color: #F8FAFC; font-weight: 600;">{record.source_port}</span></div>
                    <div style="margin: 3px 0;">Dest Port:   <span style="color: #F8FAFC; font-weight: 600;">{record.destination_port}</span></div>
                    <div style="margin: 3px 0;">UDP Length:  <span style="color: #F8FAFC;">{record.udp_length or '—'} bytes</span></div>
                    <div style="margin: 3px 0;">Checksum:    <span style="color: #F8FAFC;">{hex(record.udp_checksum) if record.udp_checksum else '—'}</span></div>
                """
            elif record.protocol == "ICMP":
                content = f"""
                    <div style="margin: 3px 0;">ICMP Type:   <span style="color: #B388FF; font-weight: 700; background: rgba(179, 136, 255, 0.1); padding: 2px 6px; border-radius: 6px;">{record.icmp_type}</span></div>
                    <div style="margin: 3px 0;">ICMP Code:   <span style="color: #F8FAFC;">{record.icmp_code}</span></div>
                    <div style="margin: 3px 0;">Checksum:    <span style="color: #F8FAFC;">{hex(record.icmp_checksum) if record.icmp_checksum else '—'}</span></div>
                    <div style="margin: 3px 0;">Identifier:  <span style="color: #F8FAFC;">{record.icmp_id or '—'}</span></div>
                    <div style="margin: 3px 0;">Sequence:    <span style="color: #F8FAFC;">{record.icmp_seq or '—'}</span></div>
                """
            else:
                content = f"""
                    <div style="margin: 3px 0;">Protocol:    <span style="color: #94A3B8;">{record.protocol}</span></div>
                    <div style="margin: 3px 0;">Wire Length: <span style="color: #F8FAFC;">{record.packet_size_bytes} bytes</span></div>
                """

            st.markdown(
                f"""
                <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(0, 230, 118, 0.25); border-radius: 12px; padding: 14px 16px; font-family: monospace; font-size: 12px;">
                    <div style="color: #00E676; font-weight: 700; margin-bottom: 8px; letter-spacing: 0.5px;">{transport_title}</div>
                    {content}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with c3:
            st.markdown(
                f"""
                <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(179, 136, 255, 0.25); border-radius: 12px; padding: 14px 16px; font-family: monospace; font-size: 12px;">
                    <div style="color: #B388FF; font-weight: 700; margin-bottom: 8px; letter-spacing: 0.5px;">⏱ METADATA & TELEMETRY</div>
                    <div style="margin: 3px 0;">Packet No:   <span style="color: #F8FAFC; font-weight: 600;">#{record.packet_number}</span></div>
                    <div style="margin: 3px 0;">Timestamp:   <span style="color: #F8FAFC;">{record.timestamp}</span></div>
                    <div style="margin: 3px 0;">Epoch Time:  <span style="color: #F8FAFC;">{record.epoch_time:.6f}</span></div>
                    <div style="margin: 6px 0 2px 0; color: #94A3B8; font-size: 11px; font-style: italic;">🛡 Payload Omitted (Metadata-Only Privacy)</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
