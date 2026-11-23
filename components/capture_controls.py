"""Capture controls bar component."""

from typing import Callable, Optional
import streamlit as st
from airtrace.filters import validate_bpf_filter
from airtrace.interfaces import DEMO_INTERFACE_ID, InterfaceInfo
from airtrace.models import CaptureState


def render_capture_controls(
    interfaces: list[InterfaceInfo],
    selected_device_id: Optional[str],
    capture_state: CaptureState,
    on_start: Callable[[str, str], None],
    on_stop: Callable[[], None],
    on_clear: Callable[[], None],
    npcap_available: bool,
    npcap_message: str,
):
    """Render the adapter selector, BPF filter, and Start/Stop buttons with rounded modern controls."""
    # Modernized Driver Notice Card
    if not npcap_available:
        st.markdown(
            f"""
            <div style="background: rgba(255, 179, 0, 0.06); border: 1px solid rgba(255, 179, 0, 0.25); border-radius: 14px; padding: 12px 18px; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; gap: 14px;">
                <div style="font-size: 13px; color: #F1F5F9; line-height: 1.4;">
                    <strong style="color: #FFB300;">ℹ️ Windows Packet Driver:</strong> {npcap_message}
                </div>
                <div style="font-size: 12px; color: #00C8FF; background: rgba(0, 200, 255, 0.1); border: 1px solid rgba(0, 200, 255, 0.25); padding: 4px 10px; border-radius: 10px; white-space: nowrap; font-weight: 600;">
                    💡 Tip: Synthetic Demo Adapter is active
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Format options for selectbox
    options = {}
    default_idx = 0
    for idx, iface in enumerate(interfaces):
        label = f"{iface.name}"
        if iface.ip_address:
            label += f" ({iface.ip_address})"
        elif iface.description and iface.description != iface.name:
            label += f" - {iface.description[:35]}"
        options[iface.device_id] = label
        if selected_device_id and iface.device_id == selected_device_id:
            default_idx = idx

    c1, c2, c3, c4, c5 = st.columns([3.6, 2.4, 1.2, 1.2, 1.2])

    with c1:
        selected_id = st.selectbox(
            "Capture Interface",
            options=list(options.keys()),
            format_func=lambda k: options[k],
            index=default_idx,
            disabled=(capture_state == CaptureState.CAPTURING),
            label_visibility="collapsed",
            help="Select network adapter for packet capture. Use Synthetic Demo Adapter for offline testing.",
        )

    with c2:
        bpf_input = st.text_input(
            "BPF Filter",
            placeholder="BPF Filter (e.g. 'tcp port 80 or icmp')",
            disabled=(capture_state == CaptureState.CAPTURING),
            label_visibility="collapsed",
            help="Optional Berkeley Packet Filter expression. Leave empty for all traffic.",
        )

    is_capturing = (capture_state == CaptureState.CAPTURING)

    with c3:
        if not is_capturing:
            if st.button("▶ START", use_container_width=True, type="primary"):
                if bpf_input:
                    valid, msg = validate_bpf_filter(bpf_input)
                    if not valid:
                        st.error(msg)
                        return
                on_start(selected_id, bpf_input)
        else:
            st.button("▶ START", use_container_width=True, disabled=True)

    with c4:
        if is_capturing:
            if st.button("⏹ STOP", use_container_width=True, type="secondary"):
                on_stop()
        else:
            st.button("⏹ STOP", use_container_width=True, disabled=True)

    with c5:
        if st.button("🔄 CLEAR", use_container_width=True, disabled=is_capturing, help="Clear capture history and reset stats"):
            on_clear()
