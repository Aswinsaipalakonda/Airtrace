"""Capture controls bar component styled as a unified Command Deck."""

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
    """Render the adapter selector, BPF filter, and Start/Stop buttons inside a unified Command Deck."""
    # Format options for selectbox
    options = {}
    default_idx = 0
    for idx, iface in enumerate(interfaces):
        label = f"{iface.name}"
        if iface.ip_address:
            label += f" ({iface.ip_address})"
        elif iface.description and iface.description != iface.name:
            label += f" - {iface.description[:32]}"
        options[iface.device_id] = label
        if selected_device_id and iface.device_id == selected_device_id:
            default_idx = idx

    driver_badge = (
        '<span style="color: #00E676; background: rgba(0, 230, 118, 0.1); border: 1px solid rgba(0, 230, 118, 0.25); padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">🛡️ Npcap Driver Active</span>'
        if npcap_available
        else '<span style="color: #FFB300; background: rgba(255, 179, 0, 0.1); border: 1px solid rgba(255, 179, 0, 0.25); padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">💡 Demo Adapter Active (Npcap not detected)</span>'
    )

    # Deck Header
    st.markdown(
        f"""
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; padding: 0 4px;">
            <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: #94A3B8; display: flex; align-items: center; gap: 6px;">
                <span>⚡ CAPTURE ENGINE CONTROLS</span>
            </div>
            <div>
                {driver_badge}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 5 Column Aligned Toolbar
    c1, c2, c3, c4, c5 = st.columns([3.5, 2.5, 1.3, 1.3, 1.3])

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
        if st.button("🔄 CLEAR", use_container_width=True, disabled=is_capturing, help="Clear capture history and reset statistics"):
            on_clear()
