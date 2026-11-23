"""Header banner component with logo, title, and live status indicator."""

import streamlit as st
from pathlib import Path
from airtrace.config import ASSETS_DIR, COLOR_PALETTE
from airtrace.models import CaptureState


def render_header(capture_state: CaptureState, elapsed_seconds: float, interface_name: str | None = None):
    """Render the top brand bar, logo, and active capture state beacon."""
    logo_path = ASSETS_DIR / "logo.png"

    status_color = COLOR_PALETTE["status_idle"]
    status_text = capture_state.value.upper()
    pulse_dot = "⚪"

    if capture_state == CaptureState.CAPTURING:
        status_color = COLOR_PALETTE["status_capturing"]
        pulse_dot = "🟢"
    elif capture_state == CaptureState.STOPPING:
        status_color = COLOR_PALETTE["status_stopping"]
        pulse_dot = "🟡"
    elif capture_state == CaptureState.ERROR:
        status_color = COLOR_PALETTE["status_error"]
        pulse_dot = "🔴"

    mins, secs = divmod(int(elapsed_seconds), 60)
    timer_str = f"{mins:02d}:{secs:02d}"

    col_logo, col_title, col_status = st.columns([1, 4, 2])

    with col_logo:
        if logo_path.exists():
            st.image(str(logo_path), width=85)
        else:
            st.markdown("### 📡")

    with col_title:
        st.markdown(
            """
            <div style="line-height: 1.2; padding-top: 5px;">
                <span style="font-size: 26px; font-weight: 800; letter-spacing: -0.5px; color: #F8FAFC;">AIRTRACE</span>
                <span style="font-size: 13px; font-weight: 500; color: #00C8FF; margin-left: 8px; text-transform: uppercase; letter-spacing: 1px;">Network Inspector</span>
                <p style="margin: 3px 0 0 0; font-size: 12px; color: #94A3B8;">High-precision IPv4 protocol decoder & traffic analysis console</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_status:
        st.markdown(
            f"""
            <div style="background: #151C2C; border: 1px solid #232F48; border-radius: 8px; padding: 8px 12px; text-align: right; margin-top: 5px;">
                <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: #64748B;">Capture Status</div>
                <div style="font-size: 14px; font-weight: 700; color: {status_color}; font-family: monospace;">
                    {pulse_dot} {status_text} <span style="color: #94A3B8; font-size: 12px; margin-left: 6px;">({timer_str})</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
