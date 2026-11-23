"""Header banner component with transparent logo, title, and live status indicator."""

from pathlib import Path
import streamlit as st
from airtrace.config import ASSETS_DIR, COLOR_PALETTE
from airtrace.models import CaptureState


def render_header(capture_state: CaptureState, elapsed_seconds: float, interface_name: str | None = None):
    """Render the top brand bar, logo, and active capture state beacon with modern rounded styling."""
    logo_transparent = ASSETS_DIR / "logo_transparent.png"
    logo_fallback = ASSETS_DIR / "logo.png"
    logo_path = logo_transparent if logo_transparent.exists() else logo_fallback

    status_color = COLOR_PALETTE["status_idle"]
    status_glow = "rgba(100, 116, 139, 0.25)"
    status_text = capture_state.value.upper()
    pulse_dot = "●"

    if capture_state == CaptureState.CAPTURING:
        status_color = COLOR_PALETTE["status_capturing"]
        status_glow = "rgba(0, 230, 118, 0.35)"
    elif capture_state == CaptureState.STOPPING:
        status_color = COLOR_PALETTE["status_stopping"]
        status_glow = "rgba(255, 179, 0, 0.35)"
    elif capture_state == CaptureState.ERROR:
        status_color = COLOR_PALETTE["status_error"]
        status_glow = "rgba(255, 82, 82, 0.35)"

    mins, secs = divmod(int(elapsed_seconds), 60)
    timer_str = f"{mins:02d}:{secs:02d}"

    col_logo, col_title, col_status = st.columns([1, 4.5, 2.2])

    with col_logo:
        if logo_path.exists():
            st.image(str(logo_path), width=78)
        else:
            st.markdown("### 📡")

    with col_title:
        st.markdown(
            """
            <div style="line-height: 1.25; padding-top: 4px;">
                <div style="display: flex; align-items: baseline; gap: 10px;">
                    <span style="font-size: 26px; font-weight: 900; letter-spacing: -0.5px; background: linear-gradient(135deg, #FFFFFF 0%, #E2E8F0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">AIRTRACE</span>
                    <span style="font-size: 11px; font-weight: 700; color: #00C8FF; background: rgba(0, 200, 255, 0.12); padding: 3px 8px; border-radius: 12px; border: 1px solid rgba(0, 200, 255, 0.25); text-transform: uppercase; letter-spacing: 0.8px;">Network Inspector</span>
                </div>
                <p style="margin: 4px 0 0 0; font-size: 13px; color: #94A3B8; font-weight: 400;">
                    High-precision IPv4 protocol decoder & real-time traffic telemetry console
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_status:
        st.markdown(
            f"""
            <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 14px; padding: 10px 14px; text-align: right; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);">
                <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #64748B;">Capture Status</div>
                <div style="font-size: 14px; font-weight: 800; color: {status_color}; font-family: monospace; display: flex; align-items: center; justify-content: flex-end; gap: 6px; margin-top: 2px;">
                    <span style="box-shadow: 0 0 10px {status_glow}; border-radius: 50%;">{pulse_dot}</span> {status_text}
                    <span style="color: #94A3B8; font-size: 12px; font-weight: 500; background: rgba(255, 255, 255, 0.05); padding: 1px 6px; border-radius: 8px;">{timer_str}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
