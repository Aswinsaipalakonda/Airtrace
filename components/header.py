"""Header banner component with transparent logo, title, and live status indicator."""

import base64
from pathlib import Path
import streamlit as st
from airtrace.config import ASSETS_DIR, COLOR_PALETTE
from airtrace.models import CaptureState


def _get_logo_base64() -> str:
    """Read the optimized transparent logo as a base64 string for seamless inline HTML rendering."""
    logo_path = ASSETS_DIR / "logo_transparent.png"
    if not logo_path.exists():
        logo_path = ASSETS_DIR / "logo.png"

    try:
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")
    except Exception:
        return ""


def render_header(capture_state: CaptureState, elapsed_seconds: float, interface_name: str | None = None):
    """Render a pixel-perfect, cohesive top header card with logo, title, and live status beacon."""
    logo_b64 = _get_logo_base64()

    status_color = COLOR_PALETTE["status_idle"]
    status_glow = "rgba(100, 116, 139, 0.3)"
    status_text = capture_state.value.upper()
    pulse_dot = "●"

    if capture_state == CaptureState.CAPTURING:
        status_color = COLOR_PALETTE["status_capturing"]
        status_glow = "rgba(0, 230, 118, 0.45)"
    elif capture_state == CaptureState.STOPPING:
        status_color = COLOR_PALETTE["status_stopping"]
        status_glow = "rgba(255, 179, 0, 0.45)"
    elif capture_state == CaptureState.ERROR:
        status_color = COLOR_PALETTE["status_error"]
        status_glow = "rgba(255, 82, 82, 0.45)"

    mins, secs = divmod(int(elapsed_seconds), 60)
    timer_str = f"{mins:02d}:{secs:02d}"

    logo_html = f'<img src="data:image/png;base64,{logo_b64}" style="height: 48px; width: auto; object-fit: contain; filter: drop-shadow(0 2px 10px rgba(0, 200, 255, 0.3));" alt="Airtrace Logo"/>' if logo_b64 else '<span style="font-size: 28px;">📡</span>'

    # Unified Floating Cyber Header
    st.markdown(
        f"""
        <div style="background: linear-gradient(145deg, #0F172A 0%, #0B1120 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 12px 22px; box-shadow: 0 8px 32px -4px rgba(0, 0, 0, 0.4); display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="display: flex; align-items: center; justify-content: center; padding-right: 4px;">
                    {logo_html}
                </div>
                <div style="display: flex; flex-direction: column;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 22px; font-weight: 900; letter-spacing: -0.3px; color: #FFFFFF; font-family: 'Inter', sans-serif;">AIRTRACE</span>
                        <span style="font-size: 10px; font-weight: 700; color: #00C8FF; background: rgba(0, 200, 255, 0.12); padding: 2px 8px; border-radius: 10px; border: 1px solid rgba(0, 200, 255, 0.3); text-transform: uppercase; letter-spacing: 0.8px;">Network Inspector</span>
                    </div>
                    <span style="margin-top: 2px; font-size: 12px; color: #64748B; font-weight: 500;">
                        High-precision IPv4 packet decoder & real-time traffic telemetry console
                    </span>
                </div>
            </div>
            <div style="background: rgba(7, 10, 18, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 6px 14px; text-align: right;">
                <div style="font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: #475569; margin-bottom: 2px;">Engine Telemetry</div>
                <div style="font-size: 13px; font-weight: 800; color: {status_color}; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; justify-content: flex-end; gap: 6px;">
                    <span style="font-size: 10px; color: {status_color}; text-shadow: 0 0 8px {status_glow};">{pulse_dot}</span> {status_text}
                    <span style="color: #94A3B8; font-size: 11px; font-weight: 600; background: rgba(255, 255, 255, 0.05); padding: 1px 6px; border-radius: 6px; margin-left: 4px;">{timer_str}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
