"""Airtrace — High-precision network traffic analyzer and protocol inspection dashboard."""

import time
from pathlib import Path
import streamlit as st

from airtrace.config import ASSETS_DIR, BATCH_DRAIN_LIMIT, CAPTURES_DIR, PROTOCOLS
from airtrace.capture import CaptureController
from airtrace.exporter import export_to_csv
from airtrace.filters import filter_records
from airtrace.interfaces import check_npcap_status, get_available_interfaces
from airtrace.models import CaptureState
from airtrace.statistics import StatisticsEngine
from components.capture_controls import render_capture_controls
from components.header import render_header
from components.metric_cards import render_metric_cards
from components.packet_details import render_packet_details
from components.packet_table import render_packet_table
from components.protocol_charts import render_protocol_charts

# Streamlit Page Configuration
logo_img = ASSETS_DIR / "logo.png"
st.set_page_config(
    page_title="Airtrace — Network Inspector",
    page_icon=str(logo_img) if logo_img.exists() else "📡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Dark cockpit engineering styling
st.markdown(
    """
    <style>
    /* Dark Theme Canvas */
    .stApp {
        background-color: #0B0F19;
        color: #F8FAFC;
    }
    header[data-testid="stHeader"] {
        background-color: #0B0F19;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 95rem;
    }
    /* Buttons */
    button[kind="primary"] {
        background: #00C8FF !important;
        border: none !important;
        color: #0B0F19 !important;
        font-weight: 700 !important;
        letter-spacing: 0.5px;
    }
    button[kind="secondary"] {
        background: #FF5252 !important;
        border: none !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }
    /* Selectboxes and Inputs */
    div[data-baseweb="select"] > div {
        background-color: #151C2C !important;
        border-color: #232F48 !important;
        color: #F8FAFC !important;
    }
    input[type="text"] {
        background-color: #151C2C !important;
        border: 1px solid #232F48 !important;
        color: #F8FAFC !important;
    }
    /* Dataframe Table styling */
    [data-testid="stDataFrame"] {
        background-color: #151C2C;
        border: 1px solid #232F48;
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Session State Singletons
if "controller" not in st.session_state:
    st.session_state["controller"] = CaptureController()

if "stats_engine" not in st.session_state:
    st.session_state["stats_engine"] = StatisticsEngine()

if "selected_iface" not in st.session_state:
    st.session_state["selected_iface"] = None

if "selected_packet_num" not in st.session_state:
    st.session_state["selected_packet_num"] = None

controller: CaptureController = st.session_state["controller"]
stats_engine: StatisticsEngine = st.session_state["stats_engine"]

# Drain any packets accumulated in the background worker queue
incoming_packets = controller.drain_packets(max_count=BATCH_DRAIN_LIMIT)
if incoming_packets:
    stats_engine.add_packets(incoming_packets)

# Check hardware capture driver availability
npcap_available, npcap_message = check_npcap_status()
interfaces = get_available_interfaces()

if not st.session_state["selected_iface"] and interfaces:
    st.session_state["selected_iface"] = interfaces[0].device_id

# Header Section
capture_state = controller.state
elapsed_sec = controller.get_elapsed_seconds()
render_header(capture_state, elapsed_sec, st.session_state["selected_iface"])

st.markdown("<hr style='border: none; border-top: 1px solid #232F48; margin: 12px 0 16px 0;'/>", unsafe_allow_html=True)


# Lifecycle Callback Handlers
def handle_start(device_id: str, bpf_filter: str):
    st.session_state["selected_iface"] = device_id
    success = controller.start_capture(interface=device_id, bpf_filter=bpf_filter)
    if not success and controller.error_message:
        st.error(f"Failed to start capture: {controller.error_message}")
    st.rerun()


def handle_stop():
    controller.stop_capture(timeout=2.0)
    st.rerun()


def handle_clear():
    controller.stop_capture(timeout=1.0)
    stats_engine.reset()
    st.session_state["selected_packet_num"] = None
    st.rerun()


# Capture Controls Bar
render_capture_controls(
    interfaces=interfaces,
    selected_device_id=st.session_state["selected_iface"],
    capture_state=capture_state,
    on_start=handle_start,
    on_stop=handle_stop,
    on_clear=handle_clear,
    npcap_available=npcap_available,
    npcap_message=npcap_message,
)

# Statistics & KPI Ribbon
stats_snapshot = stats_engine.get_snapshot()
st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
render_metric_cards(stats_snapshot)

# Protocol Analytics Charts
st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)
render_protocol_charts(stats_snapshot)

# Packet Explorer & Filtering Section
st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)
c_title, c_proto, c_search = st.columns([2.5, 2, 2.5])

with c_title:
    st.markdown(
        "<div style='font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #F8FAFC; padding-top: 5px;'>Live Packet Explorer</div>",
        unsafe_allow_html=True,
    )

with c_proto:
    selected_proto = st.selectbox(
        "Protocol Filter",
        options=PROTOCOLS,
        index=0,
        label_visibility="collapsed",
    )

with c_search:
    search_query = st.text_input(
        "Search IP / Port",
        placeholder="Search IP or Port...",
        label_visibility="collapsed",
    )

all_records = stats_engine.get_history()
filtered_records = filter_records(all_records, protocol=selected_proto, search_query=search_query)

# Display tabular packets (reverse chronological for real-time monitoring)
display_records = list(reversed(filtered_records))
selected_pkt_num = render_packet_table(display_records)

if selected_pkt_num is not None:
    st.session_state["selected_packet_num"] = selected_pkt_num

# Packet Inspector Drawer
active_pkt = None
if st.session_state["selected_packet_num"]:
    active_pkt = next((r for r in all_records if r.packet_number == st.session_state["selected_packet_num"]), None)

if active_pkt:
    render_packet_details(active_pkt)

# CSV Export Section
st.markdown("<hr style='border: none; border-top: 1px solid #232F48; margin: 20px 0 14px 0;'/>", unsafe_allow_html=True)
col_exp_info, col_exp_btn = st.columns([5, 2])

with col_exp_info:
    st.markdown(
        "<div style='font-size: 12px; color: #94A3B8;'><strong>Export Notice:</strong> CSV export extracts header metadata only. Zero application payloads or sensitive credentials are ever written.</div>",
        unsafe_allow_html=True,
    )

with col_exp_btn:
    if all_records:
        csv_path = export_to_csv(all_records)
        with open(csv_path, "r", encoding="utf-8") as f:
            csv_content = f.read()

        st.download_button(
            label="📥 EXPORT CAPTURE CSV",
            data=csv_content,
            file_name=csv_path.name,
            mime="text/csv",
            use_container_width=True,
        )
    else:
        st.button("📥 EXPORT CAPTURE CSV", disabled=True, use_container_width=True)

# Real-time Auto-refresh loop while capturing
if controller.is_running:
    time.sleep(1.0)
    st.rerun()
