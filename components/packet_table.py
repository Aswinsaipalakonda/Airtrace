"""High-density packet exploration table component with rounded styling."""

import pandas as pd
import streamlit as st
from airtrace.models import PacketRecord


def render_packet_table(
    records: list[PacketRecord],
    selected_idx: int | None = None,
) -> int | None:
    """
    Render a clean, responsive, sortable tabular packet list.
    Returns the packet_number of any row selected by the user for inspection.
    """
    if not records:
        st.markdown(
            """
            <div style="background: linear-gradient(145deg, #131B2E 0%, #0D1322 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 40px 20px; text-align: center; color: #94A3B8;">
                <div style="font-size: 26px; margin-bottom: 8px;">🔍</div>
                <div style="font-size: 15px; font-weight: 700; color: #F1F5F9; margin-bottom: 4px;">No matching packets found</div>
                <div style="font-size: 13px; color: #94A3B8;">Adjust your search query or protocol filter, or click <strong style="color: #00C8FF;">START</strong> above to capture traffic.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return None

    # Construct tabular dataframe representation
    rows = []
    for r in records:
        time_part = r.timestamp.split("T")[-1][:12] if "T" in r.timestamp else r.timestamp
        src_endpoint = f"{r.source_ip}:{r.source_port}" if r.source_port is not None else r.source_ip
        dst_endpoint = f"{r.destination_ip}:{r.destination_port}" if r.destination_port is not None else r.destination_ip

        details = ""
        if r.protocol == "TCP":
            details = f"Flags: [{r.tcp_flags or 'None'}] Seq: {r.tcp_sequence}"
        elif r.protocol == "UDP":
            details = f"Len: {r.udp_length or '—'}"
        elif r.protocol == "ICMP":
            details = f"Type: {r.icmp_type} Code: {r.icmp_code}"
        else:
            details = f"IPv4 proto {r.ip_total_length or '—'}B"

        rows.append({
            "No.": r.packet_number,
            "Time": time_part,
            "Proto": r.protocol,
            "Source Endpoint": src_endpoint,
            "Destination Endpoint": dst_endpoint,
            "Bytes": r.packet_size_bytes,
            "TTL": r.ttl if r.ttl is not None else "—",
            "Summary": details,
        })

    df = pd.DataFrame(rows)

    # Use native dataframe with selection
    event = st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=340,
        selection_mode="single-row",
        on_select="rerun",
        key="packet_table_select",
    )

    selected_rows = event.selection.rows if event and hasattr(event, "selection") else []
    if selected_rows:
        row_idx = selected_rows[0]
        return records[row_idx].packet_number

    return None
