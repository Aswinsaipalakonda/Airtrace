"""Protocol analytics charts and visualizations using Altair."""

import altair as alt
import pandas as pd
import streamlit as st
from airtrace.config import COLOR_PALETTE
from airtrace.models import CaptureStatisticsSnapshot


def render_protocol_charts(snap: CaptureStatisticsSnapshot):
    """Render protocol distribution and top endpoints split."""
    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.markdown(
            "<div style='font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #94A3B8; margin-bottom: 8px;'>Protocol Distribution</div>",
            unsafe_allow_html=True,
        )

        data = [
            {"Protocol": "TCP", "Count": snap.tcp_count, "Color": COLOR_PALETTE["proto_tcp"]},
            {"Protocol": "UDP", "Count": snap.udp_count, "Color": COLOR_PALETTE["proto_udp"]},
            {"Protocol": "ICMP", "Count": snap.icmp_count, "Color": COLOR_PALETTE["proto_icmp"]},
            {"Protocol": "OTHER", "Count": snap.other_count, "Color": COLOR_PALETTE["proto_other"]},
        ]
        df_proto = pd.DataFrame(data)
        total = snap.total_packets

        if total > 0:
            df_proto["Percentage"] = (df_proto["Count"] / total * 100).round(1)

            donut = alt.Chart(df_proto).mark_arc(innerRadius=48, stroke="#151C2C", strokeWidth=2).encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(
                    field="Protocol",
                    type="nominal",
                    scale=alt.Scale(
                        domain=["TCP", "UDP", "ICMP", "OTHER"],
                        range=[
                            COLOR_PALETTE["proto_tcp"],
                            COLOR_PALETTE["proto_udp"],
                            COLOR_PALETTE["proto_icmp"],
                            COLOR_PALETTE["proto_other"],
                        ],
                    ),
                    legend=alt.Legend(orient="bottom", labelColor="#94A3B8", title=None),
                ),
                tooltip=[
                    alt.Tooltip("Protocol:N"),
                    alt.Tooltip("Count:Q", format=","),
                    alt.Tooltip("Percentage:Q", format=".1f", title="Share (%)"),
                ],
            ).properties(height=220, background="transparent")

            st.altair_chart(donut, use_container_width=True)
        else:
            st.info("No packets captured yet. Start capture to display protocol distribution.")

    with c_right:
        st.markdown(
            "<div style='font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #94A3B8; margin-bottom: 8px;'>Top Communicating Endpoints</div>",
            unsafe_allow_html=True,
        )

        if snap.top_sources or snap.top_destinations:
            # Combine top talkers
            endpoint_counts = {}
            for ip, cnt in snap.top_sources:
                endpoint_counts[ip] = endpoint_counts.get(ip, 0) + cnt
            for ip, cnt in snap.top_destinations:
                endpoint_counts[ip] = endpoint_counts.get(ip, 0) + cnt

            sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            df_endpoints = pd.DataFrame(sorted_endpoints, columns=["IP Address", "Packets"])

            bars = alt.Chart(df_endpoints).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#00C8FF").encode(
                x=alt.X("Packets:Q", title="Packet Count", axis=alt.Axis(labelColor="#94A3B8", titleColor="#94A3B8")),
                y=alt.Y("IP Address:N", sort="-x", title=None, axis=alt.Axis(labelColor="#F8FAFC")),
                tooltip=["IP Address", "Packets"],
            ).properties(height=220, background="transparent")

            st.altair_chart(bars, use_container_width=True)
        else:
            st.info("Endpoint statistics will appear once traffic is received.")
