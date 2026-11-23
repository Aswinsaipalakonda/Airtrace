"""Protocol analytics charts and visualizations with rounded containers and error guards."""

import logging
import altair as alt
import pandas as pd
import streamlit as st
from airtrace.config import COLOR_PALETTE
from airtrace.models import CaptureStatisticsSnapshot

logger = logging.getLogger(__name__)


def render_protocol_charts(snap: CaptureStatisticsSnapshot):
    """Render protocol distribution and top endpoints split with modern rounded card containers."""
    c_left, c_right = st.columns([1, 1])

    with c_left:
        st.markdown(
            """
            <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: #94A3B8; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                <span>📊 Protocol Distribution</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        total = snap.total_packets
        if total > 0:
            data = [
                {"Protocol": "TCP", "Count": snap.tcp_count, "Color": COLOR_PALETTE["proto_tcp"]},
                {"Protocol": "UDP", "Count": snap.udp_count, "Color": COLOR_PALETTE["proto_udp"]},
                {"Protocol": "ICMP", "Count": snap.icmp_count, "Color": COLOR_PALETTE["proto_icmp"]},
                {"Protocol": "OTHER", "Count": snap.other_count, "Color": COLOR_PALETTE["proto_other"]},
            ]
            df_proto = pd.DataFrame(data)
            df_proto["Percentage"] = (df_proto["Count"] / total * 100).round(1)

            try:
                donut = alt.Chart(df_proto).mark_arc(innerRadius=50, outerRadius=86, stroke="#0A0F1D", strokeWidth=2).encode(
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
                        legend=alt.Legend(orient="bottom", labelColor="#94A3B8", title=None, symbolType="circle"),
                    ),
                    tooltip=[
                        alt.Tooltip("Protocol:N"),
                        alt.Tooltip("Count:Q", format=","),
                        alt.Tooltip("Percentage:Q", format=".1f", title="Share (%)"),
                    ],
                ).properties(height=210, background="transparent")

                st.altair_chart(donut, use_container_width=True)
            except Exception as e:
                logger.error(f"Altair donut chart fallback: {e}")
                for row in data:
                    pct = (row["Count"] / total * 100) if total else 0
                    st.progress(pct / 100.0, text=f"{row['Protocol']}: {row['Count']} ({pct:.1f}%)")
        else:
            st.markdown(
                """
                <div style="background: linear-gradient(145deg, #0F172A 0%, #0A0F1D 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 34px 20px; text-align: center; color: #94A3B8; box-shadow: 0 8px 30px -4px rgba(0, 0, 0, 0.4);">
                    <div style="font-size: 22px; margin-bottom: 6px;">⏳</div>
                    <div style="font-size: 14px; font-weight: 600; color: #F1F5F9;">No packets captured yet</div>
                    <div style="font-size: 12px; margin-top: 4px;">Click <strong style="color: #00C8FF;">▶ START</strong> above to display protocol split</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with c_right:
        st.markdown(
            """
            <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.9px; color: #94A3B8; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
                <span>🌐 Top Communicating Endpoints</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if snap.top_sources or snap.top_destinations:
            endpoint_counts = {}
            for ip, cnt in snap.top_sources:
                endpoint_counts[ip] = endpoint_counts.get(ip, 0) + cnt
            for ip, cnt in snap.top_destinations:
                endpoint_counts[ip] = endpoint_counts.get(ip, 0) + cnt

            sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            df_endpoints = pd.DataFrame(sorted_endpoints, columns=["IP Address", "Packets"])

            try:
                bars = alt.Chart(df_endpoints).mark_bar(cornerRadiusTopRight=6, cornerRadiusBottomRight=6, color="#00C8FF").encode(
                    x=alt.X("Packets:Q", title="Packet Count", axis=alt.Axis(labelColor="#94A3B8", titleColor="#94A3B8")),
                    y=alt.Y("IP Address:N", sort="-x", title=None, axis=alt.Axis(labelColor="#F8FAFC")),
                    tooltip=["IP Address", "Packets"],
                ).properties(height=210, background="transparent")

                st.altair_chart(bars, use_container_width=True)
            except Exception as e:
                logger.error(f"Altair bar chart fallback: {e}")
                for ip, cnt in sorted_endpoints:
                    st.write(f"• **{ip}**: {cnt} packets")
        else:
            st.markdown(
                """
                <div style="background: linear-gradient(145deg, #0F172A 0%, #0A0F1D 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 34px 20px; text-align: center; color: #94A3B8; box-shadow: 0 8px 30px -4px rgba(0, 0, 0, 0.4);">
                    <div style="font-size: 22px; margin-bottom: 6px;">📡</div>
                    <div style="font-size: 14px; font-weight: 600; color: #F1F5F9;">Awaiting Network Endpoints</div>
                    <div style="font-size: 12px; margin-top: 4px;">Top talker IPs will be ranked here during capture</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
