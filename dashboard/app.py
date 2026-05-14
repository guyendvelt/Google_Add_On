"""Malicious Email Scorer — Threat Intelligence & Analytics Center (Stage 3).

A Streamlit-based Security Intelligence Center over the scoring backend.
Reads only the aggregated /api/stats endpoint — never the raw scans_history
table — so the PII boundaries enforced at the API layer apply here too.

Run locally:   streamlit run dashboard/app.py
In Docker:     compose service "dashboard", exposed on :8501
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

# Optional dependency: enables true interval-based auto-refresh. The dashboard
# degrades gracefully to manual-refresh-only if the package isn't installed.
try:
    from streamlit_autorefresh import st_autorefresh
    _HAS_AUTOREFRESH = True
except ImportError:  # pragma: no cover - environment-dependent
    _HAS_AUTOREFRESH = False

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
STATS_ENDPOINT = f"{BACKEND_URL}/api/stats"
REQUEST_TIMEOUT_SECONDS = 10

# Same 5-band palette as the Gmail Add-on card, so admins and end-users
# see the same colors for the same verdicts.
VERDICT_COLORS = {
    "Safe":       "#188038",
    "Low Risk":   "#AFB42B",
    "Suspicious": "#F9A825",
    "High Risk":  "#EF6C00",
    "Malicious":  "#C62828",
}
THREAT_VERDICTS = ("Suspicious", "High Risk", "Malicious")

# Accent used for the card glow + chart highlights.
ACCENT = "#2F81F7"

st.set_page_config(
    page_title="Email Security — Threat Intelligence & Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------------------------------
# Global styling — Security Intelligence Center theme
# --------------------------------------------------------------------------
st.markdown(
    """
    <style>
        .main { background-color: #0B0E14; }
        h1, h2, h3 { color: #FAFAFA; letter-spacing: 0.4px; }

        /* --- App header --- */
        .app-header {
            display: flex; align-items: center; gap: 1.1rem;
            padding: 0.2rem 0 0.4rem 0;
        }
        .app-logo {
            font-size: 3rem; line-height: 1;
            filter: drop-shadow(0 0 10px rgba(47,129,247,0.55));
        }
        .app-title {
            font-size: 1.85rem; font-weight: 800; color: #F5F7FA;
            letter-spacing: 0.4px;
        }
        .app-title span { color: #2F81F7; margin: 0 0.35rem; }
        .app-subtitle {
            color: #8B949E; font-size: 0.95rem; margin-top: 0.15rem;
            letter-spacing: 0.3px;
        }

        /* --- Analysis Cards: every bordered container --- */
        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: linear-gradient(160deg, #161B24 0%, #0E1117 100%);
            border: 1px solid #2A2E37;
            border-radius: 14px;
            padding: 1.05rem 1.25rem;
            box-shadow: 0 4px 18px rgba(0,0,0,0.35);
            transition: border-color .25s ease, box-shadow .25s ease;
        }
        div[data-testid="stVerticalBlockBorderWrapper"]:hover {
            border-color: #2F81F7;
            box-shadow: 0 0 20px rgba(47,129,247,0.22),
                        0 4px 22px rgba(0,0,0,0.45);
        }

        /* --- Card titles --- */
        .card-title {
            font-size: 0.82rem; font-weight: 700; color: #E8EAED;
            text-transform: uppercase; letter-spacing: 1.4px;
            margin-bottom: 0.55rem; padding-left: 0.6rem;
            border-left: 3px solid #2F81F7;
        }

        /* --- Metrics --- */
        [data-testid="stMetricValue"] {
            font-family: "Courier New", monospace; font-weight: bold;
            color: #F5F7FA;
        }
        [data-testid="stMetricLabel"] {
            color: #8B949E !important; text-transform: uppercase;
            letter-spacing: 1.5px; font-size: 0.72rem;
        }

        /* --- Sidebar --- */
        section[data-testid="stSidebar"] > div { background-color: #11151C; }
        section[data-testid="stSidebar"] .card-title { margin-top: 0.4rem; }

        /* --- "All Clear" empty state --- */
        .clean-state {
            text-align: center; padding: 1.6rem 1rem;
            border: 1px dashed #2F6F4F; border-radius: 12px;
            background: rgba(24,128,56,0.06);
        }
        .clean-icon {
            font-size: 2.4rem;
            filter: drop-shadow(0 0 8px rgba(24,128,56,0.6));
        }
        .clean-title {
            color: #4ADE80; font-weight: 700; letter-spacing: 0.6px;
            margin: 0.35rem 0 0.2rem 0; text-transform: uppercase;
            font-size: 0.9rem;
        }
        .clean-msg { color: #8B949E; font-size: 0.88rem; }

        /* --- Filter badge --- */
        .filter-badge {
            display: inline-block; padding: 0.15rem 0.6rem;
            border-radius: 999px; font-size: 0.72rem; font-weight: 700;
            letter-spacing: 0.8px; background: rgba(47,129,247,0.15);
            color: #2F81F7; border: 1px solid rgba(47,129,247,0.4);
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------
# Reusable UI helpers
# --------------------------------------------------------------------------

def card_title(icon: str, text: str) -> None:
    st.markdown(
        f"<div class='card-title'>{icon}&nbsp;&nbsp;{text}</div>",
        unsafe_allow_html=True,
    )


def render_clean_state(message: str) -> None:
    """Stylized 'Clean Environment' graphic for empty/no-threat panels."""
    st.markdown(
        f"""
        <div class="clean-state">
            <div class="clean-icon">🛡️</div>
            <div class="clean-title">Analytics Status: All Clear</div>
            <div class="clean-msg">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def style_chart(fig, *, showlegend: bool = False) -> None:
    """Apply the shared dark-theme layout to a Plotly figure."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#C9D1D9",
        showlegend=showlegend,
        margin=dict(t=10, b=10, l=10, r=10),
        xaxis=dict(gridcolor="#21262D"),
        yaxis=dict(gridcolor="#21262D"),
    )


# --------------------------------------------------------------------------
# Data fetch — cache-busted by the auto-refresh tick so each interval pulls
# fresh data, while reruns within an interval reuse the cached payload.
# --------------------------------------------------------------------------

@st.cache_data(ttl=300, show_spinner=False)
def fetch_stats(refresh_tick: int) -> dict | None:
    try:
        resp = requests.get(STATS_ENDPOINT, timeout=REQUEST_TIMEOUT_SECONDS)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        st.error(f"⚠️  Threat-intelligence backend unreachable at {STATS_ENDPOINT}: {e}")
        return None


# --------------------------------------------------------------------------
# Sidebar — Analytics Control
# --------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ Analytics Control")
    st.caption("Forensic view configuration")
    st.divider()

    card_title("⏱️", "Live Refresh")
    refresh_secs = st.slider(
        "Update interval (seconds)",
        min_value=10, max_value=300, value=60, step=10,
        help="How often the dashboard pulls fresh aggregates from /api/stats.",
    )
    if not _HAS_AUTOREFRESH:
        st.caption(
            "⚠️ `streamlit-autorefresh` not installed — using manual refresh only."
        )

    st.divider()
    card_title("🎯", "Risk Filter")
    risk_filter = st.radio(
        "Forensic focus",
        options=["All Threats", "High Risk", "Malicious"],
        index=0,
        help=(
            "Filters the forensic threat feed below. /api/stats is "
            "pre-aggregated server-side, so this is a client-side view filter "
            "over the High-Risk/Malicious feed the backend returns."
        ),
    )

    st.divider()
    if st.button("⟳  Refresh Now", use_container_width=True):
        fetch_stats.clear()
        st.rerun()

# True interval refresh (if the package is available). The returned counter
# increments every interval and is used to bust the data cache.
refresh_tick = (
    st_autorefresh(interval=refresh_secs * 1000, key="data_refresh")
    if _HAS_AUTOREFRESH
    else 0
)


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------

st.markdown(
    """
    <div class="app-header">
        <span class="app-logo">🛡️</span>
        <div>
            <div class="app-title">Email Security <span>|</span> Threat Intelligence &amp; Analytics</div>
            <div class="app-subtitle">Real-time forensic analysis and system-wide security metrics.</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.divider()

stats = fetch_stats(refresh_tick)
if not stats:
    st.stop()

risk_by_verdict = {p["verdict"]: p for p in stats["risk_distribution"]}


# --------------------------------------------------------------------------
# Derived intelligence — turn raw counts into high-level metrics + trends.
# Trends are computed from the only time-series the API exposes (daily_volume):
# "today" vs "yesterday". A true hourly delta would need the backend to
# expose hourly buckets
# --------------------------------------------------------------------------

total_scans = stats["total_scans"]
threats_detected = sum(risk_by_verdict[v]["count"] for v in THREAT_VERDICTS)
malicious_count = risk_by_verdict["Malicious"]["count"]
detection_rate = (100.0 * threats_detected / total_scans) if total_scans else 0.0

daily = stats["daily_volume"]  # oldest-first, gap-filled, 7 entries
today_count = daily[-1]["count"] if daily else 0
yesterday_count = daily[-2]["count"] if len(daily) >= 2 else 0
delta_today = today_count - yesterday_count
if yesterday_count:
    delta_today_pct = 100.0 * delta_today / yesterday_count
    today_delta_label = f"{delta_today_pct:+.1f}% vs yesterday"
else:
    today_delta_label = f"{delta_today:+d} vs yesterday" if delta_today else None


# --------------------------------------------------------------------------
# Metric row — four Analysis Cards
# --------------------------------------------------------------------------

m1, m2, m3, m4 = st.columns(4)

with m1:
    with st.container(border=True):
        st.metric(
            "Total Scans Analyzed",
            f"{total_scans:,}",
            delta=(f"{delta_today:+d} today" if delta_today else None),
            help="All emails scored by the backend, all time.",
        )

with m2:
    with st.container(border=True):
        st.metric(
            "Scans — Last 24h",
            f"{today_count:,}",
            delta=today_delta_label,
            help="Scans recorded today (UTC) vs. yesterday — from daily_volume.",
        )

with m3:
    with st.container(border=True):
        st.metric(
            "Active Threats Detected",
            f"{threats_detected:,}",
            help="Scans in the Suspicious / High Risk / Malicious bands.",
        )
        st.caption(f"🛑 {malicious_count:,} confirmed malicious")

with m4:
    with st.container(border=True):
        st.metric(
            "Threat Detection Rate",
            f"{detection_rate:.1f}%",
            help="Share of all scans that landed in a threat band.",
        )
        st.caption(f"✅ {total_scans - threats_detected:,} clean scans")

st.write("")


# --------------------------------------------------------------------------
# Analytics row 1 — Risk Distribution + Top Malicious Senders
# --------------------------------------------------------------------------

a1, a2 = st.columns(2)

with a1:
    with st.container(border=True):
        card_title("🧬", "Risk Distribution Spectrum")
        dist_df = pd.DataFrame(stats["risk_distribution"])
        nonzero = dist_df[dist_df["count"] > 0]
        if nonzero.empty:
            render_clean_state(
                "No scans recorded yet. The risk spectrum will populate "
                "as emails are analyzed."
            )
        else:
            fig = px.pie(
                nonzero,
                values="count",
                names="verdict",
                color="verdict",
                color_discrete_map=VERDICT_COLORS,
                hole=0.55,
                category_orders={"verdict": list(VERDICT_COLORS.keys())},
            )
            fig.update_traces(
                textinfo="percent+label",
                textfont_color="#FAFAFA",
                marker=dict(line=dict(color="#0B0E14", width=2)),
            )
            style_chart(fig, showlegend=True)
            fig.update_layout(
                legend=dict(orientation="v", yanchor="middle", y=0.5,
                            xanchor="left", x=1.0),
            )
            st.plotly_chart(fig, use_container_width=True)

with a2:
    with st.container(border=True):
        card_title("🚨", "Top 5 Malicious Senders — Threat Volume")
        offenders = stats["top_malicious_domains"]
        if not offenders:
            render_clean_state(
                "No senders have reached a Malicious verdict. No repeat "
                "offenders in the current database partition."
            )
        else:
            off_df = pd.DataFrame(offenders).sort_values("malicious_count")
            fig = px.bar(
                off_df,
                x="malicious_count",
                y="domain",
                orientation="h",
                text="malicious_count",
                color_discrete_sequence=[VERDICT_COLORS["Malicious"]],
            )
            fig.update_traces(
                textposition="outside",
                textfont_color="#C9D1D9",
                marker_line_color=VERDICT_COLORS["High Risk"],
                marker_line_width=1,
            )
            style_chart(fig)
            fig.update_layout(
                xaxis_title="Malicious-verdict scans",
                yaxis_title=None,
            )
            st.plotly_chart(fig, use_container_width=True)


# --------------------------------------------------------------------------
# Forensic threat feed — Recent High-Risk & Malicious Scans (risk-filtered)
# --------------------------------------------------------------------------

with st.container(border=True):
    badge = (
        f"<span class='filter-badge'>FILTER · {risk_filter.upper()}</span>"
        if risk_filter != "All Threats" else ""
    )
    st.markdown(
        f"<div class='card-title'>🔬&nbsp;&nbsp;Forensic Threat Feed — "
        f"Recent High-Risk &amp; Malicious Scans &nbsp;{badge}</div>",
        unsafe_allow_html=True,
    )

    recent = stats["recent_threats"]
    if risk_filter != "All Threats":
        recent = [r for r in recent if r["verdict"] == risk_filter]

    if not recent:
        if risk_filter != "All Threats":
            render_clean_state(
                f"All clear. No active '{risk_filter}' threats identified in "
                "the current database partition."
            )
        else:
            render_clean_state(
                "All clear. No High-Risk or Malicious activity identified in "
                "the current database partition."
            )
    else:
        df = pd.DataFrame(recent)
        df["timestamp"] = (
            pd.to_datetime(df["timestamp"], utc=True)
              .dt.strftime("%Y-%m-%d %H:%M UTC")
        )
        df = df[["timestamp", "domain", "verdict", "score"]]
        df.columns = ["Time (UTC)", "Sender Domain", "Verdict", "Risk Score"]
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
        )


# --------------------------------------------------------------------------
# Footer
# --------------------------------------------------------------------------

st.divider()
refresh_mode = (
    f"auto every {refresh_secs}s" if _HAS_AUTOREFRESH else "manual"
)
st.caption(
    f"🛰️  Intelligence source: `{STATS_ENDPOINT}`  ·  "
    f"Last sync: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ·  "
    f"Refresh: {refresh_mode}  ·  "
    f"PII-safe: domain-level aggregates only"
)
