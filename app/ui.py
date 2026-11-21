"""Shared pieces for the dashboard pages: model loading, charts and tables."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from portscan import config
from portscan.modeling import load_model

APP_TITLE = "AI-Based Port Scan Detection System"
BENIGN_COLOR = "#2a78d6"
SCAN_COLOR = "#eb6834"
RISK_COLORS = {"High": "#e34948", "Medium": "#eda100", "Low": "#2a78d6", "Unknown": "#8a8984"}
RISK_ROW_BG = {"High": "#fbe3e2", "Medium": "#fdf1d6"}
TEXT = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e4e3df"


def page_setup(title: str) -> None:
    st.set_page_config(page_title=f"{title} | Port Scan Detection", page_icon="🛡️", layout="wide")
    st.title(title)


@st.cache_resource(show_spinner="Loading the detection model ...")
def get_model():
    """Load the trained model once and share it between users and pages."""
    return load_model()


def model_available() -> bool:
    return config.MODEL_PATH.exists() and config.MODEL_METADATA_PATH.exists()


def require_model() -> None:
    if not model_available():
        st.error("No trained model found. Run `python scripts/train_models.py` first, "
                 "then reload this page.")
        st.stop()


# ---------------------------------------------------------------- charts
def _layout(fig: go.Figure, height: int, **kw) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=30, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT, size=13), hoverlabel=dict(bgcolor="white", font_color=TEXT),
        **kw)
    return fig


def traffic_split_chart(benign: int, scans: int) -> go.Figure:
    """One horizontal bar split into benign and port scan shares."""
    total = max(benign + scans, 1)
    fig = go.Figure()
    for name, value, color in (("Benign", benign, BENIGN_COLOR), ("Port scan", scans, SCAN_COLOR)):
        fig.add_bar(
            y=["Flows"], x=[value], name=name, orientation="h", marker=dict(color=color, line=dict(color="white", width=2)),
            text=[f"{name}: {value:,} ({100 * value / total:.1f}%)" if value / total > 0.12 else ""],
            textposition="inside", insidetextanchor="middle", textfont=dict(color="white", size=14),
            hovertemplate=f"{name}: %{{x:,}} flows ({100 * value / total:.1f}%)<extra></extra>")
    _layout(fig, 120, barmode="stack", showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, traceorder="normal"))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return fig


PLOTLY_CONFIG = {"displayModeBar": False}


def named_services(services: pd.DataFrame) -> pd.DataFrame:
    """Only ports that are in the service map (known service and risk level)."""
    return services[services["risk_level"] != "Unknown"]


def services_chart(services: pd.DataFrame, top: int = 15) -> go.Figure:
    """Most-targeted services as horizontal bars coloured by risk level."""
    d = services.head(top).iloc[::-1]
    labels = [f"{p} {s}" if s != "Unknown service" else f"{p} (unknown)"
              for p, s in zip(d["port"], d["service"])]
    fig = go.Figure()
    for risk, color in RISK_COLORS.items():
        part = d["risk_level"] == risk
        if not part.any():
            continue
        fig.add_bar(
            y=[l for l, keep in zip(labels, part) if keep], x=d.loc[part, "hit_count"],
            orientation="h", name=f"{risk} risk" if risk != "Unknown" else "Unknown",
            marker=dict(color=color), text=d.loc[part, "hit_count"].map("{:,}".format),
            textposition="outside", cliponaxis=False,
            customdata=d.loc[part, ["description", "share_pct"]].values,
            hovertemplate="<b>%{y}</b><br>%{customdata[0]}<br>%{x:,} scan flows "
                          "(%{customdata[1]}%)<extra></extra>")
    _layout(fig, 28 * len(d) + 80, barmode="overlay", showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.0, x=0, traceorder="normal"))
    fig.update_yaxes(categoryorder="array", categoryarray=labels, showgrid=False)
    fig.update_xaxes(title="Scan flows aimed at the port", gridcolor=GRID, zeroline=False)
    return fig


def bar_chart(categories, values, color, x_title: str, height: int = 260) -> go.Figure:
    fig = go.Figure(go.Bar(x=values, y=categories, orientation="h", marker=dict(color=color),
                           text=[f"{v:,}" for v in values], textposition="outside", cliponaxis=False,
                           hovertemplate="%{y}: %{x:,}<extra></extra>"))
    _layout(fig, height, showlegend=False)
    fig.update_xaxes(title=x_title, gridcolor=GRID, zeroline=False)
    fig.update_yaxes(autorange="reversed", showgrid=False)
    return fig


# ---------------------------------------------------------------- tables
def style_services(df: pd.DataFrame):
    """Highlight high- and medium-risk rows."""
    def row_style(row):
        bg = RISK_ROW_BG.get(row.get("risk_level"))
        return [f"background-color: {bg}" if bg else ""] * len(row)
    return df.style.apply(row_style, axis=1)


SERVICE_COLUMNS = {
    "port": st.column_config.NumberColumn("Port", format="%d"),
    "protocol": "Protocol",
    "service": "Service",
    "description": st.column_config.TextColumn("Description", width="large"),
    "risk_level": "Risk",
    "hit_count": st.column_config.NumberColumn("Scan flows", format="%d"),
    "share_pct": st.column_config.NumberColumn("Share", format="%.2f%%"),
    "port_range": "Port range",
}
