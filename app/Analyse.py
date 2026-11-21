"""Main page: upload network flows, detect port scans and discover targeted services.

Start the dashboard from the project folder:
    streamlit run app/Analyse.py
"""

import time

import pandas as pd
import streamlit as st

import ui
from portscan import config, database
from portscan.pipeline import (PREDICTION_COLUMN, PROBABILITY_COLUMN,
                               InvalidFlowFile, analyse_flows)

ui.page_setup("Analyse Network Flows")
st.caption("Upload network flow records (a CSV file produced by CICFlowMeter). The system "
           "classifies every flow as benign or port scan, then shows which services the "
           "scans were aimed at.")
ui.require_model()
model, meta = ui.get_model()

# ---------------------------------------------------------------- input
samples = sorted(p.name for p in config.SAMPLES_DIR.glob("*.csv"))
source = st.radio("Flow records", ["Upload a file", "Use a sample file"], horizontal=True,
                  label_visibility="collapsed")
upload, sample_name = None, None
if source == "Upload a file":
    upload = st.file_uploader("CICFlowMeter CSV file", type="csv",
                              help=f"Needs these {len(config.REQUIRED_UPLOAD_COLUMNS)} columns: "
                                   + ", ".join(config.REQUIRED_UPLOAD_COLUMNS))
else:
    sample_name = st.selectbox("Sample file", samples,
                               help="Samples are real CICIDS2017 flows the model did not see during training.")

col_a, col_b = st.columns([1, 3])
save = col_b.checkbox("Save this analysis to the history", value=True)
run = col_a.button("Analyse", type="primary", disabled=upload is None and sample_name is None)

if run:
    file_name = upload.name if upload is not None else sample_name
    try:
        with st.spinner(f"Reading {file_name} ..."):
            src = upload if upload is not None else config.SAMPLES_DIR / sample_name
            df = pd.read_csv(src, encoding="latin1", low_memory=False)
        with st.spinner(f"Classifying {len(df):,} flows ..."):
            start = time.perf_counter()
            if save:
                with database.open_db() as conn:
                    result = analyse_flows(df, model=model, model_name=meta["model_name"],
                                           file_name=file_name, conn=conn)
            else:
                result = analyse_flows(df, model=model, model_name=meta["model_name"], file_name=file_name)
            seconds = time.perf_counter() - start
        st.session_state["result"] = result
        st.session_state["result_meta"] = {"file_name": file_name, "seconds": seconds}
    except InvalidFlowFile as exc:
        st.session_state.pop("result", None)
        st.error(f"**{file_name} cannot be analysed.** {exc}")
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        st.session_state.pop("result", None)
        st.error(f"**{file_name} is not a readable CSV file.** {exc}")

result = st.session_state.get("result")
if result is None:
    st.stop()
info = st.session_state["result_meta"]

# ---------------------------------------------------------------- 1. summary
st.divider()
st.subheader(f"Results for {info['file_name']}")
saved = f" Saved as analysis #{result.log_id}." if result.log_id else " Not saved to the history."
st.caption(f"{result.total_flows:,} flows classified by {result.model_used} in {info['seconds']:.1f} s.{saved}")
if result.skipped_flows:
    st.warning(f"{result.skipped_flows:,} row(s) were skipped because they contain missing or "
               "infinite values.")

d = result.discovery
high = int((d.services["risk_level"] == "High").sum()) if d.found else 0
m1, m2, m3, m4 = st.columns(4)
m1.metric("Flows analysed", f"{result.total_flows:,}")
m2.metric("Benign", f"{result.benign_flows:,}")
m3.metric("Port scan", f"{result.scan_flows:,}",
          f"{100 * result.scan_flows / max(result.total_flows, 1):.1f}% of traffic",
          delta_color="off", delta_arrow="off")
m4.metric("High-risk services targeted", high)

if not d.found:
    st.success(f"**{d.message}.** All flows in this file were classified as benign.")
    st.plotly_chart(ui.traffic_split_chart(result.benign_flows, 0), width="stretch", config=ui.PLOTLY_CONFIG)
    st.stop()

if high:
    names = ", ".join(f"{r.service} ({r.port})" for r in d.services[d.services["risk_level"] == "High"].head(8).itertuples())
    st.error(f"**Port scanning detected.** {high} high-risk service(s) were probed: {names}"
             + (" and more." if high > 8 else "."))
else:
    st.warning("**Port scanning detected.** No high-risk services were probed.")

# ---------------------------------------------------------------- 2. traffic split
st.plotly_chart(ui.traffic_split_chart(result.benign_flows, result.scan_flows), width="stretch",
                config=ui.PLOTLY_CONFIG)

# ---------------------------------------------------------------- 3. services
st.subheader("Discovered services")
named = ui.named_services(d.services)
unknown = d.services[d.services["risk_level"] == "Unknown"]
st.caption(f"{len(d.services):,} distinct ports were targeted by {d.scan_flows:,} scan flows: "
           f"{len(named):,} known services and {len(unknown):,} ports with no listed service "
           f"({int(unknown['hit_count'].sum()):,} scan flows).")
left, right = st.columns([3, 2])
with left:
    if named.empty:
        st.info("None of the targeted ports belong to a service in the service map.")
    else:
        st.markdown(f"**Most-targeted known services** (top {min(15, len(named))} of {len(named)})")
        st.plotly_chart(ui.services_chart(named), width="stretch", config=ui.PLOTLY_CONFIG)
with right:
    risk = d.risk_summary()
    st.markdown("**By risk level**")
    st.dataframe(risk.rename(columns={"risk_level": "Risk", "ports": "Ports", "hit_count": "Scan flows"}),
                 hide_index=True, width="stretch")
    st.markdown("**By port range**")
    st.dataframe(d.range_summary().rename(columns={"port_range": "Range", "ports": "Ports"}),
                 hide_index=True, width="stretch")
    if not result.hosts.empty:
        st.markdown("**Targeted hosts**")
        st.dataframe(result.hosts.head(10).rename(columns={
            "destination_ip": "Host", "scan_flows": "Flows", "ports_probed": "Ports",
            "high_risk_ports": "High-risk"}), hide_index=True, width="stretch")

only_named = st.toggle("Show known services only", value=True,
                       help="Hide ports that are not in the service map.")
table = named if only_named else d.services
st.caption(f"{len(table):,} rows, most-targeted first. High-risk rows are shaded red, medium-risk rows amber.")
st.dataframe(ui.style_services(table), column_config=ui.SERVICE_COLUMNS,
             hide_index=True, width="stretch", height=360)

# ---------------------------------------------------------------- 4. flagged flows
st.subheader("Flagged flows")
flagged = result.flagged
show_cols = [c for c in ["Timestamp", "Source IP", "Source Port", "Destination IP",
                         config.DESTINATION_PORT_COLUMN, "Protocol", "Flow Duration",
                         "Total Fwd Packets", "Total Backward Packets",
                         PROBABILITY_COLUMN, PREDICTION_COLUMN] if c in flagged.columns]
limit = 1000
st.caption(f"{len(flagged):,} flows were classified as port scans"
           + (f"; the first {limit:,} are shown. Download the report for all of them." if len(flagged) > limit else "."))
st.dataframe(flagged[show_cols].head(limit), hide_index=True, width="stretch", height=320,
             column_config={PROBABILITY_COLUMN: st.column_config.ProgressColumn(
                 PROBABILITY_COLUMN, min_value=0.0, max_value=1.0, format="%.2f")})

# ---------------------------------------------------------------- 5. downloads
st.subheader("Download report")
stem = info["file_name"].rsplit(".", 1)[0]
c1, c2, c3 = st.columns(3)
c1.download_button("Targeted services (CSV)", d.services.to_csv(index=False),
                   f"{stem}_targeted_services.csv", "text/csv", width="stretch")
c2.download_button("Flagged flows (CSV)", flagged.to_csv(index=False),
                   f"{stem}_flagged_flows.csv", "text/csv", width="stretch")
c3.download_button("All flows with predictions (CSV)", result.flows.to_csv(index=False),
                   f"{stem}_all_predictions.csv", "text/csv", width="stretch")
