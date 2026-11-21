"""Past analyses stored in the database."""

import streamlit as st

import ui
from portscan import database

ui.page_setup("Detection History")
st.caption("Every saved analysis, newest first. Select one to see the services it found.")

with database.open_db() as conn:
    history = database.list_analyses(conn)

if history.empty:
    st.info("No analyses have been saved yet. Analyse a file on the **Analyse** page with "
            "\"Save this analysis to the history\" ticked.")
    st.stop()

total_scans = int(history["scan_flows"].sum())
c1, c2, c3 = st.columns(3)
c1.metric("Saved analyses", len(history))
c2.metric("Flows analysed", f"{int(history['total_flows'].sum()):,}")
c3.metric("Analyses with port scans", int((history["scan_flows"] > 0).sum()))

view = history.assign(scan_pct=(100 * history["scan_flows"] / history["total_flows"].clip(lower=1)).round(2))
event = st.dataframe(
    view, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
    column_order=["log_id", "timestamp", "file_name", "total_flows", "benign_flows", "scan_flows",
                  "scan_pct", "targeted_ports", "high_risk_ports", "model_used"],
    column_config={
        "log_id": st.column_config.NumberColumn("#", format="%d"),
        "timestamp": "Date and time",
        "file_name": "File",
        "total_flows": st.column_config.NumberColumn("Flows", format="%d"),
        "benign_flows": st.column_config.NumberColumn("Benign", format="%d"),
        "scan_flows": st.column_config.NumberColumn("Port scan", format="%d"),
        "scan_pct": st.column_config.NumberColumn("Scan %", format="%.2f%%"),
        "targeted_ports": st.column_config.NumberColumn("Ports targeted", format="%d"),
        "high_risk_ports": st.column_config.NumberColumn("High-risk", format="%d"),
        "model_used": "Model",
    })

rows = event.selection.rows
if not rows:
    st.caption("Click a row to see its targeted services.")
    st.stop()

log = view.iloc[rows[0]]
log_id = int(log["log_id"])
st.subheader(f"Analysis #{log_id}: {log['file_name']}")
st.caption(f"{log['timestamp']} · {int(log['total_flows']):,} flows · {int(log['scan_flows']):,} port scan flows · {log['model_used']}")

with database.open_db() as conn:
    services = database.get_targeted_services(conn, log_id)

if services.empty:
    st.success("No scanning activity was detected in this analysis.")
else:
    services = services.assign(share_pct=(100 * services["hit_count"] / services["hit_count"].sum()).round(2))
    named = ui.named_services(services)
    unknown = len(services) - len(named)
    st.caption(f"{len(services):,} ports targeted: {len(named):,} known services and {unknown:,} "
               "ports with no listed service.")
    left, right = st.columns([3, 2])
    if named.empty:
        left.info("None of the targeted ports belong to a service in the service map.")
    else:
        left.markdown(f"**Most-targeted known services** (top {min(15, len(named))} of {len(named)})")
        left.plotly_chart(ui.services_chart(named.assign(description="")), width="stretch",
                          config=ui.PLOTLY_CONFIG)
    only_named = right.toggle("Show known services only", value=True)
    right.dataframe(ui.style_services(named if only_named else services), column_config=ui.SERVICE_COLUMNS,
                    hide_index=True, width="stretch", height=420)
    right.download_button("Download these services (CSV)", services.to_csv(index=False),
                          f"analysis_{log_id}_services.csv", "text/csv")

with st.expander("Delete this analysis"):
    st.write("This permanently removes the analysis and its targeted services from the history.")
    if st.button(f"Delete analysis #{log_id}", type="secondary"):
        with database.open_db() as conn:
            database.delete_analysis(conn, log_id)
        st.rerun()
