"""The port-to-service map used by service discovery."""

import streamlit as st

import ui
from portscan import database

ui.page_setup("Service Map")
st.caption("Service discovery looks up each scanned port in this table (stored in the "
           "service_map database table). Ports that are not listed are reported as "
           "\"Unknown service\".")

with st.expander("How risk levels are assigned", expanded=True):
    st.markdown(
        "- **High**: gives remote control, file or database access, or sends data without "
        "encryption (e.g. Telnet, FTP, SMB, RDP, databases).\n"
        "- **Medium**: normally exposed on purpose but a common target for password guessing "
        "or exploitation (e.g. SSH, HTTP, SMTP, DNS).\n"
        "- **Low**: encrypted or low-impact services (e.g. HTTPS, NTP).\n"
        "- **Unknown**: the port is not in the table, so the service behind it cannot be named.")

with database.open_db() as conn:
    services = database.get_service_map(conn)

risk = st.multiselect("Risk level", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
query = st.text_input("Search by port or service", placeholder="e.g. 3389 or SQL")
view = services[services["risk_level"].isin(risk)]
if query:
    q = query.strip().lower()
    view = view[view["port"].astype(str).str.contains(q) | view["service"].str.lower().str.contains(q)
                | view["description"].str.lower().str.contains(q)]

st.caption(f"{len(view)} of {len(services)} services")
st.dataframe(ui.style_services(view), column_config=ui.SERVICE_COLUMNS,
             hide_index=True, width="stretch", height=560)
