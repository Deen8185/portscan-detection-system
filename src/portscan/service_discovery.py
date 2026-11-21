"""Service discovery: turn detected scans into a list of targeted services.

This follows the ServiceDiscovery algorithm in Section 3.3.3:

    scanFlows  <- flows WHERE prediction = PORTSCAN
    IF scanFlows is empty THEN RETURN "No scanning activity detected"
    portCounts <- COUNT scanFlows GROUP BY DestinationPort
    FOR EACH (port, count): look the port up in the service map
    SORT results BY count DESCENDING

It is passive: it sends no probes and only reads the destination ports of
flows that the model has already classified as port scans.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from . import config
from .service_map import RISK_ORDER, lookup, port_range

NO_SCAN_MESSAGE = "No scanning activity detected"
RESULT_COLUMNS = ["port", "protocol", "service", "description", "risk_level",
                  "hit_count", "share_pct", "port_range"]


@dataclass
class DiscoveryResult:
    services: pd.DataFrame          # one row per targeted port, most hit first
    scan_flows: int                 # flows classified as port scans
    message: str = ""               # NO_SCAN_MESSAGE when nothing was found

    @property
    def found(self) -> bool:
        return self.scan_flows > 0

    def risk_summary(self) -> pd.DataFrame:
        """Number of targeted ports and scan flows per risk level."""
        if not self.found:
            return pd.DataFrame(columns=["risk_level", "ports", "hit_count"])
        s = (self.services.groupby("risk_level")
             .agg(ports=("port", "count"), hit_count=("hit_count", "sum"))
             .reset_index())
        return s.sort_values("risk_level", key=lambda c: c.map(RISK_ORDER)).reset_index(drop=True)

    def range_summary(self) -> pd.DataFrame:
        """Number of targeted ports in each IANA port range."""
        if not self.found:
            return pd.DataFrame(columns=["port_range", "ports"])
        return (self.services.groupby("port_range").size().rename("ports").reset_index())


def discover_services(flows: pd.DataFrame, predictions) -> DiscoveryResult:
    """Map the destination ports of flows predicted as port scans to services.

    ``flows`` must contain the Destination Port column; ``predictions`` holds
    1 for port scan and 0 for benign, one value per row of ``flows``.
    """
    preds = pd.Series(predictions, index=flows.index)
    scan_ports = flows.loc[preds == 1, config.DESTINATION_PORT_COLUMN]
    if scan_ports.empty:
        return DiscoveryResult(pd.DataFrame(columns=RESULT_COLUMNS), 0, NO_SCAN_MESSAGE)

    counts = scan_ports.astype(int).value_counts()
    rows = []
    for port, count in counts.items():
        info = lookup(port)
        rows.append({"port": int(port), **info, "hit_count": int(count),
                     "share_pct": round(100 * count / len(scan_ports), 2),
                     "port_range": port_range(port)})
    services = pd.DataFrame(rows, columns=RESULT_COLUMNS)
    # Most-hit first; among equal counts, the riskier service first, then by port.
    services = services.sort_values(
        ["hit_count", "risk_level", "port"],
        ascending=[False, True, True],
        key=lambda c: c.map(RISK_ORDER) if c.name == "risk_level" else c,
    ).reset_index(drop=True)
    return DiscoveryResult(services, int(len(scan_ports)))


def targeted_hosts(flows: pd.DataFrame, predictions) -> pd.DataFrame:
    """Per destination host: scan flows, distinct ports probed and high-risk
    services probed. Needs a Destination IP column; empty otherwise."""
    if "Destination IP" not in flows.columns:
        return pd.DataFrame(columns=["destination_ip", "scan_flows", "ports_probed", "high_risk_ports"])
    preds = pd.Series(predictions, index=flows.index)
    scans = flows.loc[preds == 1, ["Destination IP", config.DESTINATION_PORT_COLUMN]]
    if scans.empty:
        return pd.DataFrame(columns=["destination_ip", "scan_flows", "ports_probed", "high_risk_ports"])
    scans = scans.assign(high=scans[config.DESTINATION_PORT_COLUMN].map(lambda p: lookup(p)["risk_level"] == "High"))
    out = scans.groupby("Destination IP").agg(
        scan_flows=(config.DESTINATION_PORT_COLUMN, "size"),
        ports_probed=(config.DESTINATION_PORT_COLUMN, "nunique"),
        high_risk_ports=(config.DESTINATION_PORT_COLUMN,
                         lambda s: s[scans.loc[s.index, "high"]].nunique()),
    ).reset_index().rename(columns={"Destination IP": "destination_ip"})
    return out.sort_values("scan_flows", ascending=False).reset_index(drop=True)
