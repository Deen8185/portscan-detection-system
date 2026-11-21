"""Tests for the service map and the service discovery module."""

import pandas as pd

from portscan.service_discovery import (NO_SCAN_MESSAGE, discover_services,
                                        targeted_hosts)
from portscan.service_map import (HIGH, RISK_ORDER, SERVICE_MAP, SERVICES,
                                  UNKNOWN, lookup, port_range)


def flows(ports, ips=None):
    df = pd.DataFrame({"Destination Port": ports})
    if ips is not None:
        df["Destination IP"] = ips
    return df


# ---------------------------------------------------------------- service map
def test_service_map_has_unique_ports_and_valid_risks():
    ports = [row[0] for row in SERVICE_MAP]
    assert len(ports) == len(set(ports))
    assert all(row[4] in RISK_ORDER for row in SERVICE_MAP)
    assert all(len(row[3]) <= 100 for row in SERVICE_MAP)   # fits Table 3.2 size


def test_common_ports_match_table_2_1():
    expected = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
                443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"}
    for port, name in expected.items():
        assert SERVICES[port]["service"] == name


def test_unencrypted_remote_access_is_high_risk():
    for port in (21, 23, 445, 3389):
        assert lookup(port)["risk_level"] == HIGH


def test_unknown_port():
    info = lookup(1107)
    assert info["service"] == "Unknown service" and info["risk_level"] == UNKNOWN


def test_port_ranges():
    assert port_range(22) == "Well-known (0-1023)"
    assert port_range(3306) == "Registered (1024-49151)"
    assert port_range(65129) == "Dynamic (49152-65535)"


# ---------------------------------------------------------------- discovery
def test_no_scans_returns_message():
    result = discover_services(flows([80, 443]), [0, 0])
    assert not result.found and result.message == NO_SCAN_MESSAGE
    assert result.services.empty and result.risk_summary().empty


def test_only_predicted_scans_are_counted():
    result = discover_services(flows([22, 22, 80, 3389, 443]), [1, 1, 0, 1, 0])
    assert result.scan_flows == 3
    assert set(result.services["port"]) == {22, 3389}


def test_sorted_by_hits_then_risk():
    # 22 hit 3 times; 3389 (High) and 443 (Low) once each: RDP must come before HTTPS
    result = discover_services(flows([22, 22, 22, 443, 3389]), [1] * 5)
    assert list(result.services["port"]) == [22, 3389, 443]
    assert list(result.services["hit_count"]) == [3, 1, 1]
    assert result.services["share_pct"].sum() == 100


def test_unknown_ports_are_reported():
    result = discover_services(flows([1107, 22]), [1, 1])
    row = result.services.set_index("port").loc[1107]
    assert row.service == "Unknown service" and row.risk_level == UNKNOWN


def test_risk_and_range_summaries():
    result = discover_services(flows([21, 23, 22, 443, 50000]), [1] * 5)
    risk = result.risk_summary().set_index("risk_level")
    assert risk.loc["High", "ports"] == 2 and risk.loc[UNKNOWN, "ports"] == 1
    assert list(result.risk_summary()["risk_level"]) == ["High", "Medium", "Low", "Unknown"]
    ranges = result.range_summary().set_index("port_range")["ports"]
    assert ranges["Well-known (0-1023)"] == 4 and ranges["Dynamic (49152-65535)"] == 1


def test_targeted_hosts():
    df = flows([22, 23, 23, 80, 445], ips=["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2"])
    hosts = targeted_hosts(df, [1, 1, 1, 1, 0]).set_index("destination_ip")
    assert hosts.loc["10.0.0.1", "scan_flows"] == 3
    assert hosts.loc["10.0.0.1", "ports_probed"] == 2
    assert hosts.loc["10.0.0.1", "high_risk_ports"] == 1      # Telnet
    assert hosts.loc["10.0.0.2", "high_risk_ports"] == 0      # 445 was not a scan


def test_targeted_hosts_without_ip_column():
    assert targeted_hosts(flows([22]), [1]).empty
