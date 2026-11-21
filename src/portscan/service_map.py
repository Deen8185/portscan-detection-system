"""Port-to-service mapping used by the service discovery module.

Service names follow the IANA Service Name and Transport Protocol Port Number
Registry (Cotton et al., 2011). Each port carries a risk level, assigned with
these rules so the choice can be explained in the report:

High    Services that are frequent attack targets because they give remote
        control, file or database access, or send credentials or data
        without encryption (e.g. Telnet, FTP, SMB, RDP, VNC, databases,
        SNMP, Redis, Docker API).
Medium  Services that are often exposed on purpose but are common targets
        for password guessing or exploitation (e.g. SSH, HTTP, SMTP, DNS,
        LDAP, mail retrieval without TLS).
Low     Encrypted or low-impact public services (e.g. HTTPS, IMAPS, NTP).

Ports that are not in the table are reported as "Unknown service" with the
risk level "Unknown", because a port number alone does not reveal what is
listening on it.

This table is the single source for the service_map database table
(Table 3.2), which is filled from it in Phase 4.
"""

HIGH, MEDIUM, LOW, UNKNOWN = "High", "Medium", "Low", "Unknown"
RISK_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, UNKNOWN: 3}

# (port, protocol, service, description, risk level)
SERVICE_MAP = [
    (20, "TCP", "FTP-DATA", "File Transfer Protocol data channel", HIGH),
    (21, "TCP", "FTP", "File Transfer Protocol control; sends passwords in plain text", HIGH),
    (22, "TCP", "SSH", "Secure Shell remote login; common password-guessing target", MEDIUM),
    (23, "TCP", "Telnet", "Unencrypted remote login", HIGH),
    (25, "TCP", "SMTP", "Email transfer between mail servers", MEDIUM),
    (53, "TCP/UDP", "DNS", "Domain name resolution", MEDIUM),
    (69, "UDP", "TFTP", "Trivial File Transfer Protocol; no authentication", HIGH),
    (80, "TCP", "HTTP", "Unencrypted web traffic", MEDIUM),
    (88, "TCP/UDP", "Kerberos", "Network authentication service", MEDIUM),
    (110, "TCP", "POP3", "Email retrieval without encryption", MEDIUM),
    (111, "TCP/UDP", "RPCbind", "ONC RPC port mapper; reveals other RPC services", HIGH),
    (123, "UDP", "NTP", "Network time synchronisation", LOW),
    (135, "TCP", "MSRPC", "Microsoft RPC endpoint mapper", HIGH),
    (137, "UDP", "NetBIOS-NS", "NetBIOS name service (Windows networking)", HIGH),
    (138, "UDP", "NetBIOS-DGM", "NetBIOS datagram service (Windows networking)", HIGH),
    (139, "TCP", "NetBIOS-SSN", "NetBIOS session service; Windows file sharing", HIGH),
    (143, "TCP", "IMAP", "Email access without encryption", MEDIUM),
    (161, "UDP", "SNMP", "Network device management; weak default community strings", HIGH),
    (389, "TCP", "LDAP", "Directory service without encryption", MEDIUM),
    (443, "TCP", "HTTPS", "Encrypted web traffic", LOW),
    (444, "TCP", "SNPP", "Simple Network Paging Protocol", LOW),
    (445, "TCP", "SMB", "Windows file and printer sharing; frequent exploit target", HIGH),
    (465, "TCP", "SMTPS", "Email submission over TLS", LOW),
    (514, "UDP", "Syslog", "System log messages without encryption", MEDIUM),
    (515, "TCP", "LPD", "Line printer daemon", MEDIUM),
    (587, "TCP", "Submission", "Email submission with STARTTLS", LOW),
    (631, "TCP", "IPP", "Internet Printing Protocol", MEDIUM),
    (636, "TCP", "LDAPS", "Directory service over TLS", LOW),
    (873, "TCP", "rsync", "File synchronisation; often left without a password", HIGH),
    (993, "TCP", "IMAPS", "Email access over TLS", LOW),
    (995, "TCP", "POP3S", "Email retrieval over TLS", LOW),
    (1080, "TCP", "SOCKS", "Proxy server; can be abused to relay attacks", MEDIUM),
    (1433, "TCP", "MS-SQL", "Microsoft SQL Server database", HIGH),
    (1521, "TCP", "Oracle", "Oracle database listener", HIGH),
    (1723, "TCP", "PPTP", "Point-to-Point Tunnelling VPN; weak encryption", MEDIUM),
    (2049, "TCP/UDP", "NFS", "Network File System shares", HIGH),
    (2375, "TCP", "Docker", "Docker API without TLS; gives full host control", HIGH),
    (3000, "TCP", "Dev web", "Development web servers (Node.js, Grafana)", MEDIUM),
    (3306, "TCP", "MySQL", "MySQL database server", HIGH),
    (3389, "TCP", "RDP", "Windows Remote Desktop", HIGH),
    (5060, "TCP/UDP", "SIP", "Voice-over-IP call signalling", MEDIUM),
    (5432, "TCP", "PostgreSQL", "PostgreSQL database server", HIGH),
    (5900, "TCP", "VNC", "Remote desktop sharing; often weakly protected", HIGH),
    (5985, "TCP", "WinRM", "Windows Remote Management over HTTP", HIGH),
    (6379, "TCP", "Redis", "In-memory database; no password by default", HIGH),
    (8000, "TCP", "HTTP-alt", "Alternative web port (development servers)", MEDIUM),
    (8080, "TCP", "HTTP-proxy", "Alternative web or proxy port", MEDIUM),
    (8443, "TCP", "HTTPS-alt", "Alternative encrypted web port", LOW),
    (9050, "TCP", "Tor", "Tor SOCKS proxy", MEDIUM),
    (9200, "TCP", "Elasticsearch", "Search database HTTP API; no authentication by default", HIGH),
    (11211, "TCP/UDP", "Memcached", "Memory cache; no authentication", HIGH),
    (27017, "TCP", "MongoDB", "MongoDB database server", HIGH),
]

SERVICES = {port: {"protocol": proto, "service": name, "description": desc, "risk_level": risk}
            for port, proto, name, desc, risk in SERVICE_MAP}


def lookup(port: int) -> dict:
    """Service details for a port, or an 'Unknown service' entry."""
    entry = SERVICES.get(int(port))
    if entry:
        return entry
    return {"protocol": "-", "service": "Unknown service",
            "description": "Not in the service table", "risk_level": UNKNOWN}


def port_range(port: int) -> str:
    """IANA port range (Cotton et al., 2011)."""
    port = int(port)
    if port <= 1023:
        return "Well-known (0-1023)"
    if port <= 49151:
        return "Registered (1024-49151)"
    return "Dynamic (49152-65535)"
