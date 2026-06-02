"""Sidebar navigation structure (SIEM Enterprise layout)."""

# (label, module_key, badge_field from nav summary)
OPERATIONS = [
    ("Dashboard", "executive", None),
    ("Threats & Alerts", "alerts", "alerts_total"),
    ("Incidents", "incidents", None),
    ("Threat Hunting", "hunting", None),
    ("IDS / IPS", "ids", None),
    ("IPS Controls", "ips", None),
    ("SIEM Events", "siem", "events_total"),
    ("Network Topology", "topology", "devices_online"),
    ("Live Discovery", "discovery", None),
    ("MITRE ATT&CK", "mitre", None),
    ("Attack Timeline", "timeline", None),
]

GOVERNANCE = [
    ("Compliance", "compliance", None),
    ("Cloud Security", "cloud", None),
    ("Audit Center", "audit", None),
    ("Asset Inventory", "assets", None),
    ("Reports", "reports", None),
    ("User Management", "users", None),
    ("Settings", "settings", None),
]

# Extra modules reachable from dashboard widgets (not in sidebar)
EXTRA_MODULES = {
    "user_risk": "user_risk",
    "insider": "insider",
    "threat_intel": "threat_intel",
}

PAGE_TITLES = {
    "executive": "Security Operations Center",
    "alerts": "Threat Intelligence & Alerts",
    "incidents": "Incident Response Management",
    "hunting": "Threat Hunting",
    "ids": "IDS Dashboard",
    "ips": "IPS Dashboard",
    "siem": "SIEM Dashboard",
    "topology": "Network Topology",
    "discovery": "Live Network Discovery",
    "mitre": "MITRE ATT&CK",
    "timeline": "Attack Timeline",
    "compliance": "Compliance & Governance",
    "cloud": "Cloud Security Dashboard",
    "audit": "Audit Center",
    "assets": "Asset Inventory",
    "reports": "Reports",
    "users": "User Management",
    "settings": "Settings & Configuration",
    "user_risk": "User Risk Analytics",
    "insider": "Insider Threat Center",
    "threat_intel": "Threat Intelligence",
}


def build_nav_labels(nav: dict) -> tuple[list[str], list[str], dict[str, str]]:
    """Returns (all_labels, all_keys, label_to_module)."""
    labels: list[str] = []
    keys: list[str] = []
    mapping: dict[str, str] = {}

    def add_group(items):
        for label, module, badge_key in items:
            display = label
            if badge_key and nav.get(badge_key):
                count = nav[badge_key]
                if count and module in ("alerts", "siem"):
                    display = f"{label} ({count})"
                elif count and module == "topology":
                    display = f"{label} ({count} online)"
            labels.append(display)
            keys.append(module)
            mapping[display] = module

    add_group(OPERATIONS)
    add_group(GOVERNANCE)
    return labels, keys, mapping
