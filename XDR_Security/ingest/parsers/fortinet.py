from ..models import SecurityEvent, Company
from .assets import resolve_asset


def map_fortinet_severity(level):
    mapping = {
        "information": (1, "Informational"),
        "notice": (2, "Low"),
        "warning": (3, "Medium"),
        "error": (4, "High"),
        "critical": (5, "Critical"),
        "alert": (5, "Critical"),
        "emergency": (6, "Fatal")
    }
    return mapping.get(str(level).lower(), (0, "Unknown"))

def map_fortinet_action(action):
    action_str = str(action).lower()
    if action_str in ["accept", "allow", "permit"]:
        return 1, "Allowed"
    elif action_str in ["deny", "block", "drop", "close"]:
        return 2, "Denied"
    return 0, "Unknown"

def fortinet_normalization(raw_payload, company):
    company = Company.objects.get(id=company.id)

    asset = resolve_asset(
        company,
        hostname=raw_payload.get("hostname"),
        ip=raw_payload.get("srcip") or raw_payload.get("host") or raw_payload.get("ip_address") or raw_payload.get("ip"),
        mac=raw_payload.get("mac_address") or raw_payload.get("mac"),
        asset_type=raw_payload.get("asset_type", "other"),
        criticality=raw_payload.get("criticality", "medium"),
        is_public=raw_payload.get("is_public", False),
    )

    ocsf_severity_id, ocsf_severity_str = map_fortinet_severity(raw_payload.get("level", "notice"))
    ocsf_status_id, ocsf_status_str = map_fortinet_action(raw_payload.get("action", ""))

    # 3. OCSF Normalizasyonu (Network Activity - UID: 4001)
    ocsf_payload = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "FortiOS", "vendor_name": "Fortinet"}
        },
        "class_uid": 4001,
        "class_name": "Network Activity",
        "severity_id": ocsf_severity_id,
        "severity": ocsf_severity_str,
        "status_id": ocsf_status_id,
        "status": ocsf_status_str,
        "message": raw_payload.get("msg", ""),
        "src_endpoint": {
            "ip": raw_payload.get("srcip", ""),
            "port": raw_payload.get("srcport", 0)
        },
        "dst_endpoint": {
            "ip": raw_payload.get("dstip", ""),
            "port": raw_payload.get("dstport", 0)
        },
        "unmapped": raw_payload
    }

    security_event = SecurityEvent.objects.create(
        source="fortinet",
        asset=asset,
        description=f"Traffic {ocsf_status_str}: {ocsf_payload['message']}",
        severity=ocsf_severity_str,
        metadata=ocsf_payload, 
    )

    return security_event