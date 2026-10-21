from ..models import SecurityEvent, Company
from .assets import resolve_asset


def nessus_normalization(raw_payload, company):
    company = Company.objects.get(id=company.id)

    asset = resolve_asset(
        company,
        hostname=raw_payload.get("hostname"),
        ip=raw_payload.get("host") or raw_payload.get("ip_address") or raw_payload.get("ip"),
        mac=raw_payload.get("mac_address") or raw_payload.get("mac"),
        asset_type=raw_payload.get("asset_type", "other"),
        criticality=raw_payload.get("criticality", "medium"),
        is_public=raw_payload.get("IsPublic", False) or raw_payload.get("is_public", False),
    )

    raw_severity = raw_payload.get("severity", 0)
    mapping = {
            0: (1, "Informational"),
            1: (2, "Low"),
            2: (3, "Medium"),
            3: (4, "High"),
            4: (5, "Critical")
        }
    ocsf_severity_id, ocsf_severity_str = mapping.get(int(raw_severity), (0, "Unknown"))

    cve_list = raw_payload.get("cve", [])
    ocsf_vulnerabilities = [{"cve": {"uid": cve}} for cve in cve_list]

    # OCSF Normalizasyonu (Vulnerability Finding - UID: 2002)
    ocsf_payload = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "Nessus", "vendor_name": "Tenable"}
        },
        "class_uid": 2002,
        "class_name": "Vulnerability Finding",
        "severity_id": ocsf_severity_id,
        "severity": ocsf_severity_str, 
        "message": raw_payload.get("description", ""),
        "remediation": {
            "desc": raw_payload.get("solution", "")
        },
        "vulnerabilities": ocsf_vulnerabilities,
        "device": {
            "hostname": raw_payload.get("hostname", ""),
            "ip": raw_payload.get("host", "")
        },
        "unmapped": raw_payload
    }

    security_event = SecurityEvent.objects.create(
        source="nessus",
        asset=asset,
        description=f"{raw_payload.get('plugin_name', 'Vulnerability')} - {ocsf_payload['message'][:200]}",
        severity=ocsf_severity_str,
        metadata=ocsf_payload, 
    )

    return security_event