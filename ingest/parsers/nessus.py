from ..models import SecurityEvent, Assets, Company


def nessus_normalization(raw_payload):
    company_id = raw_payload.get("company_id") 
    company, _ = Company.objects.get_or_create(id=company_id) if company_id else Company.objects.get_or_create(name="Default Company")

    asset, _ = Assets.objects.get_or_create(
        hostname=raw_payload.get("hostname", ""),
        ip_address=raw_payload.get("host", ""),
        defaults={"company": company},
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