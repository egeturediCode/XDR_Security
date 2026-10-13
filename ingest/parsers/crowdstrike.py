from ..models import SecurityEvent, Assets, Company


def crowdstrike_normalization(raw_payload):
    event_data = raw_payload.get("event", {})
    
    customer_id = raw_payload.get("metadata", {}).get("customerIDString")
    company, _ = Company.objects.get_or_create(id=customer_id) if customer_id else Company.objects.get_or_create(name="Default Company")

    asset, _ = Assets.objects.get_or_create(
        hostname=event_data.get("ComputerName"),
        ip_address=event_data.get("LocalIP"),
        defaults={"company": company},
    )
    
    severity_name = event_data.get("SeverityName", "Unknown")
    ocsf_severity_mapping = {
        "Low": 2, 
        "Medium": 3, 
        "High": 4, 
        "Critical": 5
    }
    severity_id = ocsf_severity_mapping.get(severity_name, 0)

    # OCSF Normalizasyonu (Security Finding - UID: 2001)
    ocsf_payload = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "Falcon", "vendor_name": "CrowdStrike"}
        },
        "class_uid": 2001,
        "class_name": "Security Finding",
        "severity_id": severity_id,
        "severity": severity_name, 
        "message": event_data.get("DetectDescription", ""),
        "attack": {
            "tactic": {"name": event_data.get("Tactic")},
            "technique": {"uid": event_data.get("Technique")}
        },
        "device": {
            "hostname": event_data.get("ComputerName", ""),
            "ip": event_data.get("LocalIP", "")
        },
        "user": {
            "name": event_data.get("UserName", "")
        },
        "unmapped": raw_payload
    }

    security_event = SecurityEvent.objects.create(
        source="crowdstrike",
        asset=asset,
        description=ocsf_payload["message"],
        severity=severity_name,
        metadata=ocsf_payload, 
    )

    return security_event
