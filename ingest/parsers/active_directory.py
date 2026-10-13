from ..models import SecurityEvent, Assets, Company


def map_ad_activity(event_id):
    if event_id in [4624, 4625]:
        return 1, "Logon"
    elif event_id in [4634, 4647, 4672]:
        return 2, "Logoff"
    return 0, "Unknown"

def map_ad_status(event_id):
    if event_id == 4624:
        return 1, "Success"
    elif event_id == 4625:
        return 2, "Failure"
    return 0, "Unknown"

def active_directory_normalization(raw_payload):
    company_id = raw_payload.get("company_id")
    company, _ = Company.objects.get_or_create(id=company_id) if company_id else Company.objects.get_or_create(name="Default Company")

    asset, _ = Assets.objects.get_or_create(
        ip_address=raw_payload.get("IpAddress", ""),
        defaults={
            "company": company, 
            "hostname": raw_payload.get("WorkstationName", "")
        },
    )
    
    event_id = raw_payload.get("EventID")
    ocsf_activity_id, ocsf_activity_str = map_ad_activity(event_id)
    ocsf_status_id, ocsf_status_str = map_ad_status(event_id)

    severity_id = 3 if event_id == 4625 else 1
    severity_str = "Medium" if event_id == 4625 else "Informational"

    # 3. OCSF Normalizasyonu (Authentication - UID: 3002)
    ocsf_payload = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "Active Directory", "vendor_name": "Microsoft"}
        },
        "class_uid": 3002,
        "class_name": "Authentication",
        "activity_id": ocsf_activity_id,
        "activity": ocsf_activity_str,
        "severity_id": severity_id,
        "severity": severity_str,
        "status_id": ocsf_status_id,
        "status": ocsf_status_str,
        "message": raw_payload.get("Message", f"Windows Event ID {event_id}"),
        "user": {
            "name": raw_payload.get("TargetUserName", ""),
            "domain": raw_payload.get("TargetDomainName", "")
        },
        "src_endpoint": {
            "ip": raw_payload.get("IpAddress", "")
        },
        "unmapped": raw_payload 
    }

    security_event = SecurityEvent.objects.create(
        source="active_directory",
        asset=asset,
        description=f"{ocsf_activity_str} {ocsf_status_str} for user {ocsf_payload['user']['name']}",
        severity=severity_str,
        metadata=ocsf_payload, 
    )

    return security_event