from ..models import SecurityEvent, Assets, Company


def parse_crowdstrike_event(event_data):
    company_id = event_data.get("company_id")
    if company_id:
        company = Company.objects.get(pk=company_id)
    else:
        company, _ = Company.objects.get_or_create(
            name="Default Company", defaults={"address": ""}
        )

    asset, _ = Assets.objects.get_or_create(
        hostname=event_data.get("asset_hostname"),
        ip_address=event_data.get("asset_ip"),
        defaults={"company": company},
    )

    security_event = SecurityEvent.objects.create(
        source="crowdstrike",
        asset=asset,
        description=event_data.get("description", ""),
        severity=event_data.get("severity", ""),
        mitre_id=event_data.get("mitre_tactic", ""),
        metadata=event_data.get("raw_log", {}),
    )

    return {
        "id": security_event.id,
        "source": security_event.source,
        "asset": str(asset),
        "severity": security_event.severity,
    }
