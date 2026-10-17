from ..models import Assets


def resolve_asset(company, hostname=None, ip=None, mac=None, asset_type="other", criticality="medium", is_public=False):
    queryset = Assets.objects.filter(company=company)

    asset = None
    if hostname:
        asset = queryset.filter(hostname=hostname).first()
    if asset is None and ip:
        asset = queryset.filter(ip_address=ip).first()
    if asset is not None:
        return asset

    return Assets.objects.create(
        company=company,
        hostname=hostname or "unknown",
        ip_address=ip or None,
        mac_address=mac or None,
        asset_type=asset_type,
        criticality=criticality,
        is_public=is_public,
    )
