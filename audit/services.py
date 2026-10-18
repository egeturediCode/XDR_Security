from .models import AuditLog


def get_client_ip(request):
    if request is None:
        return None
    return request.META.get("REMOTE_ADDR") or None


def create_audit_log(action, user=None, request=None, target=None, details=None, username="", ip_address=None):
    """Write an audit record. `target` is any model instance."""
    if user is None and request is not None and getattr(request.user, "is_authenticated", False):
        user = request.user
    if user is not None and not getattr(user, "pk", None):
        user = None
    return AuditLog.objects.create(
        user=user,
        username=(user.get_username() if user else username)[:150],
        action=action,
        target_type=target._meta.label if target is not None else "",
        target_id=str(target.pk) if target is not None else "",
        target_repr=str(target)[:255] if target is not None else "",
        details=details or {},
        ip_address=ip_address or get_client_ip(request),
    )
