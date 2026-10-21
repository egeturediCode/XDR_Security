from django.contrib import admin

from .models import AuditLog
from .services import create_audit_log

ACTIONS = {
    "DetectionRule": ("RULE_CREATED", "RULE_UPDATED", "RULE_DELETED"),
    "Company": ("COMPANY_CREATED", "COMPANY_UPDATED", "COMPANY_DELETED"),
    "Assets": ("ASSET_CREATED", "ASSET_UPDATED", "ASSET_DELETED"),
}


class AuditedModelAdmin(admin.ModelAdmin):
    """Logs create/update/delete done through the admin, with old and new values."""

    def save_model(self, request, obj, form, change):
        old = {}
        if change:
            stored = type(obj).objects.get(pk=obj.pk)
            old = {
                f: getattr(stored, f)
                for f in form.changed_data
                if f in {fl.name for fl in stored._meta.concrete_fields}
            }
        super().save_model(request, obj, form, change)
        created, updated, _ = ACTIONS[type(obj).__name__]
        if not change:
            create_audit_log(created, request=request, target=obj)
            return
        changes = {
            f: {"old": _plain(old[f]), "new": _plain(getattr(obj, f))}
            for f in old
            if f != "api_key"
        }
        if changes:
            create_audit_log(updated, request=request, target=obj, details={"changes": changes})
        if "api_key" in old:
            create_audit_log("API_KEY_ROTATED", request=request, target=obj)

    def delete_model(self, request, obj):
        create_audit_log(ACTIONS[type(obj).__name__][2], request=request, target=obj)
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            create_audit_log(ACTIONS[type(obj).__name__][2], request=request, target=obj)
        super().delete_queryset(request, queryset)


def _plain(value):
    return value if isinstance(value, (str, int, float, bool, dict, list, type(None))) else str(value)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "username", "action", "target_repr", "ip_address")
    list_filter = ("action",)
    search_fields = ("username", "target_repr", "ip_address")
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
