from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ("LOGIN", "Giriş"),
        ("LOGOUT", "Çıkış"),
        ("LOGIN_FAILED", "Başarısız giriş"),
        ("RULE_UPDATED", "Kural güncellendi"),
        ("RULE_CREATED", "Kural oluşturuldu"),
        ("RULE_DELETED", "Kural silindi"),
        ("COMPANY_CREATED", "Şirket oluşturuldu"),
        ("COMPANY_UPDATED", "Şirket güncellendi"),
        ("COMPANY_DELETED", "Şirket silindi"),
        ("API_KEY_ROTATED", "API anahtarı yenilendi"),
        ("ASSET_CREATED", "Varlık eklendi"),
        ("ASSET_UPDATED", "Varlık güncellendi"),
        ("ASSET_DELETED", "Varlık silindi"),
        ("INCIDENT_STATUS_CHANGED", "Vaka durumu değişti"),
        ("INCIDENT_ASSIGNED", "Vaka atandı"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs"
    )
    username = models.CharField(max_length=150, blank=True, help_text="Kullanıcı silinse veya giriş başarısız olsa bile korunur.")
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)
    target_type = models.CharField(max_length=100, blank=True)
    target_id = models.CharField(max_length=50, blank=True)
    target_repr = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["action", "-created_at"]),
            models.Index(fields=["target_type", "target_id"]),
        ]

    def __str__(self):
        return f"{self.created_at:%d.%m.%Y %H:%M:%S} | {self.username or 'sistem'} | {self.action}"
