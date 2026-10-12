from django.db import models


class IngestEvent(models.Model):
    source = models.CharField(max_length=64)
    asset_hostname = models.CharField(max_length=255)
    asset_ip = models.GenericIPAddressField()
    severity = models.PositiveSmallIntegerField()
    description = models.TextField()
    mitre_tactic = models.CharField(max_length=32)
    raw_log = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source}: {self.asset_hostname} ({self.severity})"
