from django.db import models
from ingest.models import SecurityEvent

# Create your models here.


class MitreTechnique(models.Model):
    technique_id = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    tactics = models.JSONField(default=list, blank=True)
    platforms = models.JSONField(default=list, blank=True)
    external_url = models.URLField(blank=True)
    is_subtechnique = models.BooleanField(default=False)
    revoked = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.technique_id} - {self.name}"


class ThreatIndicator(models.Model):
    class IndicatorType(models.TextChoices):
        IP = "ip", "IP Address"
        IP_PORT = "ip:port", "IP Address with Port"
        DOMAIN = "domain", "Domain"
        URL = "url", "URL"
        HASH = "hash", "File Hash"

    value = models.CharField(max_length=2048, db_index=True)
    indicator_type = models.CharField(
        max_length=20,
        choices=IndicatorType.choices,
    )
    source = models.CharField(max_length=100)
    malware = models.CharField(max_length=255, blank=True)

    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    is_active = models.BooleanField(default=True)
    raw_data = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "value", "indicator_type"],
                name="unique_source_indicator",
            )
        ]

    def __str__(self):
        return f"{self.indicator_type}: {self.value}"


# -----------------------------------

class DetectionRule(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    mitre_techniques = models.ManyToManyField(MitreTechnique, blank=True, related_name="detection_rules")
    severity = models.CharField(
        max_length=20,
        choices=[
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
            ("critical", "Critical"),
        ],
        default='low',
    )
    parameters = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return self.name


class Detection(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    events = models.ManyToManyField(
        SecurityEvent,
        blank=True,
        related_name="detections",
    )
    indicators = models.ManyToManyField(
        ThreatIndicator,
        blank=True,
        related_name="detections",
    )
    detection_rules = models.ManyToManyField(
        DetectionRule,
        blank=True,
        related_name="detections",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    class Meta:
        ordering = ["-created_at"]
