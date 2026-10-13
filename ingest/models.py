from django.db import models

# Create your models here.


class Company(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Assets(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

class SecurityEvent(models.Model):
    source = models.CharField(max_length=255)
    asset = models.ForeignKey(Assets, on_delete=models.CASCADE)
    description = models.TextField()
    severity = models.CharField(max_length=50)
    mitre_id = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    metadata = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.asset.hostname} - {self.severity}"

