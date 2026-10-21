from django.db import models
import secrets
import uuid

# Create your models here.


def generate_api_key():
    return secrets.token_urlsafe(32)

class Company(models.Model):
    tenant_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True, null=True)
    contact_email = models.EmailField(blank=True, null=True)
    contact_phone = models.CharField(max_length=50, blank=True, null=True)
    
    api_key = models.CharField(
        max_length=255, 
        unique=True,               
        db_index=True,             
        default=generate_api_key,  
        help_text="Dış sistemlerin log gönderirken kullanacağı kimlik doğrulama anahtarı."
    )
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Assets(models.Model):
    ASSET_TYPES = [
        ('server', 'Sunucu'),
        ('workstation', 'İş İstasyonu'),
        ('network_device', 'Ağ Cihazı (Firewall/Switch)'),
        ('mobile', 'Mobil Cihaz'),
        ('other', 'Diğer'),
    ]

    CRITICALITY_CHOICES = [
        ('low', 'Düşük (Örn: Misafir Ağı)'),
        ('medium', 'Orta (Örn: Standart Personel)'),
        ('high', 'Yüksek (Örn: Yönetici Bilgisayarı)'),
        ('critical', 'Kritik (Örn: Domain Controller, Veritabanı)'),
    ]

    company = models.ForeignKey('Company', on_delete=models.CASCADE, related_name='assets')
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    mac_address = models.CharField(max_length=17, null=True, blank=True, help_text="Ağda cihazı sabit takip etmek için")
    asset_type = models.CharField(max_length=50, choices=ASSET_TYPES, default='other')
    criticality = models.CharField(max_length=50, choices=CRITICALITY_CHOICES, default='medium')
    is_public = models.BooleanField(default=False, help_text="Bu cihaz doğrudan internete açık mı? (Public IP)")
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True, help_text="Bu cihazdan en son ne zaman log geldi?")

    class Meta:
        unique_together = ('company', 'hostname')
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['hostname']),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

class SecurityEvent(models.Model):
    source = models.CharField(max_length=255)
    asset = models.ForeignKey(Assets, on_delete=models.CASCADE)
    description = models.TextField()
    severity = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    metadata = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"{self.asset.hostname} - {self.severity}"

