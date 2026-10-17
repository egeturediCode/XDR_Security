from django.db import models
from django.contrib.auth import get_user_model
from analytics.models import Detection 

# Create your models here.


User = get_user_model()

class Incident(models.Model):
    STATUS_CHOICES = [
        ('open', 'Açık (Yeni)'),
        ('investigating', 'İnceleniyor'),
        ('resolved', 'Çözüldü'),
        ('closed', 'Kapatıldı'),
        ('false_positive', 'Yanlış Alarm'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Kritik'),
        ('high', 'Yüksek'),
        ('medium', 'Orta'),
        ('low', 'Düşük'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=50, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='open')
    
    detection = models.ManyToManyField(Detection, related_name='incidents')
    
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_incidents')
    resolution_note = models.TextField(blank=True, help_text="Vaka kapatılırken analistin girdiği not.")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"INC-{self.id} | {self.title} ({self.get_severity_display()})"
