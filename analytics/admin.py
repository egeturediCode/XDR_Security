from django.contrib import admin

from audit.admin import AuditedModelAdmin

from .models import DetectionRule

admin.site.register(DetectionRule, AuditedModelAdmin)
