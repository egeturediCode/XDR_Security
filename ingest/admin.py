from django.contrib import admin

from audit.admin import AuditedModelAdmin

from .models import Assets, Company

admin.site.register(Company, AuditedModelAdmin)
admin.site.register(Assets, AuditedModelAdmin)
