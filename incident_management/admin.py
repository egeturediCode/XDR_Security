from django.contrib import admin

from .models import IncidentAction


@admin.register(IncidentAction)
class IncidentActionAdmin(admin.ModelAdmin):
    list_display = ("incident", "action", "success", "executed_by", "executed_at")
    list_filter = ("action", "success")
