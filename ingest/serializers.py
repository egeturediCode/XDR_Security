from rest_framework import serializers

from .models import IngestEvent


class IngestEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = IngestEvent
        fields = (
            "id",
            "source",
            "asset_hostname",
            "asset_ip",
            "severity",
            "description",
            "mitre_tactic",
            "raw_log",
            "created_at",
        )
        read_only_fields = ("id", "created_at")
