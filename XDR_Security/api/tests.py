from unittest.mock import patch

from django.urls import reverse
from django.test import SimpleTestCase
from rest_framework import status
from rest_framework.test import APIClient


class AutonomousIngestViewTests(SimpleTestCase):
    @patch("api.views.IngestEventSerializer")
    def test_post_saves_event(self, serializer_class):
        payload = {
            "source": "crowdstrike",
            "asset_hostname": "workstation-hr",
            "asset_ip": "192.168.10.50",
            "severity": 12,
            "description": "Suspicious PowerShell command detected",
            "mitre_tactic": "T1059.001",
            "raw_log": {"detection_id": "ldt:123456", "action": "blocked"},
        }
        serializer = serializer_class.return_value
        serializer.data = payload

        response = APIClient().post(
            reverse("autonomous-ingest"),
            payload,
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"message": "Event received", "data": payload})
        serializer.is_valid.assert_called_once_with(raise_exception=True)
        serializer.save.assert_called_once_with()
