from types import SimpleNamespace
from unittest.mock import patch

from django.urls import reverse
from django.test import SimpleTestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from ingest.models import hash_api_key


class AutonomousIngestViewTests(SimpleTestCase):
    @override_settings(ALLOWED_HOSTS=["testserver"])
    @patch("api.views.TenantRateThrottle.allow_request", return_value=True)
    @patch("api.views.process_incoming_log")
    @patch("api.views.Company.objects.get")
    def test_post_hashes_api_key_before_lookup(
        self, company_get, process_incoming_log, _allow_request
    ):
        api_key = "test-api-key"
        company_get.return_value.is_active = True
        event = SimpleNamespace(id=1, detections=SimpleNamespace(
            values_list=lambda *args, **kwargs: []
        ))
        process_incoming_log.return_value = event

        response = APIClient().post(
            reverse("autonomous-ingest"),
            {"source": "crowdstrike"},
            format="json",
            HTTP_X_API_KEY=api_key,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        company_get.assert_called_once_with(api_key=hash_api_key(api_key))
        process_incoming_log.assert_called_once_with(
            "crowdstrike", {"source": "crowdstrike"}, company_get.return_value
        )
