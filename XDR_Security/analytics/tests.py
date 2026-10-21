from django.test import TestCase

from analytics.models import Detection, DetectionRule, ThreatIndicator
from analytics.services import detection_engine
from ingest.models import Assets, Company, SecurityEvent


class DetectionEngineTests(TestCase):
    def setUp(self):
        company = Company.objects.create(name="Test company", address="")
        self.asset = Assets.objects.create(
            company=company,
            hostname="endpoint-1",
            ip_address="192.0.2.10",
        )

    def event(self, metadata):
        return SecurityEvent.objects.create(
            source="test",
            asset=self.asset,
            description="test event",
            severity="Medium",
            metadata=metadata,
        )

    def test_vendor_detection_skips_correlation_rules(self):
        rule = DetectionRule.objects.create(
            name="raw event rule",
            parameters={"target_event_uid": 2001},
        )
        event = self.event({"class_uid": 2001, "message": "vendor detection"})

        detections = detection_engine(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].detection_rules.count(), 0)
        self.assertEqual(detections[0].events.count(), 1)
        self.assertFalse(Detection.objects.filter(detection_rules=rule).exists())

    def test_single_event_rule_attaches_event_and_rule(self):
        rule = DetectionRule.objects.create(
            name="network event",
            parameters={"target_event_uid": 4001, "target_status_id": 2},
        )
        event = self.event(
            {"class_uid": 4001, "status_id": 2, "src_endpoint": {"ip": "198.51.100.4"}}
        )

        detections = detection_engine(event)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].events.get(), event)
        self.assertEqual(detections[0].detection_rules.get(), rule)

    def test_threatfox_match_is_saved_on_detection(self):
        DetectionRule.objects.create(
            name="threat intel",
            parameters={"action": "check_threatfox_api"},
        )
        indicator = ThreatIndicator.objects.create(
            source="threatfox",
            value="198.51.100.4",
            indicator_type=ThreatIndicator.IndicatorType.IP,
        )
        event = self.event(
            {"class_uid": 4001, "src_endpoint": {"ip": "198.51.100.4"}}
        )

        detections = detection_engine(event)

        self.assertEqual(detections[0].indicators.get(), indicator)
