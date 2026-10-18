import ipaddress
import re
from datetime import timedelta
from django.db import transaction
from ingest.models import SecurityEvent
from .models import Detection, DetectionRule, ThreatIndicator

def check_ioc_in_threatfox(indicator_value, indicator_type="ip"):
    if not indicator_value:
        return None
    return ThreatIndicator.objects.filter(
        indicator_type=indicator_type,
        value=indicator_value,
        is_active=True,
    ).first()

def _event_value(event, *path):
    value = event.metadata or {}
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value

def _event_indicators(event):
    metadata = event.metadata or {}
    values = [
        (_event_value(event, "src_endpoint", "ip"), "ip"),
        (_event_value(event, "url", "hostname"), "domain"),
        (_event_value(event, "query", "hostname"), "domain"),
        (_event_value(event, "http_request", "url", "text"), "url"),
    ]
    hashes = _event_value(event, "file", "hashes")
    if isinstance(hashes, dict):
        values.extend((value, "hash") for value in hashes.values())
    return [(value, indicator_type) for value, indicator_type in values if value]

def _events_for_rule(security_event, parameters):
    window_seconds = parameters.get("time_window_seconds")
    window_minutes = parameters.get("time_window_minutes")
    
    window = window_seconds or (window_minutes * 60 if window_minutes else None)
    
    if not window:
        return [security_event]

    start = security_event.created_at - timedelta(seconds=window)
    return list(
        SecurityEvent.objects.filter(
            asset=security_event.asset,
            created_at__gte=start,
            created_at__lte=security_event.created_at,
        ).order_by("created_at")
    )

def _matches_rule(event, rule, candidate_events):
    parameters = rule.parameters or {}
    metadata = event.metadata or {}
    target_uid = parameters.get("target_event_uid")
    if target_uid is not None and metadata.get("class_uid") != target_uid:
        return False

    status_id = parameters.get("target_status_id")
    if status_id is not None and metadata.get("status_id") != status_id:
        return False

    event_id = parameters.get("event_id")
    if event_id is not None and _event_value(event, "unmapped", "EventID") != event_id:
        return False

    protocol = parameters.get("protocol")
    if protocol and str(_event_value(event, "unmapped", "proto") or
        _event_value(event, "protocol") or "").upper() != protocol.upper():
        return False

    process_name = str(_event_value(event, "process", "name") or
    _event_value(event, "unmapped", "ProcessName") or "").lower()
    process_names = [name.lower() for name in parameters.get("process_names", [])]
    if process_names and process_name not in process_names:
        return False

    message = str(metadata.get("message", ""))
    patterns = parameters.get("regex_patterns", [])
    if patterns and not any(re.search(pattern, message, re.IGNORECASE) for pattern in patterns):
        return False

    groups = parameters.get("monitored_groups", [])
    if groups and not any(group.lower() in message.lower() for group in groups):
        return False

    if parameters.get("target_process") and parameters["target_process"].lower() not in process_name:
        return False

    if parameters.get("require_asset_public_ip"):
        try:
            if not ipaddress.ip_address(event.asset.ip_address).is_global:
                return False
        except ValueError:
            return False

    min_cvss = parameters.get("min_cvss_score")
    if min_cvss is not None:
        scores = [
            item.get("cvss", {}).get("score")
            for item in metadata.get("vulnerabilities", [])
            if isinstance(item, dict) and isinstance(item.get("cvss"), dict)
        ]
        if not any(score is not None and float(score) >= float(min_cvss) for score in scores):
            return False

    threshold = parameters.get("threshold")
    if threshold is not None:
        matching_events = candidate_events
        if parameters.get("target_status_id") is not None:
            matching_events = [
                item for item in matching_events
                if (item.metadata or {}).get("status_id") == parameters["target_status_id"]
            ]
        if len(matching_events) < threshold:
            return False

    threshold_failed = parameters.get("threshold_failed")
    if threshold_failed is not None:
        failures = [
            item for item in candidate_events
            if (item.metadata or {}).get("status_id") == 2
        ]
        if len(failures) - int(metadata.get("status_id") == 2) < threshold_failed:
            return False
        if parameters.get("requires_success_event") and metadata.get("status_id") != 1:
            return False

    if parameters.get("action") == "check_threatfox_api":
        if not any(check_ioc_in_threatfox(value, kind) for value, kind in _event_indicators(event)):
            return False

    return True

def correlation_service(security_event):
    detections = []
    
    for rule in DetectionRule.objects.all():
        candidate_events = _events_for_rule(security_event, rule.parameters or {})
        if not _matches_rule(security_event, rule, candidate_events):
            continue

        detection = Detection.objects.filter(
            detection_rules=rule,
            events=security_event,
        ).first()
        
        if detection is None:
            detection = Detection.objects.create(
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
            )
            detection.detection_rules.add(rule)

        detection.events.add(*candidate_events)
        detections.append(detection)
        
    return detections

VENDOR_DETECTION_UID = 2001
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

FORTINET_THREAT_KEYWORDS = (
    "ips", "intrusion", "botnet", "malware", "virus", "exploit",
    "c2", "command and control", "trojan", "ransomware", "attack",
)

# Event ID -> (tespit adı, açıklama, ciddiyet)
AD_SENSITIVE_EVENTS = {
    1102: ("Güvenlik olay günlüğü temizlendi", "Windows güvenlik günlüğü temizlendi; iz silme girişimi olabilir.", "high"),
    104: ("Sistem olay günlüğü temizlendi", "Windows sistem günlüğü temizlendi; iz silme girişimi olabilir.", "high"),
    4719: ("Denetim politikası değiştirildi", "Sistem denetim politikası değiştirildi.", "high"),
    4720: ("Yeni kullanıcı hesabı oluşturuldu", "Etki alanında yeni bir kullanıcı hesabı oluşturuldu.", "medium"),
    4728: ("Güvenlik grubuna üye eklendi", "Global güvenlik grubuna yeni üye eklendi.", "medium"),
    4732: ("Yerel gruba üye eklendi", "Yerel güvenlik grubuna yeni üye eklendi.", "medium"),
    4756: ("Evrensel gruba üye eklendi", "Evrensel güvenlik grubuna yeni üye eklendi.", "medium"),
    4740: ("Hesap kilitlendi", "Kullanıcı hesabı kilitlendi; parola deneme saldırısı olabilir.", "medium"),
    4697: ("Yeni servis kuruldu", "Sistemde yeni bir servis kuruldu.", "medium"),
    4698: ("Zamanlanmış görev oluşturuldu", "Yeni bir zamanlanmış görev oluşturuldu.", "medium"),
}
PRIVILEGED_GROUPS = ("domain admins", "enterprise admins", "administrators", "schema admins")


def _rank(severity):
    return SEVERITY_RANK.get(str(severity).lower(), 0)


def _normalize_severity(value, default="medium"):
    value = str(value or "").lower()
    if value in SEVERITY_RANK:
        return value
    if value in ("fatal", "emergency"):
        return "critical"
    if value in ("informational", "info", "unknown", ""):
        return default
    return default


def _direct_findings(event):
    """Satıcının kendi ürettiği, korelasyon gerektirmeyen bulgular."""
    metadata = event.metadata or {}
    uid = metadata.get("class_uid")
    severity_id = metadata.get("severity_id") or 0
    message = str(metadata.get("message", ""))
    findings = []

    if uid == VENDOR_DETECTION_UID:
        findings.append((
            f"EDR tespiti: {event.description[:80]}",
            event.description,
            _normalize_severity(event.severity, "high"),
        ))

    elif uid == 2002 and severity_id >= 4:
        title = _event_value(event, "unmapped", "plugin_name") or "Zafiyet bulgusu"
        findings.append((
            f"Yüksek riskli zafiyet: {title}",
            event.description,
            "critical" if severity_id >= 5 else "high",
        ))

    elif uid == 4001:
        lowered = message.lower()
        if severity_id >= 5:
            findings.append((
                "Güvenlik duvarı kritik uyarısı",
                event.description,
                "critical",
            ))
        elif any(word in lowered for word in FORTINET_THREAT_KEYWORDS):
            findings.append((
                "Ağ geçidi tehdit imzası eşleşmesi",
                event.description,
                "high" if severity_id >= 4 else "medium",
            ))

    elif uid == 3002:
        event_id = _event_value(event, "unmapped", "EventID")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            event_id = None
        known = AD_SENSITIVE_EVENTS.get(event_id)
        if known:
            name, description, severity = known
            lowered = message.lower()
            if event_id in (4728, 4732, 4756) and any(g in lowered for g in PRIVILEGED_GROUPS):
                name, severity = "Ayrıcalıklı gruba üye eklendi", "high"
            findings.append((name, f"{description} {message}".strip(), severity))

    return findings


def _ioc_matches(event):
    return [
        match
        for value, kind in _event_indicators(event)
        if (match := check_ioc_in_threatfox(value, kind))
    ]


@transaction.atomic
def create_detection(security_event, class_uid=None):
    detections = []

    # Satıcı tespitleri (EDR) kural motorunu atlar; diğer loglar korelasyondan da geçer.
    if class_uid != VENDOR_DETECTION_UID:
        detections.extend(correlation_service(security_event))

    for name, description, severity in _direct_findings(security_event):
        detection = Detection.objects.create(
            name=name, description=description, severity=severity
        )
        detection.events.add(security_event)
        detections.append(detection)

    if not detections:
        matches = _ioc_matches(security_event)
        if matches:
            detection = Detection.objects.create(
                name="Tehdit istihbaratı eşleşmesi",
                description=f"{', '.join(sorted({m.value for m in matches}))} göstergesi ThreatFox ile eşleşti.",
                severity="critical",
            )
            detection.events.add(security_event)
            detections.append(detection)

    return detections


def detection_engine(security_event):
    class_uid = (security_event.metadata or {}).get("class_uid")
    detections = create_detection(security_event, class_uid=class_uid)

    for detection in detections:
        matched_indicators = []
        for event in detection.events.all():
            matched_indicators.extend(_ioc_matches(event))
        if matched_indicators:
            detection.indicators.add(*set(matched_indicators))
            if _rank(detection.severity) < _rank("high"):
                detection.severity = "high"
                detection.save(update_fields=["severity"])

    return detections
