import json
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from analytics.models import Detection, ThreatIndicator
from ingest.models import SecurityEvent


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _detection_severity(detection):
    rule_severities = list(detection.detection_rules.values_list("severity", flat=True))
    if rule_severities:
        return max(rule_severities, key=lambda value: SEVERITY_RANK.get(value, 0))

    event_severity = detection.events.values_list("severity", flat=True).first()
    return str(event_severity or "low").lower()


def _detection_row(detection):
    events = list(detection.events.select_related("asset").order_by("created_at"))
    latest_event = events[-1] if events else None
    rules = list(detection.detection_rules.values_list("name", flat=True))
    indicators = detection.indicators.count()
    return {
        "id": detection.id,
        "name": detection.name,
        "description": detection.description or "Detection event'i için ek açıklama yok.",
        "severity": _detection_severity(detection),
        "status": "correlated" if rules else "detected",
        "detected_at": detection.created_at,
        "ip_address": latest_event.asset.ip_address if latest_event else "",
        "hostname": latest_event.asset.hostname if latest_event else "",
        "event_count": len(events),
        "indicator_count": indicators,
        "rule_names": rules,
    }


def _event_row(event):
    detection_count = event.detections.count()
    return {
        "id": event.id,
        "source": event.source,
        "description": event.description,
        "severity": str(event.severity or "unknown").lower(),
        "created_at": event.created_at,
        "hostname": event.asset.hostname,
        "ip_address": event.asset.ip_address,
        "detection_count": detection_count,
        "status": "detected" if detection_count else "ingested",
    }


@login_required
def dashboard(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    detections = Detection.objects.prefetch_related("events__asset", "detection_rules")
    recent_detections = [_detection_row(item) for item in detections[:20]]
    recent_events = [
        _event_row(item)
        for item in SecurityEvent.objects.select_related("asset").order_by("-created_at")[:20]
    ]
    high_severity_count = sum(
        row["severity"] in {"high", "critical"}
        for row in (_detection_row(item) for item in detections)
    )

    context = {
        "detection_count": detections.count(),
        "high_severity_count": high_severity_count,
        "active_threat_ip_count": ThreatIndicator.objects.filter(
            indicator_type=ThreatIndicator.IndicatorType.IP,
            is_active=True,
        ).count(),
        "events_today_count": SecurityEvent.objects.filter(created_at__gte=day_ago).count(),
        "recent_detections": recent_detections,
        "recent_events": recent_events,
        "last_event_at": SecurityEvent.objects.order_by("-created_at").values_list(
            "created_at", flat=True
        ).first(),
    }
    return render(request, "dashboard.html", context)


@login_required
def detections(request):
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").lower()
    status = request.GET.get("status", "").lower()
    queryset = Detection.objects.prefetch_related("events__asset", "detection_rules")
    if query:
        queryset = queryset.filter(
            Q(name__icontains=query) | Q(description__icontains=query)
        )

    rows = [_detection_row(item) for item in queryset]
    if severity:
        rows = [row for row in rows if row["severity"] == severity]
    if status:
        rows = [row for row in rows if row["status"] == status]

    page = Paginator(rows, 20).get_page(request.GET.get("page"))
    return render(
        request,
        "detections.html",
        {
            "page": page,
            "total_count": len(rows),
            "query": query,
            "severity": severity,
            "status": status,
            "severity_choices": ("low", "medium", "high", "critical"),
            "status_choices": ("detected", "correlated"),
        },
    )


@login_required
def detection_detail(request, detection_id):
    detection = get_object_or_404(
        Detection.objects.prefetch_related(
            "events__asset",
            "indicators",
            "detection_rules__mitre_techniques",
        ),
        id=detection_id,
    )
    events = detection.events.select_related("asset").order_by("-created_at")
    return render(
        request,
        "detection_detail.html",
        {
            "detection": detection,
            "detection_severity": _detection_severity(detection),
            "events": events,
            "indicators": detection.indicators.all(),
            "rules": detection.detection_rules.all(),
        },
    )


@login_required
def logs(request):
    queryset = SecurityEvent.objects.select_related("asset").order_by("-created_at")
    page = Paginator([_event_row(item) for item in queryset], 25).get_page(
        request.GET.get("page")
    )
    return render(request, "logs.html", {"page": page, "total_count": queryset.count()})


@login_required
def log_detail(request, event_id):
    event = get_object_or_404(
        SecurityEvent.objects.select_related("asset").prefetch_related(
            "detections__detection_rules",
            "detections__indicators",
        ),
        id=event_id,
    )
    return render(
        request,
        "log_detail.html",
        {
            "event": event,
            "event_metadata": json.dumps(event.metadata or {}, indent=2, ensure_ascii=False),
            "detections": event.detections.all(),
        },
    )
