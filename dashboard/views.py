import json
from datetime import timedelta

from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils import timezone

from analytics.models import Detection, ThreatIndicator
from incident_management.models import Incident
from incident_management.services import INCIDENT_ACTIONS, incident_action
from ingest.models import Company, SecurityEvent

from .forms import AssetFormSet, CompanyForm

COMPANY_SESSION_KEY = "company_id"


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def company_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        company = Company.objects.filter(id=request.session.get(COMPANY_SESSION_KEY)).first()
        if company is None:
            request.session.pop(COMPANY_SESSION_KEY, None)
            return redirect("company_select")
        request.company = company
        return view(request, *args, **kwargs)

    return wrapper


def _company_detections(company):
    return Detection.objects.filter(events__asset__company=company).distinct()


def _company_events(company):
    return SecurityEvent.objects.filter(asset__company=company)


def _detection_severity(detection):
    if detection.severity:
        return detection.severity
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


@company_required
def dashboard(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    company_events = _company_events(request.company)
    detections = _company_detections(request.company).prefetch_related(
        "events__asset", "detection_rules"
    )
    recent_detections = [_detection_row(item) for item in detections[:20]]
    recent_events = [
        _event_row(item)
        for item in company_events.select_related("asset").order_by("-created_at")[:20]
    ]
    high_severity_count = sum(
        row["severity"] in {"high", "critical"}
        for row in (_detection_row(item) for item in detections)
    )

    context = {
        "detection_count": detections.count(),
        "high_severity_count": high_severity_count,
        "active_threat_ip_count": ThreatIndicator.objects.filter(
            detections__in=detections,
            indicator_type=ThreatIndicator.IndicatorType.IP,
            is_active=True,
        ).distinct().count(),
        "events_today_count": company_events.filter(created_at__gte=day_ago).count(),
        "recent_detections": recent_detections,
        "recent_events": recent_events,
        "last_event_at": company_events.order_by("-created_at").values_list(
            "created_at", flat=True
        ).first(),
    }
    return render(request, "dashboard.html", context)


@company_required
def detections(request):
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").lower()
    status = request.GET.get("status", "").lower()
    queryset = _company_detections(request.company).prefetch_related(
        "events__asset", "detection_rules"
    )
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


@company_required
def detection_detail(request, detection_id):
    detection = get_object_or_404(
        _company_detections(request.company).prefetch_related(
            "events__asset",
            "indicators",
            "detection_rules__mitre_techniques",
        ),
        id=detection_id,
    )
    events = detection.events.filter(asset__company=request.company).select_related("asset").order_by("-created_at")
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


@company_required
def logs(request):
    queryset = _company_events(request.company).select_related("asset").order_by("-created_at")
    page = Paginator([_event_row(item) for item in queryset], 25).get_page(
        request.GET.get("page")
    )
    return render(request, "logs.html", {"page": page, "total_count": queryset.count()})


@company_required
def log_detail(request, event_id):
    event = get_object_or_404(
        _company_events(request.company).select_related("asset").prefetch_related(
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


def _company_incidents(company):
    return Incident.objects.filter(detection__events__asset__company=company).distinct()


def _incident_row(incident, company_id):
    detections = list(incident.detection.all())
    assets = {}
    for detection in detections:
        for event in detection.events.all():
            if event.asset.company_id == company_id:
                assets[event.asset_id] = event.asset
    return {
        "obj": incident,
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "detection_count": len(detections),
        "hostnames": sorted(a.hostname for a in assets.values()),
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
    }


@company_required
def incidents(request):
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "").lower()
    status = request.GET.get("status", "").lower()

    base = _company_incidents(request.company)
    stats = {
        "open": base.filter(status="open").count(),
        "investigating": base.filter(status="investigating").count(),
        "critical": base.filter(
            status__in=("open", "investigating"), severity__in=("critical", "high")
        ).count(),
        "done": base.filter(status__in=("resolved", "closed", "false_positive")).count(),
        "total": base.count(),
    }

    queryset = base.select_related("assigned_to").prefetch_related(
        "detection__events__asset"
    )
    if query:
        queryset = queryset.filter(Q(title__icontains=query) | Q(description__icontains=query))
    if severity:
        queryset = queryset.filter(severity=severity)
    if status:
        queryset = queryset.filter(status=status)

    rows = []
    for incident in queryset.order_by("-created_at"):
        rows.append(_incident_row(incident, request.company.id))

    page = Paginator(rows, 20).get_page(request.GET.get("page"))
    return render(
        request,
        "incidents.html",
        {
            "page": page,
            "stats": stats,
            "total_count": len(rows),
            "query": query,
            "severity": severity,
            "status": status,
            "severity_choices": ("critical", "high", "medium", "low"),
            "status_choices": [c[0] for c in Incident.STATUS_CHOICES],
        },
    )


@company_required
def incident_detail(request, incident_id):
    incident = get_object_or_404(
        _company_incidents(request.company).select_related("assigned_to"),
        id=incident_id,
    )
    company = request.company
    detections = []
    assets, users, indicators, techniques = {}, set(), {}, {}
    events = {}
    for detection in incident.detection.prefetch_related(
        "events__asset", "indicators", "detection_rules__mitre_techniques"
    ).order_by("created_at"):
        det_events = [e for e in detection.events.all() if e.asset.company_id == company.id]
        if not det_events:
            continue
        for event in det_events:
            assets[event.asset_id] = event.asset
            events[event.id] = event
            name = ((event.metadata or {}).get("user") or {}).get("name")
            if name:
                users.add(name)
        for indicator in detection.indicators.all():
            indicators[indicator.id] = indicator
        for rule in detection.detection_rules.all():
            for technique in rule.mitre_techniques.all():
                techniques[technique.id] = technique
        detections.append(
            {
                "obj": detection,
                "severity": _detection_severity(detection),
                "rules": [r.name for r in detection.detection_rules.all()],
                "event_count": len(det_events),
            }
        )

    timeline = sorted(events.values(), key=lambda e: e.created_at, reverse=True)
    return render(
        request,
        "incident_detail.html",
        {
            "incident": incident,
            "detections": detections,
            "assets": sorted(assets.values(), key=lambda a: a.hostname),
            "users": sorted(users),
            "indicators": list(indicators.values()),
            "techniques": list(techniques.values()),
            "timeline": timeline[:50],
            "event_total": len(timeline),
            "is_active": incident.status in ("open", "investigating"),
        },
    )


@company_required
@require_POST
def incident_update(request, incident_id):
    incident = get_object_or_404(_company_incidents(request.company), id=incident_id)
    action = request.POST.get("action", "")
    note = request.POST.get("note", "").strip()

    if action not in INCIDENT_ACTIONS:
        messages.error(request, "Geçersiz işlem.")
    elif action in ("resolve", "close", "false_positive") and not note:
        messages.error(request, "Vakayı kapatırken çözüm notu girmelisin.")
    else:
        user = request.user if action in ("investigate", "assign") else None
        if action == "assign" and request.POST.get("release"):
            user = None
        incident_action(incident, action, note=note, user=user)
        messages.success(request, "Vaka güncellendi.")
    return redirect("incident_detail", incident_id=incident.id)


def _company_select_response(request, form=None, formset=None, status=200):
    companies = Company.objects.annotate(
        asset_count=Count("assets", distinct=True),
        event_count=Count("assets__securityevent", distinct=True),
        detection_count=Count("assets__securityevent__detections", distinct=True),
    ).order_by("name")
    formset = formset or AssetFormSet(prefix="assets")
    return render(
        request,
        "company_select.html",
        {
            "companies": companies,
            "form": form or CompanyForm(),
            "formset": formset,
            "open_assets": bool(formset.is_bound and any(f.errors for f in formset.forms)),
            "active_company_id": request.session.get(COMPANY_SESSION_KEY),
        },
        status=status,
    )


@login_required
def company_select(request):
    if request.method == "POST":
        company = Company.objects.filter(id=request.POST.get("company_id")).first()
        if company is None:
            messages.error(request, "Seçilen şirket bulunamadı.")
        else:
            request.session[COMPANY_SESSION_KEY] = company.id
            return redirect("dashboard")
    return _company_select_response(request)


@login_required
def company_create(request):
    if request.method != "POST":
        return redirect("company_select")

    form = CompanyForm(request.POST)
    formset = AssetFormSet(request.POST, prefix="assets")
    if not (form.is_valid() and formset.is_valid()):
        return _company_select_response(request, form=form, formset=formset, status=400)

    with transaction.atomic():
        company = form.save()
        assets = [
            row.save(commit=False)
            for row in formset.forms
            if row.has_changed() and row.cleaned_data
        ]
        for asset in assets:
            asset.company = company
            asset.save()

    messages.success(
        request,
        f"{company.name} kaydedildi, {len(assets)} varlık eklendi. API anahtarı: {company.api_key}",
    )
    return redirect("company_select")
