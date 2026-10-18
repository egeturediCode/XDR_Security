from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import Incident, IncidentAction
from .payloads.ad_payloads import action_disable_user, action_force_password_reset
from .payloads.nessus_payloads import action_trigger_scan
from .payloads.crowdstrike_payloads import action_isolate_device, action_kill_process, action_quarantine_file
from .payloads.fortinet_payloads import action_ban_ip_address, action_block_port, action_block_domain

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIVE_STATUSES = ("open", "investigating")
CORRELATION_WINDOW = timedelta(hours=24)

def _finish(incident, status, note=""):
    incident.status = status
    incident.resolved_at = timezone.now()
    if note:
        incident.resolution_note = note
    incident.save()
    return incident


def _resolve(incident, note="", **_):
    return _finish(incident, "resolved", note)


def _close(incident, note="", **_):
    return _finish(incident, "closed", note)


def _false_positive(incident, note="", **_):
    return _finish(incident, "false_positive", note)


def _investigate(incident, user=None, **_):
    incident.status = "investigating"
    incident.resolved_at = None
    if user is not None and incident.assigned_to_id is None:
        incident.assigned_to = user
    incident.save()
    return incident


def _reopen(incident, **_):
    incident.status = "open"
    incident.resolved_at = None
    incident.save()
    return incident


def _assign(incident, user=None, **_):
    incident.assigned_to = user
    incident.save(update_fields=["assigned_to", "updated_at"])
    return incident

def ad_payloads():
    return {
        "disable_user": action_disable_user,
        "force_password_reset": action_force_password_reset
    }   
def nessus_payloads():
    return {
        "trigger_scan": action_trigger_scan
    }
def crowdstrike_payloads():
    return {
        "isolate_device": action_isolate_device,
        "kill_process": action_kill_process,
        "quarantine_file": action_quarantine_file
    }
def fortinet_payloads():
    return {
        "ban_ip_address": action_ban_ip_address,
        "block_port": action_block_port,
        "block_domain": action_block_domain
    }


INCIDENT_ACTIONS = {
    "investigate": _investigate,
    "resolve": _resolve,
    "close": _close,
    "false_positive": _false_positive,
    "reopen": _reopen,
    "assign": _assign,
    "disable_user": ad_payloads()["disable_user"],
    "force_password_reset": ad_payloads()["force_password_reset"],
    "trigger_scan": nessus_payloads()["trigger_scan"],
    "isolate_device": crowdstrike_payloads()["isolate_device"],
    "kill_process": crowdstrike_payloads()["kill_process"],
    "quarantine_file": crowdstrike_payloads()["quarantine_file"],
    "ban_ip_address": fortinet_payloads()["ban_ip_address"],
    "block_port": fortinet_payloads()["block_port"],
    "block_domain": fortinet_payloads()["block_domain"],
}

def create_incident(title, description, severity='medium', status='open', assigned_to=None):
    incident = Incident.objects.create(
        title=title,
        description=description,
        severity=severity,
        status=status,
        assigned_to=assigned_to
    )
    return incident

def _rank(severity):
    return SEVERITY_RANK.get(severity, 0)


def _detection_severity(detection):
    severities = [detection.severity] if detection.severity else []
    severities += list(detection.detection_rules.values_list("severity", flat=True))
    if detection.indicators.exists():
        severities.append("high")
    if not severities:
        severities = [
            str(value).lower()
            for value in detection.events.values_list("severity", flat=True)
        ]
    severities = [value for value in severities if value in SEVERITY_RANK]
    return max(severities, key=_rank) if severities else "high"


def _detection_users(events):
    users = set()
    for event in events:
        name = ((event.metadata or {}).get("user") or {}).get("name")
        if name:
            users.add(name)
    return users


def _find_active_incident(asset_ids, users):
    scope = Q(detection__events__asset_id__in=asset_ids)
    for user in users:
        scope |= Q(detection__events__metadata__user__name=user)
    return (
        Incident.objects.filter(
            scope,
            status__in=ACTIVE_STATUSES,
            created_at__gte=timezone.now() - CORRELATION_WINDOW,
        )
        .distinct()
        .order_by("-created_at")
        .first()
    )


@transaction.atomic
def _correlate_detection(detection):
    events = list(detection.events.select_related("asset"))
    if not events:
        return None

    severity = _detection_severity(detection)
    asset_ids = {event.asset_id for event in events}
    incident = _find_active_incident(asset_ids, _detection_users(events))

    if incident is None:
        hostnames = ", ".join(sorted({event.asset.hostname for event in events}))
        incident = create_incident(
            title=f"{detection.name} - {hostnames}",
            description=detection.description,
            severity=severity,
            status="open",
        )
    elif _rank(severity) > _rank(incident.severity):
        incident.severity = severity
        incident.save(update_fields=["severity", "updated_at"])

    incident.detection.add(detection)
    return incident


def incident_correlation(detections):
    incidents = []
    for detection in detections:
        if detection.incidents.exists():
            continue
        incident = _correlate_detection(detection)
        if incident is not None and incident not in incidents:
            incidents.append(incident)
    return incidents


SECRET_PARAMS = {"ms_graph_token", "crowdstrike_token", "fw_token", "nessus_token"}
SERVICE_ACTION_NAMES = {
    "disable_user", "force_password_reset", "trigger_scan", "isolate_device",
    "kill_process", "quarantine_file", "ban_ip_address", "block_port", "block_domain",
}


def _record_action(incident, action, params, actor, success=True, message=""):
    return IncidentAction.objects.create(
        incident=incident,
        action=action,
        params={k: v for k, v in params.items() if k not in SECRET_PARAMS},
        executed_by=actor if getattr(actor, "pk", None) else None,
        success=success,
        message=message,
    )


def incident_action(incident, action, actor=None, **kwargs):
    """Run an action and record it. Service actions return (success, message)."""
    if not incident or action not in INCIDENT_ACTIONS:
        return None
    if action in SERVICE_ACTION_NAMES:
        result = INCIDENT_ACTIONS[action](**kwargs)
        success, message = result if isinstance(result, tuple) else (bool(result), "")
        _record_action(incident, action, kwargs, actor, success, message)
        if success:
            incident.save(update_fields=["updated_at"])
        return success, message

    INCIDENT_ACTIONS[action](incident, **kwargs)
    params = {"note": kwargs["note"]} if kwargs.get("note") else {}
    _record_action(incident, action, params, actor)
    return None
