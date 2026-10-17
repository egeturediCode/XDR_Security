from .models import Incident

def _resolve(incident):
    incident.status = 'resolved'
    incident.save()
    return incident

def _close(incident):
    incident.status = 'closed'
    incident.save()
    return incident

INCIDENT_ACTIONS = {
    "resolve": _resolve,
    "close": _close
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

def incident_correlation(detections):
    return None


def incident_action(incident, action, **kwargs):
    if action in INCIDENT_ACTIONS:
        return INCIDENT_ACTIONS[action](incident, **kwargs)
    return None




