from ..models import SecurityEvent, Assets

def parse_registry_event(data):
    # Registry event parsing logic here
    event = {
        "source": "registry",
        "details": data
    }
    return event