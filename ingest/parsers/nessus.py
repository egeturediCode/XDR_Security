from ..models import SecurityEvent, Assets

def parse_nessus_event(data):
    # Nessus event parsing logic here
    event = {
        "source": "nessus",
        "details": data
    }
    return event