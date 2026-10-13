from ..models import SecurityEvent, Assets

def parse_fortinet_event(data):
    # Fortinet event parsing logic here
    event = {
        "source": "fortinet",
        "details": data
    }
    return event