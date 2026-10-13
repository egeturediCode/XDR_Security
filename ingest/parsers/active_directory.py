from ..models import SecurityEvent, Assets

def parse_active_directory_event(data):
    # Active Directory event parsing logic here
    event = {
        "source": "active_directory",
        "details": data
    }
    return event