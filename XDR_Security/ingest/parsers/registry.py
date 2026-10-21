from ..models import SecurityEvent, Assets
from .crowdstrike import crowdstrike_normalization 
from .nessus import nessus_normalization
from .fortinet import fortinet_normalization
from .active_directory import active_directory_normalization

SUPPORTED_SERVICES = [
    "crowdstrike",
    "nessus",
    "fortinet",
    "active_directory"
]

def normalization_registry():
    return {
        "crowdstrike": crowdstrike_normalization,
        "nessus": nessus_normalization,
        "fortinet": fortinet_normalization,
        "active_directory": active_directory_normalization,
    }
