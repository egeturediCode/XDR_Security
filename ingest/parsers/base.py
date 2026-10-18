from .registry import normalization_registry
from analytics.services import detection_engine
from incident_management.services import incident_correlation

def process_incoming_log(source_name, raw_payload, company):
    registry = normalization_registry()
    parser_func = registry.get(source_name)
    
    if not parser_func:
        raise ValueError(f"Desteklenmeyen veri kaynağı: {source_name}")
        
    event = parser_func(raw_payload, company)
    detections = detection_engine(event)
    incident_correlation(detections)
    return event