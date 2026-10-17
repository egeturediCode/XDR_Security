from .registry import normalization_registry
from analytics.services import detection_engine

def process_incoming_log(source_name, raw_payload, company):
    registry = normalization_registry()
    parser_func = registry.get(source_name)
    
    if not parser_func:
        raise ValueError(f"Desteklenmeyen veri kaynağı: {source_name}")
        
    event = parser_func(raw_payload, company)
    detection_engine(event)
    return event