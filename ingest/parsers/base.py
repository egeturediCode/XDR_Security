from .registry import normalization_registry

def process_incoming_log(source_name, raw_payload):
    registry = normalization_registry()
    parser_func = registry.get(source_name)
    
    if not parser_func:
        raise ValueError(f"Desteklenmeyen veri kaynağı: {source_name}")
        
    return parser_func(raw_payload)