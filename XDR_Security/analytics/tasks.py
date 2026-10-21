from celery import shared_task
from .models import SecurityEvent
from .services import detection_engine
from incident_management.services import incident_correlation

@shared_task
def run_detection_pipeline_task(event_id):
    try:
        event = SecurityEvent.objects.get(id=event_id)
        detections = detection_engine(event)
        
        if detections:
            incident_correlation(detections)
            
    except SecurityEvent.DoesNotExist:
        pass