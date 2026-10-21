from django.urls import path
from .views import AutonomousIngestView, response_incident_action

urlpatterns = [
    path('v1/ingest/', AutonomousIngestView.as_view(), name='autonomous-ingest'),
    path('v1/incident-action/', response_incident_action, name='incident-action'),
]