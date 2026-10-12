from django.urls import path
from .views import AutonomousIngestView

urlpatterns = [
    path('api/v1/ingest/', AutonomousIngestView.as_view(), name='autonomous-ingest'),
]