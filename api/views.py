from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ingest.parsers.base import process_incoming_log
from ingest.models import Company


class AutonomousIngestView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            company = Company.objects.get(api_key=request.headers.get("X-API-KEY"))
        except Company.DoesNotExist:
            return Response(
                {"error": "Invalid API key"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not company.is_active:
            return Response(
                {"error": "Company is not active"},
                status=status.HTTP_403_FORBIDDEN,
            )
        data = request.data
        source = data.get("source")

        try:
            event = process_incoming_log(source, data, company)
            detection_ids = list(event.detections.values_list("id", flat=True))
            return Response(
                {
                    "message": "Event received",
                    "event_id": event.id,
                    "detection_ids": detection_ids,
                },
                status=status.HTTP_200_OK,
            )
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

def health_check(request):
    return Response({"status": "ok"}, status=status.HTTP_200_OK)

def response_incident_action(request):
    return Response({"status": "ok"}, status=status.HTTP_200_OK)