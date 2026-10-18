import inspect
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ingest.parsers.base import process_incoming_log
from incident_management.services import SERVICE_ACTION_NAMES, incident_action, INCIDENT_ACTIONS
from incident_management.models import Incident
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
        


SERVICE_ACTION_CREDENTIALS = {
    "ms_graph_token": "MS_GRAPH_TOKEN",
    "crowdstrike_token": "CROWDSTRIKE_TOKEN",
    "fw_url": "FORTINET_URL",
    "fw_token": "FORTINET_TOKEN",
    "nessus_url": "NESSUS_URL",
    "nessus_token": "NESSUS_TOKEN",
}
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def response_incident_action(request):
    incident_id = request.data.get("incident_id")
    action = request.data.get("action")
    params = request.data.get("params") or {}

    if not incident_id:
        return Response({"error": "Incident ID is required"}, status=status.HTTP_400_BAD_REQUEST)
    if action not in SERVICE_ACTION_NAMES or action not in INCIDENT_ACTIONS:
        return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)
    if not isinstance(params, dict):
        return Response({"error": "params must be an object"}, status=status.HTTP_400_BAD_REQUEST)

    incident = Incident.objects.filter(
        id=incident_id,
        status="investigating",
        detection__events__asset__company_id=request.session.get("company_id"),
    ).first()
    if incident is None:
        return Response({"error": "Incident not found or not under investigation"}, status=status.HTTP_404_NOT_FOUND)

    kwargs = {}
    for name in inspect.signature(INCIDENT_ACTIONS[action]).parameters:
        if name in SERVICE_ACTION_CREDENTIALS:
            kwargs[name] = getattr(settings, SERVICE_ACTION_CREDENTIALS[name])
        elif str(params.get(name, "")).strip():
            kwargs[name] = str(params[name]).strip()
        else:
            return Response({"error": f"Missing parameter: {name}"}, status=status.HTTP_400_BAD_REQUEST)

    success, message = incident_action(incident, action, actor=request.user, **kwargs)
    return Response(
        {"success": success, "message": message},
        status=status.HTTP_200_OK if success else status.HTTP_502_BAD_GATEWAY,
    )



@api_view(["GET"])
def health_check(request):
    return Response({"status": "ok"}, status=status.HTTP_200_OK)