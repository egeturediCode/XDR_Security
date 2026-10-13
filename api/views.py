from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from ingest.parsers.crowdstrike import parse_crowdstrike_event
from ingest.parsers.active_directory import parse_active_directory_event
from ingest.parsers.nessus import parse_nessus_event
from ingest.parsers.fortinet import parse_fortinet_event


class AutonomousIngestView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        source = data.get("source")

        if source == "crowdstrike":
            event = parse_crowdstrike_event(data)
        elif source == "nessus":
            event = parse_nessus_event(data)
        elif source == "fortinet":
            event = parse_fortinet_event(data)
        elif source in ("active_directory", "activedirectory"):
            event = parse_active_directory_event(data)
        else:
            return Response(
                {"error": "Unsupported source"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        print(event)
        return Response(
            {"message": "Event received", "event": event},
            status=status.HTTP_200_OK,
        )
