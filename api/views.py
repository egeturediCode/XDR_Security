from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ingest.parsers.base import process_incoming_log


class AutonomousIngestView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        source = data.get("source")

        try:
            event = process_incoming_log(source, data)
            return Response(
                {"message": "Event received", "event_id": event.id},
                status=status.HTTP_200_OK,
            )
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )