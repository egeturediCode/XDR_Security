from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from ingest.serializers import IngestEventSerializer


class AutonomousIngestView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = IngestEventSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Event received", "data": serializer.data},
            status=status.HTTP_200_OK,
        )
