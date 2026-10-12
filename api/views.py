from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Create your views here.

class AutonomousIngestView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        # Burada veriyi işleyebilir veya kaydedebilirsiniz
        return Response({"message": "Event received", "data": data}, status=status.HTTP_200_OK)
