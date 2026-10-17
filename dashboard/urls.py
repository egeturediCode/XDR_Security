from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("companies/", views.company_select, name="company_select"),
    path("companies/new/", views.company_create, name="company_create"),
    path("detections/", views.detections, name="detections"),
    path(
        "detections/<int:detection_id>/",
        views.detection_detail,
        name="detection_detail",
    ),
    path("logs/", views.logs, name="logs"),
    path("logs/<int:event_id>/", views.log_detail, name="log_detail"),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="login.html"),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
]
