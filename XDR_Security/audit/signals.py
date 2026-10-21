from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .services import create_audit_log


@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    create_audit_log("LOGIN", user=user, request=request)


@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    if user is not None:
        create_audit_log("LOGOUT", user=user, request=request)


@receiver(user_login_failed)
def log_login_failed(sender, credentials, request=None, **kwargs):
    create_audit_log("LOGIN_FAILED", request=request, username=str(credentials.get("username", "")))
