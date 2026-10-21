from celery import shared_task
from .models import Incident
from .services import incident_action

# bind=True görevin kendisine erişmesini sağlar, max_retries hata olursa kaç kez deneyeceğini belirler
@shared_task(bind=True, max_retries=3)
def execute_async_action_task(self,action, target_id, actor, **kwargs):
    try:
        incident = Incident.objects.get(id=target_id)
        incident_action(incident, action, actor=actor, **kwargs)
        incident.save()

    except Exception as exc:
        # Eğer bağlantı kopması gibi beklenmedik bir hata olursa görevi silme, 60 saniye bekle ve tekrar dene (Maks 3 kere)
        raise self.retry(exc=exc, countdown=60)