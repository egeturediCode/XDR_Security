
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone as dt_timezone
import requests
from decouple import config
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

if __package__ in (None, ""):
    import django

    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "XDR_Security.settings")
    django.setup()
    from analytics.models import ThreatIndicator
else:
    from ...models import ThreatIndicator


API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def parse_threatfox_date(value):
    if not value:
        return None

    try:
        # ThreatFox formatı: 2026-10-13 12:30:00 UTC
        parsed = datetime.strptime(
            value, "%Y-%m-%d %H:%M:%S UTC"
        )
        return parsed.replace(tzinfo=dt_timezone.utc)
    except (ValueError, TypeError):
        return None


def normalize_ioc_type(ioc_type):
    mapping = {
        "ip": ThreatIndicator.IndicatorType.IP,
        "ip:port": ThreatIndicator.IndicatorType.IP_PORT,
        "domain": ThreatIndicator.IndicatorType.DOMAIN,
        "url": ThreatIndicator.IndicatorType.URL,
        "md5_hash": ThreatIndicator.IndicatorType.HASH,
        "sha256_hash": ThreatIndicator.IndicatorType.HASH,
    }
    return mapping.get(ioc_type)


class Command(BaseCommand):
    help = "ThreatFox IOC verilerini veritabanına aktarır"

    def handle(self, *args, **options):
        auth_key = config("THREATFOX_AUTH_KEY", default="")

        if not auth_key:
            raise CommandError(
                "THREATFOX_AUTH_KEY değeri .env dosyasında veya ortam değişkenlerinde tanımlı değil."
            )

        max_attempts = 4
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(
                    API_URL,
                    headers={"Auth-Key": auth_key},
                    json={"query": "get_iocs", "days": 7},
                    timeout=60,
                )
                response.raise_for_status()
                payload = response.json()
                break
            except (requests.RequestException, ValueError) as exc:
                if attempt == max_attempts:
                    raise CommandError(
                        f"ThreatFox API isteği başarısız: {exc}"
                    ) from exc
                self.stderr.write(
                    f"İstek başarısız (deneme {attempt}/{max_attempts}), "
                    "tekrar deneniyor..."
                )
                time.sleep(2 * attempt)

        if payload.get("query_status") != "ok":
            raise CommandError(
                "ThreatFox sorgusu başarılı değil: "
                f"{payload.get('query_status')}"
            )

        indicators = payload.get("data") or []
        created_count = 0
        updated_count = 0
        skipped_count = 0

        with transaction.atomic():
            for item in indicators:
                value = item.get("ioc", "").strip()
                indicator_type = normalize_ioc_type(
                    item.get("ioc_type", "")
                )

                if not value or not indicator_type:
                    skipped_count += 1
                    continue

                _, created = ThreatIndicator.objects.update_or_create(
                    source="threatfox",
                    value=value,
                    indicator_type=indicator_type,
                    defaults={
                        "malware": (
                            item.get("malware_printable")
                            or item.get("malware")
                            or ""
                        ),
                        "first_seen": parse_threatfox_date(
                            item.get("first_seen")
                        ),
                        "last_seen": parse_threatfox_date(
                            item.get("last_seen")
                        ),
                        "is_active": True,
                        "raw_data": item,
                    },
                )

                if created:
                    created_count += 1
                else:
                    updated_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"ThreatFox senkronizasyonu tamamlandı. "
                f"Yeni: {created_count}, "
                f"Güncellenen: {updated_count}, "
                f"Atlanan: {skipped_count}"
            )
        )

if __name__ == "__main__":
    Command().handle()