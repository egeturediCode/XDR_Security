import os
import sys
from pathlib import Path

import django
import requests
from django.core.management.base import BaseCommand

if __package__ in (None, ""):
    project_root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(project_root))


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "XDR_Security.settings")
django.setup()



if __package__ in (None, ""):
    from analytics.models import MitreTechnique
else:
    from ...models import MitreTechnique


MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/"
    "enterprise-attack.json"
)


class Command(BaseCommand):
    help = "Import MITRE ATT&CK techniques into the database"

    def handle(self, *args, **options):
        self.stdout.write("MITRE verisi indiriliyor...")

        response = requests.get(MITRE_URL, timeout=120)
        response.raise_for_status()
        bundle = response.json()

        count = 0

        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            external_id = None
            external_url = ""

            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id")
                    external_url = ref.get("url", "")
                    break

            if not external_id:
                continue

            tactics = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            MitreTechnique.objects.update_or_create(
                technique_id=external_id,
                defaults={
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "external_url": external_url,
                    "is_subtechnique": obj.get(
                        "x_mitre_is_subtechnique", False
                    ),
                    "revoked": (
                        obj.get("revoked", False)
                        or obj.get("x_mitre_deprecated", False)
                    ),
                },
            )

            count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"MITRE senkronizasyonu tamamlandı. "
                f"{count} teknik işlendi."
            )
        )

if __name__ == "__main__":
    Command().handle()