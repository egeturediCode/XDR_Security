from django.core.management.base import BaseCommand

from ingest.models import Company, Assets

def seed_companies_and_assets():
    company1, c1_created = Company.objects.get_or_create(
        name="Alpha Corp",
        defaults={
            "address": "Levent, İstanbul",
            "contact_email": "security@alphacorp.com",
            "contact_phone": "+905551234567"
        }
    )
    
    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-dc-01",
        defaults={
            "ip_address": "192.168.1.10",
            "mac_address": "00:1A:2B:3C:4D:5E",
            "asset_type": "server",
            "criticality": "critical",
            "is_public": False
        }
    )
    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-fw-01",
        defaults={
            "ip_address": "203.0.113.5",
            "mac_address": "00:11:22:33:44:55",
            "asset_type": "network_device",
            "criticality": "high",
            "is_public": True,
        }
    )

    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-web-01",
        defaults={
            "ip_address": "203.0.113.10",
            "mac_address": "AA:BB:CC:11:22:33",
            "asset_type": "server",
            "criticality": "high",
            "is_public": True,
        }
    )
    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-db-prod",
        defaults={
            "ip_address": "192.168.1.50",
            "mac_address": "00:1A:2B:AA:BB:CC",
            "asset_type": "server",
            "criticality": "critical",
            "is_public": False,
        }
    )
    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-hr-laptop",
        defaults={
            "ip_address": "192.168.2.105",
            "mac_address": "FC:AA:14:55:77:88",
            "asset_type": "workstation",
            "criticality": "medium",
            "is_public": False,
        }
    )
    Assets.objects.get_or_create(
        company=company1,
        hostname="alpha-dev-srv",
        defaults={
            "ip_address": "192.168.3.20",
            "mac_address": "00:50:56:C0:00:08",
            "asset_type": "server",
            "criticality": "low",
            "is_public": False,
        }
    )

    company2, c2_created = Company.objects.get_or_create(
        name="Beta Lojistik",
        defaults={
            "address": "Alsancak, İzmir",
            "contact_email": "it@betalojistik.com",
            "contact_phone": "+905559876543"
        }
    )

    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-web-prod",
        defaults={
            "ip_address": "10.0.5.20",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "asset_type": "server",
            "criticality": "high",
            "is_public": True
        }
    )
    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-hr-pc",
        defaults={
            "ip_address": "10.0.5.105",
            "mac_address": "11:22:33:44:55:66",
            "asset_type": "workstation",
            "criticality": "medium",
            "is_public": False
        }
    )

    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-db-main",
        defaults={
            "ip_address": "10.0.5.50",
            "mac_address": "00:50:56:AB:CD:EF",
            "asset_type": "server",
            "criticality": "critical",
            "is_public": False
        }
    )
    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-core-switch",
        defaults={
            "ip_address": "10.0.1.1",
            "mac_address": "C4:12:F5:AA:BB:CC",
            "asset_type": "network_device",
            "criticality": "critical",
            "is_public": False
        }
    )
    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-ceo-laptop",
        defaults={
            "ip_address": "10.0.10.15",
            "mac_address": "E0:D4:64:11:22:33",
            "asset_type": "workstation",
            "criticality": "high",
            "is_public": False
        }
    )
    Assets.objects.get_or_create(
        company=company2,
        hostname="beta-mail-ex",
        defaults={
            "ip_address": "185.10.20.30",
            "mac_address": "00:15:5D:44:55:66",
            "asset_type": "server",
            "criticality": "high",
            "is_public": True
        }
    )

    print("Veritabanı kayıt işlemi tamamlandı.")
    print(f"Alpha Corp API Key: {company1.api_key}")
    print(f"Beta Lojistik API Key: {company2.api_key}")


class Command(BaseCommand):
    help = "Örnek şirket ve varlık kayıtlarını oluşturur."

    def handle(self, *args, **options):
        seed_companies_and_assets()