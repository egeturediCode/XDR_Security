from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from ...models import DetectionRule, MitreTechnique


DETECTION_RULES = (
    {
        "name": "successful_brute_force",
        "description": "Kısa süre içinde çoklu başarısız girişin ardından gelen başarılı giriş.",
        "technique_id": "T1110",
        "severity": "critical",
        "parameters": {
            "threshold_failed": 10,
            "time_window_seconds": 60,
            "requires_success_event": True,
            "target_event_uid": 3002,
        },
    },
    {
        "name": "impossible_travel",
        "description": "Aynı kullanıcının iki farklı coğrafi konumdan (IP) mantıksız bir süre zarfında oturum açması.",
        "technique_id": "T1078",
        "severity": "high",
        "parameters": {
            "time_window_minutes": 120,
            "require_geo_ip_lookup": True,
            "target_event_uid": 3002,
            "target_status_id": 1,
        },
    },
    {
        "name": "admin_group_modification",
        "description": "Kritik bir AD grubuna (örn: Domain Admins, Enterprise Admins) şüpheli üye eklenmesi.",
        "technique_id": "T1098",
        "severity": "high",
        "parameters": {
            "target_event_uid": 3002,
            "monitored_groups": [
                "Domain Admins",
                "Enterprise Admins",
                "Administrators",
            ],
            "threshold": 1,
        },
    },
    {
        "name": "obfuscated_powershell_execution",
        "description": "Endpoint üzerinde Base64 ile şifrelenmiş veya gizlenmiş PowerShell komutu.",
        "technique_id": "T1059.001",
        "severity": "high",
        "parameters": {
            "target_event_uid": 2001,
            "regex_patterns": ["(?i)(-e|-enc|-encodedcommand|-w hidden)"],
            "process_names": ["powershell.exe", "pwsh.exe"],
        },
    },
    {
        "name": "critical_cve_on_public_asset",
        "description": "İnternete açık (public) bir varlık üzerinde CVSS skoru 9+ olan zafiyet tespiti.",
        "technique_id": "T1190",
        "severity": "critical",
        "parameters": {
            "target_event_uid": 2002,
            "min_cvss_score": 9.0,
            "require_asset_public_ip": True,
        },
    },
    {
        "name": "brute_force_login",
        "description": "Kısa süre içinde çoklu başarısız giriş denemesi tespiti.",
        "technique_id": "T1110",
        "severity": "high",
        "parameters": {
            "threshold": 20,
            "time_window_seconds": 40,
            "target_event_uid": 3002,
            "target_status_id": 2
        }
    },
    {
        "name": "threat_intel_ip_match",
        "description": "Bilinen zararlı (C2/Botnet) IP adresi ile ağ trafiği tespiti.",
        "technique_id": "T1071",
        "severity": "critical",
        "parameters": {
            "action": "check_threatfox_api",
            "auto_ban": True
        }
    },
    {
        "name": "suspicious_port_scan",
        "description": "Kısa süre içinde tek bir hedeften veya hedefe yönelik çok sayıda engellenen ağ bağlantı denemesi (Port Taraması).",
        "technique_id": "T1046",
        "severity": "medium",
        "parameters": {
            "threshold": 50,
            "time_window_seconds": 60,
            "target_event_uid": 4001,
            "target_status_id": 2
        }
    },
    {
        "name": "successful_brute_force",
        "description": "Kısa süre içinde çoklu başarısız girişin ardından gelen başarılı giriş (Hesap Ele Geçirme).",
        "technique_id": "T1110",
        "severity": "critical",
        "parameters": {
            "threshold_failed": 10,
            "time_window_seconds": 60,
            "requires_success_event": True,
            "target_event_uid": 3002
        }
    },
    {
        "name": "impossible_travel",
        "description": "Aynı kullanıcının fiziksel olarak seyahat edemeyeceği kadar kısa sürede iki farklı ülkeden başarılı giriş yapması.",
        "technique_id": "T1078",
        "severity": "high",
        "parameters": {
            "time_window_minutes": 120,
            "require_geo_ip_lookup": True,
            "target_event_uid": 3002,
            "target_status_id": 1
        }
    },
    {
        "name": "admin_group_modification",
        "description": "Kritik bir AD grubuna (örn: Domain Admins, Enterprise Admins) şüpheli üye eklenmesi.",
        "technique_id": "T1098",
        "severity": "high",
        "parameters": {
            "target_event_uid": 3002,
            "monitored_groups": ["Domain Admins", "Enterprise Admins", "Administrators"],
            "threshold": 1
        }
    },
    {
        "name": "obfuscated_powershell_execution",
        "description": "Endpoint üzerinde Base64 ile şifrelenmiş veya gizlenmiş PowerShell komutu çalıştırılması.",
        "technique_id": "T1059.001",
        "severity": "high",
        "parameters": {
            "target_event_uid": 2001,
            "regex_patterns": ["(?i)(-e|-enc|-encodedcommand|-w hidden)"],
            "process_names": ["powershell.exe", "pwsh.exe"]
        }
    },
    {
        "name": "critical_cve_on_public_asset",
        "description": "İnternete açık (public) bir varlık üzerinde CVSS skoru 9.0 ve üzeri olan zafiyet tespiti.",
        "technique_id": "T1190",
        "severity": "critical",
        "parameters": {
            "target_event_uid": 2002,
            "min_cvss_score": 9.0,
            "require_asset_public_ip": True
        }
    },
    {
        "name": "ransomware_file_extension_activity",
        "description": "Kısa süre içinde bilinen fidye yazılımı (Ransomware) uzantılarına sahip çok sayıda dosya oluşturulması veya değiştirilmesi.",
        "technique_id": "T1486",
        "severity": "critical",
        "parameters": {
            "target_event_uid": 2001,
            "threshold": 20,
            "time_window_seconds": 60,
            "suspicious_extensions": [".encrypted", ".locked", ".crypt", ".ryuk", ".wncry"]
        }
    },
    {
        "name": "lsass_memory_dump",
        "description": "Kimlik hırsızlığı için lsass.exe sürecinin belleğine yetkisiz erişim veya bellek dökümü (dump) alma girişimi.",
        "technique_id": "T1003.001",
        "severity": "critical",
        "parameters": {
            "target_event_uid": 2001,
            "target_process": "lsass.exe",
            "suspicious_access_masks": ["0x1010", "0x1410"]
        }
    },
    {
        "name": "kerberoasting_activity",
        "description": "Kısa süre içinde bir hesaptan çok sayıda SPN (Service Principal Name) bileti talep edilmesi.",
        "technique_id": "T1558.003",
        "severity": "high",
        "parameters": {
            "target_event_uid": 3002,
            "event_id": 4769,
            "ticket_encryption_type": "0x17",
            "threshold": 15,
            "time_window_seconds": 120
        }
    },
    {
        "name": "dns_data_exfiltration",
        "description": "Normalden çok daha uzun ve karmaşık alt alan adları (subdomain) kullanılarak DNS üzerinden veri sızdırma şüphesi.",
        "technique_id": "T1048.003",
        "severity": "medium",
        "parameters": {
            "target_event_uid": 4001,
            "protocol": "DNS",
            "query_length_threshold": 100,
            "entropy_threshold": 4.5
        }
    },
    {
        "name": "cleared_windows_event_logs",
        "description": "Saldırganın izlerini örtmek için Windows Olay Günlüklerini (Security, System, Application) temizlemesi.",
        "technique_id": "T1070.001",
        "severity": "high",
        "parameters": {
            "target_event_uid": 2001,
            "event_ids": [1102, 104],
            "threshold": 1
        }
    },
    {
        "name": "suspicious_scheduled_task",
        "description": "Sisteme kalıcılık sağlamak amacıyla şüpheli bir zamanlanmış görev (schtasks.exe) oluşturulması.",
        "technique_id": "T1053.005",
        "severity": "medium",
        "parameters": {
            "target_event_uid": 2001,
            "process_names": ["schtasks.exe"],
            "command_line_keywords": ["/create", "SYSTEM", "hidden"]
        }
    },
    {
        "name": "concurrent_vpn_logins_same_ip",
        "description": "Aynı dış IP adresinden kısa süre içinde 3 veya daha fazla farklı VPN kullanıcı hesabına başarılı giriş yapılması (Credential Stuffing).",
        "technique_id": "T1078",
        "severity": "high",
        "parameters": {
            "target_event_uid": 3002,
            "status_id": 1,
            "threshold_distinct_users": 3,
            "time_window_minutes": 30
        }
    },
    {
        "name": "edr_tampering_or_disable",
        "description": "Güvenlik yazılımı (Defender, CrowdStrike vb.) servislerinin durdurulması, silinmesi veya yapılandırmasının değiştirilmesi.",
        "technique_id": "T1562.001",
        "severity": "critical",
        "parameters": {
            "target_event_uid": 2001,
            "keywords": ["DisableRealtimeMonitoring", "Stop-Service", "sc stop"],
            "target_services": ["WinDefend", "csagent", "Sense"]
        }
    },
    {
        "name": "rdp_out_of_business_hours",
        "description": "Mesai saatleri dışında veya hafta sonu gerçekleştirilen başarılı RDP (Uzak Masaüstü) bağlantıları.",
        "technique_id": "T1021.001",
        "severity": "low",
        "parameters": {
            "target_event_uid": 4001,
            "target_port": 3389,
            "status_id": 1,
            "business_hours_start": "08:00",
            "business_hours_end": "18:00",
            "exclude_weekends": True
        }
    },
    {
        "name": "large_outbound_data_transfer",
        "description": "İç ağdan dış ağa (İnternet) doğru kısa süre içinde anormal boyutta veri aktarımı (Veri Sızdırma şüphesi).",
        "technique_id": "T1048",
        "severity": "high",
        "parameters": {
            "target_event_uid": 4001,
            "direction": "outbound",
            "bytes_out_threshold": 1073741824, # 1 GB
            "time_window_minutes": 15
        }
    },
    {
        "name": "lotl_binary_abuse",
        "description": "Sistemde var olan meşru araçların (certutil, bitsadmin) zararlı amaçlarla, dosya indirme veya kalıcılık için kullanılması.",
        "technique_id": "T1105",
        "severity": "high",
        "parameters": {
            "target_event_uid": 2001,
            "process_names": ["certutil.exe", "bitsadmin.exe", "vssadmin.exe", "wmic.exe"],
            "command_line_keywords": ["urlcache", "split", "f", "/transfer", "delete shadows"]
        }
    },
    {
        "name": "local_admin_creation",
        "description": "Endpoint veya sunucu üzerinde yetki yükseltme amaçlı yeni bir yerel yönetici hesabı oluşturulması.",
        "technique_id": "T1136.001",
        "severity": "medium",
        "parameters": {
            "target_event_uid": 3002,
            "event_ids": [4720, 4732],
            "target_group": "Administrators"
        }
    }
)


class Command(BaseCommand):
    help = "Algılama kurallarını veritabanına ekler veya günceller"

    def handle(self, *args, **options):
        technique_ids = {rule["technique_id"] for rule in DETECTION_RULES}
        techniques = {
            technique.technique_id: technique
            for technique in MitreTechnique.objects.filter(
                technique_id__in=technique_ids
            )
        }
        missing_techniques = sorted(technique_ids - techniques.keys())
        if missing_techniques:
            raise CommandError(
                "MITRE teknikleri veritabanında bulunamadı: "
                f"{', '.join(missing_techniques)}. Önce mitre_syn komutunu çalıştırın."
            )

        created_count = 0
        updated_count = 0

        with transaction.atomic():
            for rule_data in DETECTION_RULES:
                rule, created = DetectionRule.objects.update_or_create(
                    name=rule_data["name"],
                    defaults={
                        "description": rule_data["description"],
                        "severity": rule_data["severity"],
                        "parameters": rule_data["parameters"],
                    },
                )
                rule.mitre_techniques.set(
                    [techniques[rule_data["technique_id"]]]
                )

                if created:
                    created_count += 1
                else:
                    updated_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                "Algılama kuralları tamamlandı. "
                f"Yeni: {created_count}, Güncellenen: {updated_count}"
            )
        )
