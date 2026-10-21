import time
import random
import urllib.request
import json

DJANGO_API_URL = "http://127.0.0.1:8000/api/v1/ingest/"

COMPANY_NAME = "Beta Lojistik"
API_KEY = "zNZQKmtc5GUxHJePYhzPoXA-DgrxFp6JVR4sD5CQdxU"

# Beta Lojistik şirketine bağlı varlıklar (Assets)
ASSETS = [
    {"hostname": "beta-web-prod", "ip": "10.0.5.20", "mac": "AA:BB:CC:DD:EE:FF", "asset_type": "server"},
    {"hostname": "beta-hr-pc", "ip": "10.0.5.105", "mac": "11:22:33:44:55:66", "asset_type": "workstation"},
    {"hostname": "beta-db-main", "ip": "10.0.5.50", "mac": "00:50:56:AB:CD:EF", "asset_type": "server"},
    {"hostname": "beta-core-switch", "ip": "10.0.1.1", "mac": "C4:12:F5:AA:BB:CC", "asset_type": "network_device"},
    {"hostname": "beta-ceo-laptop", "ip": "10.0.10.15", "mac": "E0:D4:64:11:22:33", "asset_type": "workstation"},
    {"hostname": "beta-mail-ex", "ip": "185.10.20.30", "mac": "00:15:5D:44:55:66", "asset_type": "server"},
]

DOMAIN_NAME = "BETA"
USERS = ["m.demir", "e.kaya", "administrator"]
DC_HOSTNAME = "beta-mail-ex"


def endpoint_assets():
    return [a for a in ASSETS if a["asset_type"] in ("workstation", "server")]


def generate_crowdstrike_event():
    """CrowdStrike Falcon detection olaylarını (native format) simüle eder"""
    asset = random.choice(endpoint_assets())
    events = [
        {"sev": "Critical", "desc": "Endpoint üzerinde şüpheli encoded PowerShell komutu tespit edildi", "tactic": "Execution", "technique": "T1059.001"},
        {"sev": "High", "desc": "LSASS sürecinden kimlik bilgisi çıkarma girişimi engellendi", "tactic": "Credential Access", "technique": "T1003.001"},
        {"sev": "Medium", "desc": "Şüpheli dosya davranışı nedeniyle endpoint karantinaya alındı", "tactic": "Execution", "technique": "T1204.002"}
    ]
    ev = random.choice(events)
    return {
        "source": "crowdstrike",
        "metadata": {"eventType": "DetectionSummaryEvent"},
        "event": {
            "ComputerName": asset["hostname"],
            "LocalIP": asset["ip"],
            "MacAddress": asset["mac"],
            "AssetType": asset["asset_type"],
            "SeverityName": ev["sev"],
            "DetectDescription": ev["desc"],
            "Tactic": ev["tactic"],
            "Technique": ev["technique"],
            "UserName": random.choice(USERS),
            "DetectId": f"ldt:{random.randint(100000, 999999)}"
        }
    }


def generate_activedirectory_event():
    """Active Directory (Windows Security) olaylarını simüle eder"""
    event_id = random.choice([4624, 4625, 4625, 4634])
    src = random.choice([a for a in ASSETS if a["asset_type"] == "workstation"])
    return {
        "source": "active_directory",
        "EventID": event_id,
        "IpAddress": src["ip"],
        "WorkstationName": src["hostname"],
        "MacAddress": src["mac"],
        "AssetType": src["asset_type"],
        "TargetUserName": random.choice(USERS + ["svc-backup"]),
        "TargetDomainName": DOMAIN_NAME,
        "Message": f"Windows Event {event_id} on {DC_HOSTNAME}"
    }


def generate_nessus_event():
    """Nessus zafiyet tarama bulgularını simüle eder"""
    asset = random.choice(ASSETS)
    events = [
        {"sev": 4, "name": "Remote Code Execution", "desc": "Uzaktan kod çalıştırmaya yol açabilecek kritik zafiyet bulundu", "cve": ["CVE-2021-44228"], "solution": "Yamayı uygulayın"},
        {"sev": 2, "name": "SSL/TLS Weak Cipher", "desc": "Sunucuda güvensiz SSL/TLS şifreleme yapılandırması bulundu", "cve": [], "solution": "Güçlü şifre takımlarını etkinleştirin"},
        {"sev": 1, "name": "Exposed Management Service", "desc": "Varlık üzerinde gereksiz ve dışarıya açık yönetim servisi bulundu", "cve": [], "solution": "Servisi kapatın"}
    ]
    ev = random.choice(events)
    return {
        "source": "nessus",
        "hostname": asset["hostname"],
        "host": asset["ip"],
        "mac_address": asset["mac"],
        "asset_type": asset["asset_type"],
        "severity": ev["sev"],
        "plugin_name": ev["name"],
        "description": ev["desc"],
        "cve": ev["cve"],
        "solution": ev["solution"],
        "plugin_id": random.randint(100000, 999999)
    }


def generate_fortinet_event():
    """Fortinet FortiOS trafik/güvenlik loglarını simüle eder"""
    events = [
        {"level": "warning", "action": "block", "msg": "Zararlı C2 adresine giden trafik FortiGate tarafından engellendi"},
        {"level": "notice", "action": "deny", "msg": "Ağda şüpheli port taraması tespit edildi ve kaynak engellendi"},
        {"level": "error", "action": "deny", "msg": "VPN ağ geçidinde tekrarlanan başarısız kimlik doğrulama girişimleri"}
    ]
    ev = random.choice(events)
    src = random.choice(ASSETS)
    return {
        "source": "fortinet",
        "hostname": src["hostname"],
        "mac_address": src["mac"],
        "asset_type": src["asset_type"],
        "level": ev["level"],
        "action": ev["action"],
        "msg": ev["msg"],
        "srcip": src["ip"],
        "srcport": random.randint(1024, 65535),
        "dstip": f"203.0.113.{random.randint(1, 254)}",
        "dstport": random.choice([22, 80, 443, 3389]),
        "proto": random.choice(["TCP", "UDP"])
    }


def main():
    generators = [
        generate_crowdstrike_event,
        generate_activedirectory_event,
        generate_fortinet_event,
        generate_nessus_event
    ]
    print(f"{COMPANY_NAME} Güvenlik Simülatörü Başlatıldı...")
    print("-> Desteklenen Araçlar: CrowdStrike, Active Directory, Fortinet, Nessus")
    print("-> Hedef API: ", DJANGO_API_URL)
    print("-" * 50)

    while True:
        gen_func = random.choice(generators)
        payload = gen_func()

        try:
            req = urllib.request.Request(
                DJANGO_API_URL,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'X-API-KEY': API_KEY}
            )
            with urllib.request.urlopen(req) as response:
                print(f"[{COMPANY_NAME}] [{payload['source'].upper()}] -> İletildi (HTTP {response.status})")
        except Exception as e:
            print(f"[Bağlantı Hatası] Django API'ye ulaşılamadı: {e}")

        time.sleep(random.randint(2, 5))


if __name__ == "__main__":
    main()
