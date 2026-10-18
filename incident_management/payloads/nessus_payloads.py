import requests
# Nessus payload definitions for incident management

def action_trigger_scan(target_ip, scan_template_id, nessus_url, nessus_token):
    endpoint = f"{nessus_url}/scans/{scan_template_id}/launch"
    
    headers = {
        "X-ApiKeys": nessus_token,
        "Content-Type": "application/json"
    }
    
    payload = {
        "alt_targets": [target_ip]
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=10)
        
        if response.status_code == 200:
            scan_uuid = response.json().get("scan_uuid")
            return True, f"IP ({target_ip}) için zafiyet taraması başlatıldı. Tarama UUID: {scan_uuid}"
        else:
            return False, f"Hata (HTTP {response.status_code}): {response.text}"
    except Exception as e:
        return False, f"Bağlantı Hatası: {str(e)}"