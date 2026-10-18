import requests
# CrowdStrike payload definitions for incident management

def action_isolate_device(device_id, crowdstrike_token):
    endpoint = "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain"
    
    headers = {
        "Authorization": f"Bearer {crowdstrike_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "ids": [device_id]
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 202:
            return True, "Cihaz başarıyla ağdan izole edildi (Containment)."
        else:
            return False, f"Hata (HTTP {response.status_code}): {response.text}"
    except Exception as e:
        return False, f"Bağlantı Hatası: {str(e)}"


def action_quarantine_file(file_hash, crowdstrike_token):
    endpoint = "https://api.crowdstrike.com/indicators/entities/iocs/v1"
    
    headers = {
        "Authorization": f"Bearer {crowdstrike_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "indicators": [
            {
                "type": "sha256",
                "value": file_hash,
                "policy": "detect",
                "action": "prevent",
                "description": "SentinelCore tarafindan engellendi."
            }
        ]
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code in [200, 201]:
            return True, f"Dosya hash değeri ({file_hash}) tüm uç noktalarda karantinaya alındı."
        else:
            return False, f"Hata: {response.text}"
    except Exception as e:
        return False, str(e)

def action_kill_process(device_id, process_id, crowdstrike_token):
    headers = {"Authorization": f"Bearer {crowdstrike_token}", "Content-Type": "application/json"}
    
    try:
        session_url = "https://api.crowdstrike.com/real-time-response/entities/sessions/v1"
        session_res = requests.post(session_url, json={"device_id": device_id}, headers=headers, timeout=10)
        session_id = session_res.json().get("resources", [{}])[0].get("session_id")
        
        if not session_id:
            return False, "Cihaz ile canlı oturum açılamadı (Çevrimdışı olabilir)."

        command_url = "https://api.crowdstrike.com/real-time-response/entities/admin-command/v1"
        payload = {
            "base_command": "kill",
            "command_string": f"kill {process_id}",
            "session_id": session_id
        }
        cmd_res = requests.post(command_url, json=payload, headers=headers, timeout=10)
        
        if cmd_res.status_code == 201:
            return True, f"Süreç (PID: {process_id}) başarıyla sonlandırıldı."
        else:
            return False, f"Komut Hatası: {cmd_res.text}"
            
    except Exception as e:
        return False, str(e)