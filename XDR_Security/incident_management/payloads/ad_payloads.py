import requests

# Active Directory payload definitions for incident management

def action_disable_user(user_id, ms_graph_token):
    endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    
    headers = {
        "Authorization": f"Bearer {ms_graph_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "accountEnabled": False
    }

    try:
        response = requests.patch(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 204:
            return True, "Kullanıcı başarıyla askıya alındı."
        else:
            return False, f"Hata: {response.text}"
            
    except Exception as e:
        return False, str(e)


def action_force_password_reset(user_id, ms_graph_token):
    endpoint = f"https://graph.microsoft.com/v1.0/users/{user_id}"
    
    headers = {
        "Authorization": f"Bearer {ms_graph_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True
        }
    }

    try:
        response = requests.patch(endpoint, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 204:
            return True, "Kullanıcı bir sonraki girişinde parola sıfırlamaya zorlandı."
        else:
            return False, f"Hata (HTTP {response.status_code}): {response.text}"
            
    except Exception as e:
        return False, f"Bağlantı Hatası: {str(e)}"
