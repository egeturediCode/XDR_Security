import requests

# Fortinet payload definitions for incident management

def action_ban_ip_address(ip_address, fw_url, fw_token):
    endpoint = f"{fw_url}/api/v2/cmdb/firewall/address"
    
    headers = {
        "Authorization": f"Bearer {fw_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "name": f"SentinelCore_Ban_{ip_address.replace('.', '_')}",
        "subnet": f"{ip_address} 255.255.255.255",
        "type": "ipmask",
        "color": 6,
        "comment": "SentinelCore tarafindan otomatik engellendi."
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=10)
        
        if response.status_code == 200:
            return True, f"IP Adresi ({ip_address}) FortiGate adres defterine eklendi."
        else:
            return False, f"Hata (HTTP {response.status_code}): {response.text}"
    except Exception as e:
        return False, f"Bağlantı Hatası: {str(e)}"


def action_block_port(port_number, protocol_type, fw_url, fw_token):
    endpoint = f"{fw_url}/api/v2/cmdb/firewall.service/custom"
    
    headers = {
        "Authorization": f"Bearer {fw_token}",
        "Content-Type": "application/json"
    }
    
    protocol_type = protocol_type.upper()
    
    payload = {
        "name": f"SentinelCore_Port_{protocol_type}_{port_number}",
        "protocol": "TCP/UDP/SCTP",
        "comment": "SentinelCore şüpheli port engellemesi"
    }
    
    if protocol_type == "TCP":
        payload["tcp-portrange"] = str(port_number)
    elif protocol_type == "UDP":
        payload["udp-portrange"] = str(port_number)

    try:
        response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=10)
        
        if response.status_code == 200:
            return True, f"Port {protocol_type}/{port_number} FortiGate üzerinde tanımlandı/kapatıldı."
        else:
            return False, f"Hata: {response.text}"
    except Exception as e:
        return False, str(e)


def action_block_domain(domain_name, fw_url, fw_token):
    endpoint = f"{fw_url}/api/v2/cmdb/firewall/address"
    
    headers = {
        "Authorization": f"Bearer {fw_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "name": f"SentinelCore_Domain_{domain_name.replace('.', '_')}",
        "fqdn": domain_name,
        "type": "fqdn",
        "color": 6,
        "comment": "SentinelCore C2 Domain Engellemesi"
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=10)
        
        if response.status_code == 200:
            return True, f"Domain ({domain_name}) FortiGate üzerinde engellendi."
        else:
            return False, f"Hata: {response.text}"
    except Exception as e:
        return False, str(e)