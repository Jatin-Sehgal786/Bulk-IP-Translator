import requests
import socket
import configparser

# Load API keys from config.ini
config = configparser.ConfigParser()
config.read("config.ini")
ABUSEIPDB_API_KEY = config.get("API_KEYS", "ABUSEIPDB_API_KEY", fallback=None)
SHODAN_API_KEY = config.get("API_KEYS", "SHODAN_API_KEY", fallback=None)

def get_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "N/A"

def get_asn_info(ip):
    try:
        response = requests.get(f"https://ipwhois.app/json/{ip}", timeout=5)
        data = response.json()
        return {
            "ASN": data.get("asn", "N/A"),
            "Org": data.get("org", "N/A")
        }
    except Exception:
        return {"ASN": "N/A", "Org": "N/A"}

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"AbuseScore": "N/A", "IsMalicious": "N/A"}

    try:
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=5)
        data = response.json()["data"]
        return {
            "AbuseScore": data.get("abuseConfidenceScore", "N/A"),
            "IsMalicious": "Yes" if data.get("abuseConfidenceScore", 0) > 0 else "No"
        }
    except Exception:
        return {"AbuseScore": "N/A", "IsMalicious": "N/A"}

def check_shodan(ip):
    if not SHODAN_API_KEY:
        return {"OpenPorts": "N/A", "Hostnames": "N/A", "Tags": "N/A"}

    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=5)
        data = response.json()
        open_ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])
        return {
            "OpenPorts": ", ".join(map(str, open_ports)) if open_ports else "None",
            "Hostnames": ", ".join(hostnames) if hostnames else "None",
            "Tags": ", ".join(tags) if tags else "None"
        }
    except Exception:
        return {"OpenPorts": "N/A", "Hostnames": "N/A", "Tags": "N/A"}

def lookup_ip(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        geo = response.json()

        if geo["status"] != "success":
            return {"IP": ip, "Error": geo.get("message", "Unknown error")}

        reverse_dns = get_reverse_dns(ip)
        asn_info = get_asn_info(ip)
        abuse_data = check_abuseipdb(ip)
        shodan_data = check_shodan(ip)

        return {
            "IP": geo["query"],
            "Country": geo["country"],
            "Region": geo["regionName"],
            "City": geo["city"],
            "ISP": geo["isp"],
            "Lat": geo["lat"],
            "Lon": geo["lon"],
            "Reverse DNS": reverse_dns,
            "ASN": asn_info["ASN"],
            "Org": asn_info["Org"],
            "AbuseScore": abuse_data["AbuseScore"],
            "IsMalicious": abuse_data["IsMalicious"],
            "OpenPorts": shodan_data["OpenPorts"],
            "Hostnames": shodan_data["Hostnames"],
            "Tags": shodan_data["Tags"]
        }

    except Exception as e:
        return {"IP": ip, "Error": str(e)}
