import json
from datetime import datetime

KNOWN_DEVICES_FILE = "known_devices.json"

def load_known_devices():
    """Load trusted devices from local file."""
    try:
        with open(KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_known_devices(devices):
    """Save known devices locally."""
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=4)

def get_mac_vendor(mac):
    """Lookup MAC vendor (optional - can be disabled)."""
    try:
        import requests
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"
