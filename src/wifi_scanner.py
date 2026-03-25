#!/usr/bin/env python3
"""
WiFi Device Scanner v2.3
Improved version with argparse for the xAI Security Engineer study plan
"""

import os
import sys
import json
import argparse
import netifaces
from datetime import datetime
from scapy.all import *

KNOWN_DEVICES_FILE = "known_devices.json"

def load_known_devices():
    """Load trusted devices from local file."""
    try:
        with open(KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_known_devices(devices):
    """Save known devices locally (never uploaded to GitHub)."""
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=4)

def get_mac_vendor(mac):
    """Lookup MAC vendor using public API (optional)."""
    try:
        import requests
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def is_monitor_mode(iface):
    """Check if WiFi interface is in monitor mode."""
    try:
        output = os.popen(f"iwconfig {iface} 2>/dev/null").read()
        return "Mode:Monitor" in output
    except:
        return False

def get_best_interface():
    """Automatically choose the best network interface."""
    interfaces = get_if_list()
    print(f"[+] Available interfaces: {interfaces}")

    # Priority 1: Monitor mode (best for WiFi sniffing)
    for iface in interfaces:
        if "mon" in iface.lower():
            print(f"[+] Using monitor-mode interface: {iface}")
            return iface

    # Priority 2: Wireless interface
    for iface in interfaces:
        if iface.lower().startswith(('wlan', 'wlp', 'wl')) and iface != "lo":
            print(f"[+] Using wireless interface: {iface}")
            return iface

    # Priority 3: Any non-loopback interface
    for iface in interfaces:
        if iface != "lo":
            print(f"[+] Using interface: {iface}")
            return iface

    print("[-] No suitable interface found!")
    sys.exit(1)

def get_subnet(iface):
    """Automatically detect your local network range."""
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            subnet = ip.rsplit('.', 1)[0] + ".0/24"
            print(f"[+] Auto-detected subnet: {subnet} (your IP: {ip})")
            return subnet
    except:
        pass
    print("[-] Could not detect subnet. Using safe default.")
    return "192.168.0.0/24"

def passive_wifi_scan(iface, duration):
    """Passive scan - listens for WiFi beacons and probes."""
    print(f"[+] Starting passive WiFi scan on {iface} for {duration} seconds...")
    devices = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            mac = pkt.addr2 or (pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else None)
            if mac and mac not in devices:
                devices[mac] = {
                    "mac": mac,
                    "vendor": get_mac_vendor(mac),
                    "type": "AP" if pkt.haslayer(Dot11Beacon) else "Client",
                    "timestamp": datetime.now().isoformat()
                }

    sniff(iface=iface, prn=packet_handler, timeout=duration, store=False)
    return list(devices.values())

def arp_scan(iface, target):
    """Active ARP scan - works best in normal (managed) mode."""
    print(f"[+] Starting ARP scan on {iface} for {target}...")
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, iface=iface, timeout=6, verbose=False)[0]

    devices = []
    for _, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc),
            "type": "Device"
        })
    return devices

def print_devices(devices, known_devices):
    print("\n" + "="*85)
    print(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*85)

    for dev in devices:
        mac = dev.get("mac", "N/A")
        status = "KNOWN" if mac in known_devices else "UNKNOWN ⚠️"
        ip = dev.get("ip", "N/A")
        print(f"IP: {ip:18}  MAC: {mac}   Vendor: {dev.get('vendor','Unknown')[:40]:40}  [{status}]")

    print("="*85)

def main():
    # === ARGUMENT PARSER - This is the big new feature ===
    parser = argparse.ArgumentParser(description="WiFi Device Scanner for Security Learning")
    
    parser.add_argument("-i", "--interface", help="Network interface to use (e.g. wlp0s20f3)")
    parser.add_argument("-m", "--mode", choices=["auto", "arp", "passive"], default="auto",
                        help="Scan mode: auto (default), arp, or passive")
    parser.add_argument("-d", "--duration", type=int, default=20,
                        help="Duration in seconds for passive scan (default: 20)")
    parser.add_argument("--no-vendor", action="store_true",
                        help="Disable MAC vendor lookup (faster, no internet needed)")

    args = parser.parse_args()

    print("🚀 WiFi Device Scanner v2.3 - Security Engineer Project")

    # Choose interface
    iface = args.interface or get_best_interface()

    known = load_known_devices()

    # Decide which scan to run
    if args.mode == "passive" or (args.mode == "auto" and is_monitor_mode(iface)):
        devices = passive_wifi_scan(iface, args.duration)
    else:
        target = get_subnet(iface)
        devices = arp_scan(iface, target)

    print_devices(devices, known)

    if devices and input("\nAdd unknown devices to known list? (y/n): ").lower() == 'y':
        for dev in devices:
            mac = dev.get("mac")
            if mac and mac not in known:
                known[mac] = dev
        save_known_devices(known)
        print("[+] Known devices updated.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Error: This script must be run with sudo!")
        sys.exit(1)
    main()
