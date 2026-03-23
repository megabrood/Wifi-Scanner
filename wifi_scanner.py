#!/usr/bin/env python3
"""
WiFi / Network Device Scanner v2.1
Clean version for xAI Security Engineer study plan
"""

import os
import sys
import json
from datetime import datetime
from scapy.all import *

KNOWN_DEVICES_FILE = "known_devices.json"

def load_known_devices():
    try:
        with open(KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_known_devices(devices):
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=4)

def get_mac_vendor(mac):
    try:
        import requests
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return r.text.strip() if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def is_monitor_mode(iface):
    try:
        output = os.popen(f"iwconfig {iface} 2>/dev/null").read()
        return "Mode:Monitor" in output
    except:
        return False

def get_best_interface():
    """Smart interface selection - skips lo, prefers monitor mode or wireless"""
    interfaces = get_if_list()
    print(f"[+] Available interfaces: {interfaces}")
    
    # Priority 1: Monitor mode interfaces
    for iface in interfaces:
        if "mon" in iface.lower():
            print(f"[+] Using monitor mode interface: {iface}")
            return iface
    
    # Priority 2: Wireless interfaces (wlan, wlp, etc.)
    for iface in interfaces:
        if iface.lower().startswith(('wlan', 'wlp', 'wl')) and iface != "lo":
            print(f"[+] Using wireless interface: {iface}")
            return iface
    
    # Priority 3: First non-loopback interface
    for iface in interfaces:
        if iface != "lo":
            print(f"[+] Using interface: {iface}")
            return iface
    
    print("[-] No suitable interface found!")
    sys.exit(1)

def passive_wifi_scan(iface, duration=15):
    print(f"[+] Starting passive 802.11 scan on {iface} ({duration}s)...")
    devices = {}
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            mac = None
            if pkt.addr2:
                mac = pkt.addr2
            elif pkt.addr1 and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
                mac = pkt.addr1
            if mac and mac not in devices:
                devices[mac] = {
                    "mac": mac,
                    "vendor": get_mac_vendor(mac),
                    "type": "AP" if pkt.haslayer(Dot11Beacon) else "Client",
                    "timestamp": datetime.now().isoformat()
                }
    
    sniff(iface=iface, prn=packet_handler, timeout=duration, store=False)
    return list(devices.values())

def arp_scan(iface, target="192.168.4.0/22"):
    print(f"[+] Starting ARP scan on {iface} for subnet {target}...")
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
    print("\n" + "="*75)
    print(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*75)
    
    for dev in devices:
        mac = dev.get("mac", "N/A")
        status = "KNOWN" if mac in known_devices else "UNKNOWN ⚠️"
        ip = dev.get("ip", "N/A")
        dev_type = dev.get("type", "Unknown")
        print(f"IP: {ip:18} MAC: {mac}  Vendor: {dev.get('vendor','Unknown')[:35]:35} [{status}] ({dev_type})")
    
    print("="*75)

def main():
    print("🚀 WiFi Device Scanner v2.1 - Security Engineer Project")
    
    iface = get_best_interface()
    print(f"[+] Monitor mode: {is_monitor_mode(iface)}")
    
    known = load_known_devices()
    
    if is_monitor_mode(iface):
        devices = passive_wifi_scan(iface, duration=20)
    else:
        devices = arp_scan(iface, target="192.168.4.0/22")
    
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
        print("[-] Please run with sudo!")
        sys.exit(1)
    main()
