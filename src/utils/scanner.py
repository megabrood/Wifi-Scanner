import os
from scapy.all import *
import netifaces
from datetime import datetime

def is_monitor_mode(iface):
    try:
        output = os.popen(f"iwconfig {iface} 2>/dev/null").read()
        return "Mode:Monitor" in output
    except:
        return False

def get_best_interface():
    interfaces = get_if_list()
    print(f"[+] Available interfaces: {interfaces}")

    for iface in interfaces:
        if "mon" in iface.lower():
            print(f"[+] Using monitor-mode interface: {iface}")
            return iface
    for iface in interfaces:
        if iface.lower().startswith(('wlan', 'wlp', 'wl')) and iface != "lo":
            print(f"[+] Using wireless interface: {iface}")
            return iface
    for iface in interfaces:
        if iface != "lo":
            print(f"[+] Using interface: {iface}")
            return iface

    print("[-] No suitable interface found!")
    return None

def get_subnet(iface):
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            subnet = ip.rsplit('.', 1)[0] + ".0/24"
            print(f"[+] Auto-detected subnet: {subnet}")
            return subnet
    except:
        pass
    return "192.168.0.0/24"

def passive_wifi_scan(iface, duration, use_vendor=True):
    print(f"[+] Starting passive 802.11 scan on {iface} for {duration} seconds...")
    devices = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            mac = pkt.addr2 or (pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else None)
            if mac and mac not in devices:
                vendor = get_mac_vendor(mac) if use_vendor else "Unknown"
                devices[mac] = {
                    "mac": mac,
                    "vendor": vendor,
                    "type": "AP" if pkt.haslayer(Dot11Beacon) else "Client",
                    "timestamp": datetime.now().isoformat()
                }

    sniff(iface=iface, prn=packet_handler, timeout=duration, store=False)
    return list(devices.values())

def arp_scan(iface, target, use_vendor=True):
    print(f"[+] Starting ARP scan on {iface} for {target}...")
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, iface=iface, timeout=6, verbose=False)[0]

    devices = []
    for _, received in result:
        vendor = get_mac_vendor(received.hwsrc) if use_vendor else "Unknown"
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": vendor,
            "type": "Device"
        })
    return devices
