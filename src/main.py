#!/usr/bin/env python3
"""
WiFi Device Scanner - Week 1 Modular Version
For xAI Security Engineer Study Plan
"""

import argparse
import logging
import signal
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scanner import get_best_interface, is_monitor_mode, passive_wifi_scan, arp_scan
from utils.helpers import load_known_devices, save_known_devices


# Setup logging
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_dir = os.path.join(project_root, "logs")
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler(os.path.join(log_dir, "scanner.log")),
		logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def signal_handler(sig, frame):
    logger.info("Scan stopped by user (Ctrl+C)")
    print("\n[!] Scan stopped.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def main():
    parser = argparse.ArgumentParser(description="Modular WiFi Device Scanner")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-m", "--mode", choices=["auto", "arp", "passive"], default="auto")
    parser.add_argument("-d", "--duration", type=int, default=20, help="Passive scan duration in seconds")
    parser.add_argument("--no-vendor", action="store_true", help="Disable MAC vendor lookup")
    args = parser.parse_args()

    logger.info("Starting WiFi Device Scanner v2.4 (Week 1 Modular)")

    iface = args.interface or get_best_interface()
    if not iface:
        logger.error("No valid interface found")
        sys.exit(1)

    known = load_known_devices()
    use_vendor = not args.no_vendor

    if args.mode == "passive" or (args.mode == "auto" and is_monitor_mode(iface)):
        devices = passive_wifi_scan(iface, args.duration, use_vendor)
    else:
        target = "192.168.4.0/22"   # You can change this or keep auto later
        devices = arp_scan(iface, target, use_vendor)

    # Print results
    print("\n" + "="*90)
    print(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*90)
    for dev in devices:
        status = "KNOWN" if dev.get("mac") in known else "UNKNOWN ⚠️"
        ip = dev.get("ip", "N/A")
        print(f"IP: {ip:18}  MAC: {dev.get('mac')}   Vendor: {dev.get('vendor','Unknown')[:40]:40}  [{status}]")
    print("="*90)

    if devices and input("\nAdd unknown devices to known list? (y/n): ").lower() == 'y':
        for dev in devices:
            mac = dev.get("mac")
            if mac and mac not in known:
                known[mac] = dev
        save_known_devices(known)
        logger.info(f"Updated known devices with {len(devices)} entries")

    logger.info("Scan completed successfully")

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("This script must be run with sudo!")
        print("[-] Error: Please run with sudo!")
        sys.exit(1)
    main()
