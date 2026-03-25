#!/usr/bin/env python3
"""
WiFi Device Scanner - Week 2 Version
Added SIEM export + Alerting for xAI Detection & Response practice
"""

import argparse
import logging
import signal
import sys
import os
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.scanner import get_best_interface, is_monitor_mode, passive_wifi_scan, arp_scan
from utils.helpers import (
    load_known_devices, 
    save_known_devices, 
    save_scan_results,
    generate_alert
)

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
    print("\n[!] Scan stopped by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def main():
    parser = argparse.ArgumentParser(description="WiFi Device Scanner with SIEM Export & Alerting")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-m", "--mode", choices=["auto", "arp", "passive"], default="auto")
    parser.add_argument("-d", "--duration", type=int, default=20, help="Passive scan duration")
    parser.add_argument("--no-vendor", action="store_true", help="Disable MAC vendor lookup")
    parser.add_argument("--alert", action="store_true", help="Enable alert generation for unknown devices")
    args = parser.parse_args()

    logger.info("Starting WiFi Device Scanner - Week 2 (SIEM + Alerting)")

    iface = args.interface or get_best_interface()
    if not iface:
        logger.error("No valid interface found")
        sys.exit(1)

    known = load_known_devices()
    use_vendor = not args.no_vendor

    # Run the scan
    if args.mode == "passive" or (args.mode == "auto" and is_monitor_mode(iface)):
        devices = passive_wifi_scan(iface, args.duration, use_vendor)
    else:
        target = "192.168.4.0/22"   # Your home subnet
        devices = arp_scan(iface, target, use_vendor)

    # Print results
    print("\n" + "="*90)
    print(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*90)
    
    new_devices = []
    for dev in devices:
        mac = dev.get("mac")
        status = "KNOWN" if mac in known else "UNKNOWN ⚠️"
        ip = dev.get("ip", "N/A")
        print(f"IP: {ip:18}  MAC: {mac}   Vendor: {dev.get('vendor','Unknown')[:40]:40}  [{status}]")
        
        if mac and mac not in known:
            new_devices.append(dev)

    print("="*90)

    # Save results for Wazuh
    save_scan_results(devices, scan_type=args.mode)

    # Generate alerts if requested
    if args.alert and new_devices:
        generate_alert(new_devices)

    # Optional: Update known devices
    if new_devices and input("\nAdd unknown devices to known list? (y/n): ").lower() == 'y':
        for dev in new_devices:
            known[dev.get("mac")] = dev
        save_known_devices(known)
        logger.info(f"Added {len(new_devices)} new known devices")

    logger.info("Scan completed successfully")

if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("This script must be run with sudo!")
        print("[-] Error: Please run with sudo!")
        sys.exit(1)
    main()
