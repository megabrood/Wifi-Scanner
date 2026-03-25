# WiFi Device Scanner

A clean, beginner-friendly network scanner built with **scapy** for home-lab security monitoring
and detection engineering practice

**Perfect for learning Python Automation** 

## Features

- Automatic interface detection (skips loopback)
- **Two scanning modes**: ARP (active) + 802.11 passive (monitor mode)
- Known vs unknow device tracking (local JSON - NEVER UPLOAD)
- Optional MAC vendor lookup
- Full 'argparse' support for easy command-line use

# Purpose

Built as part of my Security Engineer - Detection & Response preparation

# How to Run

sudo apt install python3-scapy aircrack-ng -y

pip install scapy requests # for vendor lookup if needed

cd src

sudo python3 main.py --mode passive
