# WiFi Device Scanner

A lightweight Python network scanner using **Scapy** for home lab security monitoring and detection engineering practice.

## Features

- Automatic WiFi/Ethernet interface detection
- Passive and active device discovery (MAC addresses + vendor OUI lookups)
- Known vs Unknown device tracking
- Local Ollama integration for smart alert analysis
- Ready for SIEM export (Wazuh / Elastic)

# Purpose

Built as part of my Security Engineer - Detection & Response preparation (targeting roles like xAI)

# How to Run

sudo apt install python3-scapy aircrack-ng -y

pip install scapy requests # for vendor lookup if needed
