# DNS Spoof Detector

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)

A lightweight DNS spoofing detection tool that monitors network traffic and validates DNS responses against trusted servers.

## Features ✨

- 🕵️ Real-time DNS traffic monitoring
- 🔍 Response validation against multiple trusted DNS servers
- 📝 Alert logging with timestamps
- 🚦 Intelligent caching to minimize false positives
- 🎨 Color-coded console output

## Installation ⚙️

### Prerequisites
- Python 3.6+
- Windows 10/11 (with Admin privileges)
- Npcap (WinPcap-compatible mode)

```bash
# Clone the repository
git clone https://github.com/yourusername/dns-spoof-detector.git
cd dns-spoof-detector

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python dns_spoof_detector.py

[*] Starting DNS monitoring...
[*] DNS Spoof Detector running. Press Ctrl+C to stop.

[ALERT] DNS Spoofing detected!
Domain: example.com 
Suspicious IP: 192.168.1.100
Expected IPs: 93.184.216.34
From: 192.168.1.1

# Trusted DNS servers
trusted_dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

# Log file location
log_file = "dns_spoof_log.txt"