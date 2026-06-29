# 🔍 Automated Network Scanning and Vulnerability Assessment Tool

## Overview

The **Automated Network Scanning and Vulnerability Assessment Tool** is a Python-based command-line application development project . The tool automates network reconnaissance and vulnerability assessment by integrating multiple open-source security tools into a single workflow.

The primary objective of the project is to simplify manual security assessments by executing multiple scanners sequentially and storing the results in a structured format.

---

## Features

* Automated host discovery
* Full TCP port scanning
* Service version detection
* Operating System detection
* Nmap NSE script execution
* Web technology fingerprinting using WhatWeb
* Directory enumeration using Gobuster
* SMB enumeration using enum4linux
* Web vulnerability scanning using Nikto
* Timestamped scan output directory
* Automatic HTML report generation
* Command-line interface
* Logging of all scan activities

---

## Project Structure

```text
network-scanning/

├── net.py          # Main scanner
├── report.py       # HTML report generator
├── scan.sh         # Automation script
├── scans/          # Scan outputs
├── reports/        # Generated reports
└── README.md
```

---

## Technologies Used

| Component                 | Technology         |
| ------------------------- | ------------------ |
| Programming Language      | Python 3.13        |
| Operating System          | Kali Linux         |
| Target Machine            | Metasploitable 2   |
| Virtualization            | VMware Workstation |
| Network Scanner           | Nmap               |
| Web Fingerprinting        | WhatWeb            |
| Directory Enumeration     | Gobuster           |
| SMB Enumeration           | enum4linux         |
| Web Vulnerability Scanner | Nikto              |
| Automation                | Python subprocess  |

---

## Prerequisites

Install the required security tools.

```bash
sudo apt update

sudo apt install -y \
nmap \
whatweb \
gobuster \
enum4linux \
nikto
```

---

## Usage

Run the scanner

```bash
python3 net.py -t <TARGET_IP>
```

Example

```bash
python3 net.py -t 192.168.218.129
```

Or use the automation script

```bash
chmod +x scan.sh
./scan.sh
```

---

## Generated Output

The scanner automatically creates a timestamped directory.

Example

```text
scans/

2026-06-29_10-15-25/

host_discovery.xml

ports.xml

services.xml

os.xml

scripts.xml

whatweb.json

gobuster.txt

enum4linux.txt

nikto.txt

scan.log
```

---

## Workflow

```text
Start

↓

Enter Target IP

↓

Host Discovery

↓

Port Scan

↓

Service Detection

↓

OS Detection

↓

NSE Scan

↓

WhatWeb

↓

Gobuster

↓

enum4linux

↓

Nikto

↓

Generate HTML Report

↓

Finish
```

---

## Disclaimer

This tool is intended **only for authorized security testing, educational purposes, and laboratory environments**. Always obtain permission before scanning any network or system.

---

## Author

**Shakthi**



Cybersecurity Enthusiast | Ethical Hacking | Network Security
