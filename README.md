# IdentityNet

> **Zero-client, network-level access control and examination gateway server for Windows and Linux.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![C Standard](https://img.shields.io/badge/C-C11-orange.svg)]()

---

## 📌 Overview

**IdentityNet** transforms a standard host laptop or server into a secure, policy-enforcing network gateway for exams, hackathons, and restricted testing environments.

- **Zero-Client Installation**: Participants connect to a Wi-Fi hotspot (e.g. Windows Mobile Hotspot) with no agent, browser extension, or client software installed on their devices.
- **Default-Deny Security**: All outbound Internet traffic is blocked by default; only explicitly allowed domains and exam workspaces are accessible.
- **Dual-Engine Architecture**: Includes a high-performance **native C/Win32 gateway** (using WFP & Winsock) and an **application-aware Python engine** (using FastAPI, Scapy, and WinDivert).

---

## 🏗️ Architecture

```text
                     INTERNET (Upstream Wi-Fi / Ethernet)
                                      ▲
                                      │
              ┌───────────────────────┴───────────────────────┐
              │             IDENTITYNET GATEWAY HOST          │
              │                                               │
              │  [ Control Plane ]                            │
              │   • Admin Control Dashboard UI                │
              │   • Participant Portal & Auth (/login)        │
              │   • Policy Engine (config/policy.json)        │
              │   • SQLite Audit & Event Logging              │
              │                                               │
              │  [ Data Plane ]                               │
              │   • DNS Policy Filter (Port 53 UDP/TCP)       │
              │   • Anti-Bypass DNS Protection (Blocks 8.8.8.8)│
              │   • TLS SNI Application Classifier (V2)       │
              │   • WFP / WinDivert Dynamic Packet Filter     │
              └───────────────────────┬───────────────────────┘
                                      │
              Hotspot Subnet (192.168.137.0/24 / Gateway: .1)
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
          Participant 1        Participant 2        Participant 3
         (192.168.137.10)     (192.168.137.11)     (192.168.137.12)
```

---

## ✨ Key Features

- **🛡️ Strict Default-Deny Allowlisting**: Only specified resources (e.g. contest portal, official documentation) resolve; all other destinations return `0.0.0.0` or get dropped.
- **📱 Application-Aware Classification (V2)**: Identifies and restricts desktop & mobile applications (Discord, WhatsApp, Telegram, Spotify, social media) using DNS and TLS ClientHello SNI inspection without MITM decryption.
- **🔒 Anti-Bypass DNS Enforcement**: Blocks or redirects rogue outbound DNS requests (e.g. queries directed to `8.8.8.8` or `1.1.1.1`) to prevent bypass attempts.
- **👤 Device & Session Tracking**: Discovers connected participant MAC addresses via ARP (`SendARP`) and correlates active IP leases with participant authentication.
- **📊 Real-Time Admin Dashboard**: Live web interface to view connected devices, monitor real-time traffic events, manage participants, and update policies on the fly.
- **🧪 Multi-Platform Deployment**: Runs natively on Windows 10/11 using WFP/WinDivert, or on Linux using nftables/iptables.

---

## 📁 Repository Structure

```text
IdentityNet/
├── config/                 # Policy, application signatures, and user profiles
│   ├── application_signatures.json  # Wildcard signatures for app classification
│   ├── policy.json                  # Active security profile & allowed domains
│   └── users.json                   # Participant accounts and role mappings
├── docs/                   # Detailed documentation and reference guides
│   ├── SETUP_GUIDE.md               # Step-by-step Windows hotspot & hardware setup
│   ├── V2_MIGRATION_GUIDE.md        # V1 to V2 application-filtering migration
│   └── NETWORKING_CONCEPTS.md       # 21 networking concepts demonstrated
├── drivers/                # WinDivert 64-bit kernel driver and user-mode DLL
├── src/                    # Gateway source code
│   ├── main.py             # Python gateway entry point
│   ├── server.py           # FastAPI web portal and admin REST endpoints
│   ├── app_classifier.py   # Multi-signal application classification engine
│   ├── policy_engine.py    # Allowlist/blocklist policy evaluation
│   ├── dns_server.py       # Custom DNS server with policy enforcement
│   ├── firewall_enforcer.py# Dynamic packet dropping via WinDivert / nftables
│   ├── database.py         # SQLite database models and audit storage
│   ├── main.c              # Native C gateway entry point
│   ├── dns_server.c        # Native Winsock DNS server
│   ├── contest_server.c    # Native embedded C HTTP server
│   └── network.c           # Win32 network adapter discovery (IP Helper API)
├── templates/              # Jinja2 HTML templates (Admin, Login, Contest UI)
├── static/                 # CSS stylesheets and client JavaScript
├── web/                    # Static assets served by native C server
├── wfp/                    # Windows Filtering Platform (WFP) C implementation
├── test/                   # Automated test suite and client simulators
│   ├── run_all_tests.py    # Test runner for core policy scenarios
│   ├── test_gateway.py     # Gateway integration unit tests
│   ├── test_dns.py         # DNS resolution unit tests
│   └── test_v2.py          # Application classification unit tests
├── build.bat               # Compiles C gateway using MinGW GCC
├── run.bat                 # Launches Python gateway in local test mode
├── setup.sh                # Linux installation script
├── start.sh                # Linux launch script
├── CMakeLists.txt          # CMake build configuration for C gateway
├── requirements.txt        # Python package dependencies
├── LICENSE                 # MIT License
└── README.md
```

---

## 🚀 Quick Start

### Option 1: Python Gateway (Application-Aware V2)

Recommended for testing, development, and application classification.

#### 1. Setup Environment
```bash
# Clone the repository
git clone https://github.com/M-DhanyaShree/IdentityNet.git
cd IdentityNet

# Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 2. Run in Local Dry-Run Mode
Test the web interface, policy engine, and database locally without modifying system firewall rules:
```bash
# Windows
run.bat
# or directly:
python src/main.py --dry-run --gateway-ip 127.0.0.1 --port 8080
```

#### 3. Access the Portals
- **Participant Login**: `http://127.0.0.1:8080/login`
- **Admin Dashboard**: `http://127.0.0.1:8080/admin` (Default: `admin` / `admin123`)

---

### Option 2: Native Windows C Gateway (WFP Native V1)

For zero-overhead native execution directly on Windows using Winsock2 and the Windows Filtering Platform:

#### 1. Compile with MinGW GCC
```cmd
build.bat
```
This produces `bin\IdentityNet.exe`.

#### 2. Run as Administrator
Open **Command Prompt as Administrator** and launch:
```cmd
bin\IdentityNet.exe 80
```

> For complete instructions on configuring the Windows Mobile Hotspot adapter and connecting physical participant devices, refer to [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md).

---

## ⚙️ Configuration

Security rules are managed in `config/`:

### 1. `config/policy.json`
Defines active profiles, allowed domains, and blocked categories:
```json
{
  "active_profile": "contest-2026",
  "blocked_categories": ["Messaging", "SocialMedia", "Streaming"],
  "blocked_apps": ["Discord"],
  "profiles": {
    "contest-2026": {
      "allowed": [
        "contest.identitynet.local",
        "github.com",
        "*.github.com",
        "docs.python.org"
      ]
    }
  }
}
```

### 2. `config/application_signatures.json`
Maps domain patterns to application identities (e.g. WhatsApp, Discord, YouTube, Telegram):
```json
{
  "Discord": {
    "category": "Messaging",
    "domains": ["discord.com", "*.discord.com", "discord.gg", "*.discordapp.com"]
  }
}
```

---

## 🧪 Testing

IdentityNet includes an automated test suite verifying policy evaluation, domain allowlisting, and application classification:

```bash
# Run the core 4-scenario validation suite
python test/run_all_tests.py

# Run gateway integration tests
python test/test_gateway.py

# Run DNS filtering tests
python test/test_dns.py

# Run V2 application classifier tests
python test/test_v2.py
```

---

## 📚 Further Reading

- [Complete Hardware & Hotspot Setup Guide](docs/SETUP_GUIDE.md)
- [V1 to V2 Application-Aware Migration Guide](docs/V2_MIGRATION_GUIDE.md)
- [21 Networking Concepts Demonstrated](docs/NETWORKING_CONCEPTS.md)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
