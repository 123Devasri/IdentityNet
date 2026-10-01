# IdentityNet: Windows Network-Level Access Control & Policy System

**IdentityNet** is a zero-client, Windows-native network access control system and contest/examination gateway server implemented in **C/C++ using Win32 Networking APIs** (`Winsock2`, `IP Helper API`, `Windows Filtering Platform / WFP`).

It turns a Windows 10/11 laptop into a secure network gateway servicing standard participant devices (Windows laptops, phones, tablets) connected via **Windows Mobile Hotspot**.

---

## 🌐 1. System Architecture & Network Topology

```text
                         INTERNET
                            │
                            │ (Upstream Interface: Wi-Fi / Ethernet)
                    ┌───────┴──────────────────────────────┐
                    │    Windows Host Laptop (Gateway)     │
                    │                                      │
                    │  [ Control Plane - C Win32 Engine ]  │
                    │   • Embedded C HTTP Server (Port 80) │
                    │   • Participant Session & MAC Map    │
                    │   • Admin Control Dashboard UI       │
                    │   • Policy Engine & Reload Mechanism │
                    │   • Domain-to-IP Cache Table         │
                    │                                      │
                    │  [ Data Plane - Windows Networking ] │
                    │   • Windows Mobile Hotspot / ICS     │
                    │   • Winsock UDP/TCP DNS (Port 53)    │
                    │   • WFP Filters (fwpapi.h)           │
                    │   • Anti-Bypass DNS Protection       │
                    │   • Default-Deny Egress Filtering    │
                    └───────┬──────────────────────────────┘
                            │ (Hotspot Interface: 192.168.137.1)
                            │
                 Windows Mobile Hotspot Network
                        192.168.137.0/24
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
   Windows Laptop 1  Windows Laptop 2   Windows Laptop 3
   192.168.137.10    192.168.137.11    192.168.137.12
   Participant P001  Participant P002  Participant P003
```

---

## ⚡ 2. Separation of Control Plane & Data Plane

IdentityNet cleanly separates the **Control Plane** (Web Server, Auth, UI, Policy Editor) from the **Data Plane** (Windows Mobile Hotspot NAT/ICS, Winsock DNS Filter, WFP Filtering):

### 🧠 Control Plane (User-Mode C)
- **APIs**: Winsock2 C Sockets + Win32 Threads + IP Helper API
- **Responsibilities**:
  - Serves participant login portal (`http://contest.identitynet.local/login`).
  - Tracks active sessions (Participant ID, IP address, MAC address via `SendARP()`, login time).
  - Hosts the contest workspace (`/contest`, `/questions`, `/submit`).
  - Serves the Admin Dashboard (`/admin`).
  - Manages domain allowlist and Domain-to-IP Cache Table.

### 🛡️ Data Plane (Windows Network Stack & WFP)
- **APIs**: Windows Filtering Platform (`fwpuclnt.dll` / `fwpapi.h`), Winsock UDP/TCP 53.
- **Responsibilities**:
  - **Anti-Bypass DNS Protection**: Adds WFP filter on layer `FWPM_LAYER_ALE_AUTH_CONNECT_V4` to block/redirect client DNS queries (UDP port 53) to external DNS servers (`8.8.8.8`, `1.1.1.1`).
  - **DNS Policy Filtering**: Resolves `contest.identitynet.local` -> `192.168.137.1`. For allowed external domains (`github.com`, `docs.python.org`), performs upstream DNS resolution and caches destination IPs. For unauthorized domains (`google.com`, `chatgpt.com`), returns `0.0.0.0` and logs `BLOCK` events.
  - **WFP Destination IP Permitting**: Adds dynamic WFP permit filters (`FWPM_ACTION_PERMIT`) for IP destinations associated with allowed domains.

---

## 🔒 3. Default-Deny Allowlist Policy Model

IdentityNet enforces a strict **Default-Deny Model**:

```json
{
  "profile": "contest-2026",
  "default_action": "DENY",
  "allowed_domains": [
    "contest.identitynet.local",
    "exam.identitynet.local",
    "github.com",
    "*.github.com",
    "docs.python.org"
  ]
}
```

### Policy Decision Matrix:

| Destination Requested | Gateway Verdict | Resulting Network Action |
|:---|:---:|:---|
| `contest.identitynet.local` | **ALLOWED** | Resolves to Gateway IP `192.168.137.1`. Served locally by C HTTP server. |
| `github.com` | **ALLOWED** | Upstream DNS resolved. WFP permits destination IP. Traffic forwarded to Internet. |
| `docs.python.org` | **ALLOWED** | Upstream DNS resolved. WFP permits destination IP. Traffic forwarded to Internet. |
| `google.com` | **BLOCKED** | DNS returns `0.0.0.0`. WFP drops outbound connection attempts. Logged in Admin Dashboard. |
| `chatgpt.com` | **BLOCKED** | DNS returns `0.0.0.0`. WFP drops connection. Event logged. |

---

## 🔬 4. Computer Networking Concepts Demonstrated

IdentityNet practically demonstrates 21 core networking concepts:

| # | Networking Concept | IdentityNet C Implementation | Demonstration Method |
|:---:|:---|:---|:---|
| 1 | **Wi-Fi / Hotspot** | Windows Mobile Hotspot adapter (`192.168.137.1`). | `GetAdaptersAddresses()` |
| 2 | **IP Addressing** | Hotspot IPv4 addressing (`192.168.137.0/24`). | `ipconfig /all` |
| 3 | **DHCP** | Windows ICS / Mobile Hotspot DHCP server. | `ipconfig /renew` |
| 4 | **MAC Addresses** | Client MAC discovery using IP Helper API (`SendARP()`). | `clients.c` / Admin Dashboard |
| 5 | **ARP (Layer 2)** | Gateway MAC resolution for hotspot clients. | `arp -a` |
| 6 | **Routing & Gateway** | Windows IP routing and default gateway (`192.168.137.1`). | `route print` / `Get-NetRoute` |
| 7 | **NAT / ICS** | Windows Internet Connection Sharing masquerading. | `netsh wlan show hostednetwork` |
| 8 | **DNS Filter** | C Winsock UDP/TCP port 53 resolver & policy filter. | `nslookup contest.identitynet.local` |
| 9 | **UDP (Layer 4)** | Connectionless DNS packet handling on port 53. | `dns_server.c` |
| 10 | **TCP (Layer 4)** | Reliable Winsock TCP sockets for C HTTP contest server. | `contest_server.c` / `netstat -ano` |
| 11 | **Firewall (WFP)** | Windows Filtering Platform (`fwpuclnt.dll` / `fwpapi.h`). | `wfp_manager.c` |
| 12 | **Stateful Filtering** | WFP connection-aware layer `FWPM_LAYER_ALE_AUTH_CONNECT_V4`. | WFP filter rules |
| 13 | **Anti-Bypass DNS** | WFP block filter for external port 53 (`8.8.8.8`). | `nslookup google.com 8.8.8.8` |
| 14 | **Application Layer** | Embedded C HTTP server handling contest application. | `http://192.168.137.1/login` |
| 15 | **HTTP** | C Web server serving HTML/CSS/JS frontend files. | `contest_server.c` |
| 16 | **HTTPS Limitations** | DNS policy + WFP IP filter enforcing default-deny without MITM. | Documentation & WFP log |
| 17 | **Authentication** | Participant ID & password authentication (`clients.c`). | `/login` form |
| 18 | **Logging** | Thread-safe C event log file (`logs/traffic.log`). | `logger.c` |
| 19 | **Allowlist Policy** | Domain pattern matcher (`policy.c`). | `config/policy.json` |
| 20 | **Client-Server Model** | Win32 socket multi-threaded client request processing. | `contest_server.c` |
| 21 | **Network Discovery** | Dynamic interface discovery via `GetAdaptersAddresses()`. | `network.c` |

---

## 🛠️ 5. Build & Compilation Guide

### Requirements:
- **OS**: Windows 10 / Windows 11
- **Compiler**: MinGW GCC 14+ (`gcc.exe`) or MSVC (`cl.exe` / Visual Studio)

### Build with MinGW GCC:
```cmd
build.bat
```

### Run Binary:
```cmd
bin\IdentityNet.exe 80
```
