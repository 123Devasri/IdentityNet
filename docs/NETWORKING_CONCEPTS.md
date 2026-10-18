# Computer Networking Concepts in IdentityNet

IdentityNet serves as a comprehensive, hands-on implementation demonstrating 21 core computer networking concepts across the OSI model:

| # | Networking Concept | Layer | IdentityNet Implementation | Verification Method |
|:---:|:---|:---:|:---|:---|
| 1 | **Wi-Fi / Hotspot** | Layer 1/2 | Windows Mobile Hotspot adapter (`192.168.137.1`). | `GetAdaptersAddresses()` |
| 2 | **IPv4 Addressing** | Layer 3 | Hotspot subnet addressing (`192.168.137.0/24`). | `ipconfig /all` |
| 3 | **DHCP Server** | Layer 7 / Network Setup | Windows ICS / Mobile Hotspot DHCP server assigning client IPs. | `ipconfig /renew` |
| 4 | **MAC Addresses** | Layer 2 | Client hardware discovery via IP Helper API (`SendARP()`). | `clients.c` / Admin Dashboard |
| 5 | **ARP Protocol** | Layer 2 | Hotspot gateway MAC address resolution for participants. | `arp -a` |
| 6 | **Default Gateway** | Layer 3 | Windows IP routing and gateway host forwarding (`192.168.137.1`). | `route print` / `Get-NetRoute` |
| 7 | **NAT / ICS** | Layer 3 | Network Address Translation & Windows Internet Connection Sharing. | Hotspot adapter properties |
| 8 | **DNS Filtering** | Layer 7 | Custom DNS resolver intercepting UDP/TCP port 53 with policy enforcement. | `nslookup contest.identitynet.local` |
| 9 | **UDP Sockets** | Layer 4 | Connectionless DNS packet reception and synthesized response generation. | `dns_server.c` / `dns_server.py` |
| 10 | **TCP Sockets** | Layer 4 | Reliable multi-threaded HTTP contest and admin portal server. | `contest_server.c` / `server.py` |
| 11 | **Firewall (WFP / WinDivert)** | Layer 3/4 | Windows Filtering Platform (`fwpapi.h`) and WinDivert packet filter. | `wfp_manager.c` / `firewall_enforcer.py` |
| 12 | **Stateful Inspection** | Layer 4 | Dynamic flow tracking on `FWPM_LAYER_ALE_AUTH_CONNECT_V4`. | WFP filter table |
| 13 | **Anti-Bypass Protection** | Layer 3/4 | Blocking external DNS queries (e.g. `8.8.8.8:53`) to prevent DNS hijacking. | `nslookup google.com 8.8.8.8` |
| 14 | **Application Classification** | Layer 7 | Pattern matching on DNS lookups, TLS SNI headers, and cached IPs. | `app_classifier.py` / Admin API |
| 15 | **HTTP Server** | Layer 7 | Lightweight embedded HTTP server serving participant portal and admin UI. | `http://192.168.137.1:80` |
| 16 | **TLS SNI Inspection** | Layer 7 | Parsing TLS ClientHello SNI without decrypting encrypted payloads. | `tls_sni_inspector.py` |
| 17 | **Session Authentication** | Application | Participant ID & password authentication tied to IP and MAC identity. | `/login` form |
| 18 | **Audit Logging** | Application | Thread-safe structured event logging and SQLite database storage. | `logs/traffic.log` / `database.py` |
| 19 | **Default-Deny Policy** | Security | Strict allowlist model dropping all non-whitelisted domain requests. | `config/policy.json` |
| 20 | **Client-Server Architecture**| Architecture | Multi-threaded client handling with decoupled control and data planes. | `contest_server.c` |
| 21 | **Network Interface Discovery**| System | Automatic enumeration of UP/DOWN interfaces and gateways via Win32. | `network.c` |
