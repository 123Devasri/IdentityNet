# Complete Setup & Testing Guide - Windows IdentityNet Gateway

This guide details the complete build, configuration, deployment, and testing procedure for **IdentityNet Windows Gateway** on **Windows 10/11**.

---

## 📌 Prerequisites & Build Setup

### System Requirements:
- **Host OS**: Windows 10 or Windows 11 (Host machine creating Mobile Hotspot)
- **Compiler**: MinGW GCC (`gcc.exe`) or Visual Studio MSVC (`cl.exe`)
- **Libraries**: Winsock2 (`ws2_32.lib`), IP Helper API (`iphlpapi.lib`), WFP (`fwpuclnt.dll`)

### Step 1: Compiling the C Gateway Binary
Open Command Prompt (`cmd.exe`) inside the `IdentityNet` project directory and execute:

```cmd
build.bat
```

This compiles all C modules into `bin\IdentityNet.exe`.

---

## 📡 Step 2: Enabling Windows Mobile Hotspot

1. Open **Windows Settings** (`Win + I`) -> **Network & internet** -> **Mobile hotspot**.
2. Select your active Internet connection (e.g. Wi-Fi or Ethernet) under **Share my internet connection from**.
3. Toggle **Mobile hotspot** to **On**.
4. Windows will create a virtual hotspot adapter (typically assigned IP `192.168.137.1` and subnet `192.168.137.0/24`).

---

## ⚡ Step 3: Launching IdentityNet Gateway Server

For a local Python control-plane test, create a virtual environment, install `requirements.txt`, set an administrator password, and run:

```cmd
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
set IDENTITYNET_ADMIN_PASSWORD=choose-a-strong-password
python src\main.py --dry-run --gateway-ip 127.0.0.1 --port 8080
```

Use `http://127.0.0.1:8080/login` for the participant UI. The admin UI uses HTTP Basic authentication with username `admin` and the password in `IDENTITYNET_ADMIN_PASSWORD`.

For the native Windows gateway, which uses Mobile Hotspot and WFP, open **Command Prompt as Administrator** and launch:

```cmd
bin\IdentityNet.exe 80
```

### What IdentityNet automatically does at startup:
1. **Discovers Topology**: Scans network adapters using `GetAdaptersAddresses()`, displaying Upstream interface and Hotspot interface (`192.168.137.1`).
2. **Initializes Policy**: Loads `config/policy.json` (Profile: `contest-2026`).
3. **Initializes WFP**: Opens Windows Filtering Platform engine (`FwpmEngineOpen0`) and configures Anti-Bypass DNS Protection Filter.
4. **Starts C DNS Server**: Binds UDP socket to `0.0.0.0:53`.
5. **Starts Embedded C HTTP Server**: Binds Winsock TCP socket to `0.0.0.0:80`.

---

## 💻 Step 4: Connecting Participant Windows Devices

Connect 3 Windows participant laptops (or phones/tablets) to the **IdentityNet Mobile Hotspot**:

- **Gateway IP**: `192.168.137.1`
- **Participant 1 (P001)**: Assigned IP `192.168.137.10` via Windows DHCP
- **Participant 2 (P002)**: Assigned IP `192.168.137.11` via Windows DHCP
- **Participant 3 (P003)**: Assigned IP `192.168.137.12` via Windows DHCP

> **Note**: Participants do **NOT** install any software on their laptops.

---

## 🧪 Step 5: Multi-Device Test Protocol

### Test 1: Contest Server Access & Authentication
1. On Participant 1 (`192.168.137.10`), open Edge/Chrome browser.
2. Go to: `http://contest.identitynet.local` (or `http://192.168.137.1`).
3. **EXPECTED VERDICT**: **ALLOWED** (Participant Login Page renders cleanly).
4. Enter Credentials:
   - **Participant ID**: `P001`
   - **Password**: `pass123`
5. Click **AUTHENTICATE SESSION**.
6. **EXPECTED VERDICT**: Authenticated session created. Redirects to `/contest` workspace.

### Test 2: Admin Dashboard Verification
1. On Host Gateway machine, open browser: `http://192.168.137.1/admin` (or `http://127.0.0.1/admin`).
2. Observe **CONNECTED PARTICIPANTS** table:
   - Shows `P001` | `Alice Johnson` | `192.168.137.10` | MAC Address (`XX-XX-XX-XX-XX-XX`) | `ONLINE`.

### Test 3: Unauthorized Domain Blocking (Default-Deny Policy)
1. On Participant 1 (`192.168.137.10`), attempt to open:
   - `https://google.com`
   - `https://youtube.com`
   - `https://chatgpt.com`
2. **EXPECTED VERDICT**: **BLOCKED** (Browser connection fails / `ERR_NAME_NOT_RESOLVED`).
3. Check `logs/traffic.log` or Admin Console output:
   - `[P001] 192.168.137.10 -> google.com [DNS:53] => BLOCK (Default-deny policy enforced)`

### Test 4: Anti-Bypass DNS Protection Test
1. On Participant 2 (`192.168.137.11`), manually configure IPv4 DNS settings to static `8.8.8.8` (Google Public DNS).
2. Open Command Prompt and run: `nslookup chatgpt.com`
3. **EXPECTED VERDICT**: **BLOCKED / CONTROLLED** (WFP filter blocks direct port 53 traffic to `8.8.8.8`, enforcing DNS policy).

### Test 5: Dynamic Allowlist Policy Modification
1. On Admin Dashboard (`http://192.168.137.1/admin`), type `github.com` into the policy list.
2. On Participant 3 (`192.168.137.12`), open `https://github.com`.
3. **EXPECTED VERDICT**: **ALLOWED** (Access immediately granted without restarting the C server!).

---

## 🔬 Step 6: Diagnostic Demonstration Commands

Demonstrate networking concepts using standard Windows terminal tools:

| Command | Concept Demonstrated | What It Shows |
|:---|:---|:---|
| `ipconfig /all` | IPv4, Subnet, DHCP, Default Gateway | Participant IP `192.168.137.10`, Gateway `192.168.137.1`, Subnet `255.255.255.0`. |
| `arp -a` | Layer 2 MAC Address Resolution | Maps Gateway IP `192.168.137.1` to Gateway Network Card MAC address. |
| `ping 192.168.137.1` | ICMP, Layer 3 Connectivity | RTT latency and packet loss between Participant and Gateway. |
| `nslookup contest.identitynet.local` | DNS A Record Resolution | Resolves contest domain to Gateway IP `192.168.137.1`. |
| `nslookup google.com` | DNS Policy Blocking | Resolves unauthorized domain to `0.0.0.0` under default-deny policy. |
| `tracert github.com` | Layer 3 IP Routing Hop Path | Hop 1 is Gateway `192.168.137.1`, Hop 2+ is WAN ISP routing. |
| `netstat -ano` | Layer 4 TCP/UDP Sockets | Active TCP connections on port 80 and UDP socket listening on port 53. |
| `route print` | Windows Routing Table | Default route `0.0.0.0` pointing to Gateway `192.168.137.1`. |
| `Get-NetAdapter` | PowerShell Adapter Query | Lists physical Wi-Fi and virtual Hotspot adapter state. |
