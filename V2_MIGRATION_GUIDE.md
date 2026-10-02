# IdentityNet V1 to V2 Migration Guide

## What changes

V2 keeps the existing domain allowlist, participant login, SQLite database, DNS filtering, and administrator API. It adds application signatures, TLS SNI inspection, DNS-IP correlation, application policy decisions, application-event logging, and dynamic destination blocking.

## 1. Install dependencies

From the project root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Install Npcap with WinPcap compatibility if live packet capture is required. Run the gateway with Administrator privileges because packet capture and Windows Firewall rule changes may require elevation.

## 2. Preserve the V1 policy

Keep the existing domain allowlist under `profiles`. Add V2 controls at the top level or inside each profile:

```json
{
  "blocked_categories": ["Messaging", "SocialMedia", "Streaming"],
  "blocked_apps": ["Discord"]
}
```

Category blocking applies to every application in that category. `blocked_apps` can be used for individual exceptions or additional application blocks.

## 3. Review signatures

Edit `config/application_signatures.json` to add or remove domains. Each application has a name, category, and wildcard domain list. Use both the base domain and wildcard form when both should match.

## 4. Start V2

```powershell
$env:IDENTITYNET_ADMIN_PASSWORD = "choose-a-strong-password"
python src\main.py `
  --gateway-ip 192.168.137.1 `
  --subnet 192.168.137.0/24 `
  --port 8080 `
  --enable-app-filtering `
  --capture-interface "Wi-Fi"
```

Use the actual adapter carrying hotspot traffic for `--capture-interface`. Verify it with:

```powershell
Get-NetAdapter
```

## 5. Verify operation

Check:

- Existing allowed and blocked domain behavior.
- DNS resolutions for application domains.
- TLS SNI events in the application-event API.
- Windows Firewall rules beginning with `IdentityNet-V2-`.
- Application events at `/api/admin/application-events`.

## Detection limitations

V2 does not decrypt HTTPS and does not install software on participants. SNI is unavailable when encrypted ClientHello is used. DNS-IP correlation can be ambiguous for shared CDNs. Applications using QUIC, hard-coded IP addresses, alternate DNS transports, or unrecognized domains require additional policy controls. V2 should therefore be deployed with controlled DNS, forwarding enforcement, and explicit testing of the services relevant to the contest.