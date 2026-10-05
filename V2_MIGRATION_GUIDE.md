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

Install Npcap with WinPcap compatibility if live packet capture is required. Install the WinDivert driver separately from the official WinDivert distribution. Run the gateway with Administrator privileges because packet capture and WinDivert require elevation.

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
- The WinDivert active-startup message.
- Application events at `/api/admin/application-events`.

On Windows, the successful startup message must include:

```text
[Firewall Enforcer] WinDivert packet-drop enforcement ACTIVE.
```

If WinDivert cannot open, startup fails rather than falling back to log-only detection. This prevents an operator from accidentally running an apparently protected but unenforced gateway.

## 6. Enforcement validation

1. Connect an Android or iPhone to the Windows Mobile Hotspot.
2. Confirm the device receives an address in `192.168.137.0/24`.
3. Start IdentityNet with `--enable-app-filtering` and confirm the WinDivert active message.
4. Open WhatsApp, Instagram, Telegram, Discord, Spotify, or YouTube on the participant device.
5. Query `/api/admin/application-events` and confirm entries contain the participant IP, application, `TLS_SNI` or `DNS_IP_CACHE`, and `DROPPED`.
6. Confirm the application cannot send or receive new content after the drop event.
7. Open an allowed educational/development site such as GitHub. Its packets should be reinjected and the site should remain usable.
8. Repeat after removing the application from `blocked_apps` or its category from `blocked_categories`; restart the gateway and confirm the application is no longer dropped.

The decisive result is `DROPPED` for packets, not merely `BLOCKED` for a DNS decision. A DNS block proves classification; a WinDivert drop proves the packet was not forwarded.

## Detection limitations

V2 does not decrypt HTTPS and does not install software on participants. SNI is unavailable when encrypted ClientHello is used. DNS-IP correlation can be ambiguous for shared CDNs. Applications using QUIC, hard-coded IP addresses, alternate DNS transports, or unrecognized domains require additional policy controls. V2 should therefore be deployed with controlled DNS, WinDivert packet enforcement, and explicit testing of the services relevant to the contest.