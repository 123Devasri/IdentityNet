# Windows Filtering Platform (WFP) Architecture Guide

IdentityNet uses the **Windows Filtering Platform (WFP)** API (`fwpapi.h` / `fwpapi.lib`) to enforce network-level security rules directly inside the Windows TCP/IP networking stack.

---

## 🏛️ WFP User-Mode Management API vs Kernel Callout Drivers

| Feature / Capability | User-Mode WFP API (`fwpapi.dll`) | Kernel Callout Driver (`.sys`) |
|:---|:---|:---|
| **Execution Context** | User-mode application (Administrator privileges) | Windows Kernel (`KMDF` / `NDIS`) |
| **Actions Supported** | `FWP_ACTION_PERMIT`, `FWP_ACTION_BLOCK`, `FWP_ACTION_CALLOUT` | Deep packet inspection, payload modification, custom injection |
| **Layer Interception** | `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, `FWPM_LAYER_INBOUND_IPPACKET_V4` | Raw packet modification, stream inspection |
| **Deployment Requirement** | Zero driver installation; standard Win32 C executable | Requires test signing or EV driver signing certificate |
| **IdentityNet Usage** | **Used for Gateway Security Enforcement** | Documented for advanced packet-level extensions |

---

## 🔒 Implemented WFP Filters in IdentityNet

1. **Anti-Bypass DNS Protection**:
   - Layer: `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
   - Action: `FWP_ACTION_BLOCK`
   - Condition: `FWPM_CONDITION_IP_REMOTE_PORT == 53`
   - Purpose: Prevents clients on the Mobile Hotspot from specifying manual DNS servers (`8.8.8.8`, `1.1.1.1`) to bypass policy.

2. **Dynamic IP Allowlist Egress Filtering**:
   - Layer: `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
   - Action: `FWP_ACTION_PERMIT`
   - Condition: `FWPM_CONDITION_IP_REMOTE_ADDRESS == <Permitted_IP>`
   - Purpose: Permits outbound connection establishment only to IP destinations explicitly allowed by the DNS policy engine.
