# WinDivert Drivers & Binaries

This directory contains the 64-bit Windows packet capture and diversion binaries for **WinDivert 2.2**:

- `WinDivert.dll`: User-mode API library for interacting with the WinDivert kernel driver.
- `WinDivert64.sys`: Signed Windows kernel-mode driver for intercepting and dropping network packets.

## Usage in IdentityNet

- Used by the **Python V2 Application-Aware Firewall Enforcer** (`src/firewall_enforcer.py`) to drop unauthorized network packets on Windows gateways.
- When running with `pydivert`, the Python library bundles these binaries; these standalone files provide a fallback driver source when running on systems without pre-packaged wheels.
- WinDivert requires running the terminal with **Administrator Privileges** (`Run as Administrator`).
