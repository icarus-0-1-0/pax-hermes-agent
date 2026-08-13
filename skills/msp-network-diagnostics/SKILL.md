---
name: msp-network-diagnostics
description: MSP network troubleshooting. Ping, traceroute, SNMP, DNS, port scan. Read-only diagnostics that bypass quorum.
version: 1.0.0
author: PAX + Hermes Agent
created: 2026-08-13
license: Proprietary (pax-hermes-agent fork)
platforms: [linux]
metadata:
  hermes:
    tags: [msp, network, diagnostics, ping, traceroute, snmp, dns, port-scan]
    category: msp
    requires_toolsets: [msp-tools, terminal]
---

# MSP Network Diagnostics

Troubleshoot client network issues using read-only diagnostic tools. All actions in this skill are non-destructive and **bypass quorum** — they execute directly and are logged to the audit trail.

## When to Use

Use this skill when a ticket involves connectivity, latency, DNS, or reachability:

- "The internet is down."
- "I can't reach the server / website / printer."
- Slow or intermittent connectivity.
- DNS resolution failures.
- A device is unreachable on the network.

## Read-Only Rule

All diagnostics here are read-only. They do not change state on any system, so they **skip the 3-agent quorum**. Execute directly, but always log the action and result to the audit trail.

## Diagnostic Toolkit

### Ping

- Verify host reachability and round-trip latency.
- `ping -c 4 <host>` — check packet loss and RTT.
- Distinguish "host down" from "host unreachable" (network path issue).

### Traceroute

- Map the path to a target and find where it breaks.
- `traceroute <host>` — identify the failing hop.
- Useful for isolating LAN vs WAN vs ISP issues.

### SNMP Queries

- Query network devices (switches, routers, printers, UPS) for status.
- Use the `msp-tools` SNMP tool with the device's community string / credentials.
- Read OIDs for interface status, uptime, CPU, temperature, etc.
- **Read-only** — do not write OIDs (no SET operations).

### DNS Lookups

- Verify name resolution.
- `dig <hostname>` / `nslookup <hostname>` — check A/AAAA/CNAME records.
- Check the client's configured DNS servers and forwarders.
- Confirm the record matches the expected IP.

### Port Scanning

- Verify a service is listening and reachable.
- `nc -zv <host> <port>` or `nmap -p <port> <host>` — check open ports.
- Confirm the expected service port is open on the target.
- **Scope to the target** — do not scan broad ranges or unrelated hosts.

## Pitfalls

- **Stay read-only** — never issue SNMP SET, config writes, or state changes from diagnostics.
- **Scope port scans** to the specific host/port in the ticket; broad scans are noisy and may trip client security.
- **Respect tenant network boundaries** — only touch your tenant's client networks.
- **Do not send raw credentials or PHI to cloud models.**
- **Correlate results** — a single failed ping is not a diagnosis; combine ping, traceroute, and DNS.
- **Log everything** to the audit trail even though quorum is bypassed.

## Verification

- Diagnostic commands returned clear, interpretable results.
- Root cause isolated (host down, path break, DNS failure, port closed).
- Findings recorded in the ticket.
- Audit trail contains the diagnostic actions and results.
