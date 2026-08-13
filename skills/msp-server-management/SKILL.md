---
name: msp-server-management
description: MSP server administration via SSH. Service restarts, disk checks, log analysis, process inspection. Destructive actions require quorum.
version: 1.0.0
author: PAX + Hermes Agent
created: 2026-08-13
license: Proprietary (pax-hermes-agent fork)
platforms: [linux]
metadata:
  hermes:
    tags: [msp, server, ssh, systemd, disk, logs, processes]
    category: msp
    requires_toolsets: [msp-tools, terminal]
---

# MSP Server Administration

Manage client servers over SSH. Covers service restarts, disk space checks, log analysis, and process inspection. Read-only inspection executes directly; destructive actions (restarts, config changes) require the 3-agent quorum + human confirmation.

## When to Use

Use this skill when a ticket involves a server:

- A service is down or misbehaving.
- Disk space is full or low.
- An application is slow or erroring.
- A process is consuming excessive resources.
- Logs need to be inspected to diagnose an issue.

## Action Classification

| Action | Class | Quorum required |
|---|---|---|
| Service status check | Read-only | No |
| Disk space check | Read-only | No |
| Log analysis | Read-only | No |
| Process inspection | Read-only | No |
| Service restart | Destructive | Yes — 3 agents + human |
| Config change | Destructive | Yes — 3 agents + human |
| Package install/update | Destructive | Yes — 3 agents + human |

## Read-Only Inspection (bypasses quorum)

Execute directly, log to audit trail:

- **Service status:** `systemctl status <service>` — is it active, failed, or degraded?
- **Disk space:** `df -h` — check mount usage; `du -sh <dir>` for large directories.
- **Log analysis:** `journalctl -u <service> -n 200` or tail relevant log files; look for errors, crashes, OOM.
- **Process inspection:** `ps aux --sort=-%mem` / `top` — find resource hogs; `ss -tlnp` for listening ports.

## Destructive Actions (require quorum)

Before any restart or config change:

1. **ASSESS** — gather current state (status, logs, disk, processes).
2. **PLAN** — state exactly what will change and why; identify rollback.
3. **QUORUM** — submit to the 3-agent quorum (see `msp-quorum`).
4. **HUMAN CONFIRM** — wait for human confirmation.
5. **EXECUTE** — perform the change via SSH.
6. **VERIFY** — confirm the service is healthy and the change took effect.

## SSH Connection

- Connect using the Credential vault (AES-256-GCM encrypted device credentials).
- Use the `msp-tools` SSH tool.
- Decrypt only the credential needed for the target host.
- Never send raw credentials to any model.

## Pitfalls

- **Never restart a service without quorum + human confirmation.**
- **Check disk and logs BEFORE restarting** — a restart often masks the root cause.
- **Confirm the target host** — restarting the wrong server is a critical, unrecoverable error.
- **Respect the atomic-operation rule** — if interrupted mid-change, roll back to a consistent state before freezing.
- **Do not send raw credentials or PHI to cloud models.**
- **Stay within your tenant's network** — only manage servers belonging to your assigned tenant.
- **Log every action** to the audit trail, read-only and destructive alike.

## Verification

- Read-only checks returned clear results and isolated the cause.
- Destructive changes confirmed by quorum + human before execution.
- Service healthy and change verified after execution.
- Audit trail contains the full action chain.
