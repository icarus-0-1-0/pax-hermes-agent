---
name: msp-password-reset
description: MSP password reset workflow (AD domain + standalone via SSH). Use when a client employee cannot log in and needs a password reset.
version: 1.0.0
author: PAX + Hermes Agent
created: 2026-08-13
license: Proprietary (pax-hermes-agent fork)
platforms: [linux]
metadata:
  hermes:
    tags: [msp, password-reset, active-directory, ssh, quorum]
    category: msp
    requires_toolsets: [msp-tools, terminal]
---

# MSP Password Reset

Automated password reset for MSP client employees. This is the first automation target of the pax-msp-portal platform. Covers both Active Directory domain accounts and standalone machines reached over SSH with a local admin credential.

## When to Use

Use this skill when a support ticket indicates a client employee cannot log in and the resolution is a password reset:

- "I can't log in, my password isn't working."
- Account locked out or expired.
- User forgot their password and needs a temporary one.
- New user needs an initial password set.

Do NOT use it for account creation, deletion, or privilege changes — those are separate destructive actions with their own quorum review.

## Prerequisites

- Assigned MSP tenant context (see `msp-client-context`).
- Access to the pax-msp-portal database for client topology and the encrypted Credential vault (AES-256-GCM).
- `msp-tools` plugin providing SSH and AD management tools.
- Quorum system available for the destructive execute phase.

## Checkpoint-Based Execution

Every password reset follows the platform's mandatory phases. Each phase ends at a checkpoint where a human can stop, take over, or abort.

### 1. ASSESS

- Parse the ticket for: employee name/username, hostname, or "my computer".
- Look up the employee in the tenant's client directory (`ClientContact`).
- Determine whether the client is on an AD domain or standalone (check custom assets / credentials).
- Identify the target system(s) (`SubnetIP` hostname).
- **Checkpoint:** record findings, then proceed.

### 2. PLAN

- **If AD:** "Connect to domain controller, reset password for `<username>`, set temporary password, flag for change at next login."
- **If standalone:** "Connect to `<hostname>` via SSH/local admin, reset password for `<username>`, set temporary password, flag for change at next login."
- Submit the plan to the 3-agent quorum (see `msp-quorum`).
- **Checkpoint:** wait for quorum consensus + human confirmation before any change.

### 3. EXECUTE

- Connect to the target system via SSH using the Credential vault.
- Perform the password reset.
- Record the temporary password in the ticket message (encrypted).
- **The agent does NOT store the password** — it lives only in the ticket response.

### 4. VERIFY

- Confirm the password reset succeeded.
- Confirm the "change at next login" flag is set.
- Report the result to the ticket.

### 5. RESOLVE

- Update the ticket with the result.
- Email the employee the temporary password + instructions (via existing SMTP).
- Audit log: full chain of actions recorded.

## Temporary Password Generation

- Generate a strong temporary password meeting the client's password policy (length, complexity).
- Use a cryptographically secure random source.
- Never reuse a previous password.
- Always set the **force change at next login** flag so the temporary value is short-lived.

## Pitfalls

- **Never send PHI or raw credentials to cloud models.** Sanitize ticket text before any model call (see `msp-client-context`).
- **Do not store the temporary password** in agent memory or logs — ticket response only.
- **Confirm AD vs standalone** before planning; the wrong path wastes a quorum round and risks a failed reset.
- **Respect the atomic-operation rule:** if interrupted mid-reset, roll back to a consistent state before freezing at the checkpoint.
- **Verify the flag** — a reset without "change at next login" leaves a permanent known password in place.
- **Lockout awareness:** repeated failed attempts may have already locked the account; note this in the plan.

## Verification

- Password reset command returned success.
- "Change at next login" flag confirmed set.
- Employee can authenticate with the temporary password (or the reset is confirmed at the directory level).
- Ticket updated and email sent.
- Audit log contains the full action chain (ASSESS → PLAN → EXECUTE → VERIFY → RESOLVE).
