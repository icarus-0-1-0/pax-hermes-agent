---
name: msp-client-context
description: MSP client context awareness. Query pax-msp-portal DB for client topology, hosts, credentials, contacts. Enforces tenant isolation.
version: 1.0.0
author: PAX + Hermes Agent
created: 2026-08-13
license: Proprietary (pax-hermes-agent fork)
platforms: [linux]
metadata:
  hermes:
    tags: [msp, client-context, tenant-isolation, topology, credentials]
    category: msp
    requires_toolsets: [msp-tools]
---

# MSP Client Context Awareness

Build and maintain an accurate picture of the assigned MSP tenant's client infrastructure by querying the pax-msp-portal Postgres database. This skill is the foundation for every other MSP skill — you cannot plan or execute safely without correct context.

## When to Use

Use this skill at the start of any ticket and whenever you need to:

- Identify a client's networks, hosts, and topology.
- Find the correct device or domain controller for an action.
- Retrieve device credentials from the encrypted Credential vault.
- Look up client contacts and employees.
- Confirm which tenant a ticket belongs to.

## Tenant Isolation (MANDATORY)

**One agent per MSP tenant. Strict context isolation. No exceptions.**

- You only access data for your assigned tenant.
- Every query is scoped to your `tenantId`.
- Never query, read, or infer data belonging to another tenant.
- Your profile/config contains only your tenant's data.
- Network access is limited to your tenant's client networks (Tailscale ACLs).

If a ticket or query appears to reference another tenant, stop and escalate — do not attempt to access it.

## Data Sources (pax-msp-portal Postgres)

Query the portal database for client topology:

- **Tenant** — your assigned tenant record and `tenantId`.
- **Client** — client organizations under the tenant.
- **ClientContact** — employees and contacts (used for password resets).
- **Credential** — encrypted device credentials (AES-256-GCM, per-tenant DEK).
- **SubnetIP / networks** — IPAM, hostnames, subnets.
- **Domain / DNS / SSL** — domain records.
- **Custom assets** — client-specific asset types and relations.

## Building Context

1. Load your tenant record and confirm the `tenantId`.
2. Enumerate the tenant's clients.
3. For the relevant client, load networks, hosts, and custom assets.
4. Identify the target system(s) for the ticket.
5. Retrieve the needed credential from the vault (decrypt only what the action requires).
6. Confirm the employee/contact record for identity-based actions.

## PHI Handling

- **No PHI ever sent to cloud models.**
- Scan ticket text for PHI patterns before any model call.
- Substitute placeholders for detected PHI.
- Audit log records the substitution, never the PHI itself.
- Cloud models are OK for general reasoning + sanitized text only.

## Pitfalls

- **Never cross tenant boundaries** — a query that leaks another tenant's data is a critical failure.
- **Decrypt only the credential you need** — do not bulk-decrypt the vault.
- **Do not send raw credentials or PHI to any model.**
- **Confirm the tenant before acting** — a mis-scoped action is destructive and unrecoverable.
- **Keep context current** — re-query topology if the ticket spans time or the plan depends on live state.

## Verification

- All queries scoped to the assigned `tenantId`.
- Target systems and credentials correctly identified for the ticket.
- No cross-tenant data accessed.
- No PHI or raw credentials sent to any model.
- Context recorded in the ticket/audit trail.
