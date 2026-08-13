# msp-tools — Custom MSP Tools Plugin

Custom tool plugin for the pax-hermes-agent fork. Provides the MSP-specific tools that the skills in `skills/msp-*` depend on. This is a **plugin directory**, not a skill — it will be built out as custom tools in the fork.

## Purpose

The MSP skills (`msp-password-reset`, `msp-client-context`, `msp-network-diagnostics`, `msp-server-management`, `msp-quorum`) reference toolsets provided by this plugin. This plugin is the integration layer between the agent and client infrastructure.

## Planned Custom Tools

### SSH to Client Devices

- `msp_ssh_exec` — run a command on a client device over SSH.
- `msp_ssh_connect` — open a managed SSH session to a target host.
- Used by `msp-password-reset` and `msp-server-management`.
- Credentials come from the encrypted Credential vault (AES-256-GCM), never from model context.

### SNMP Queries

- `msp_snmp_get` — read a single OID from a network device.
- `msp_snmp_walk` — walk a subtree of OIDs.
- Used by `msp-network-diagnostics`.
- **Read-only** — no SET operations. Bypasses quorum.

### AD Management

- `msp_ad_reset_password` — reset an Active Directory user password.
- `msp_ad_set_flag` — set the "change at next login" flag.
- `msp_ad_lookup_user` — look up a user in the tenant's directory.
- Used by `msp-password-reset`.
- **Destructive** — requires 3-agent quorum + human confirmation.

### Client Context / Portal DB

- `msp_portal_query` — query the pax-msp-portal Postgres database for client topology.
- `msp_vault_get_credential` — retrieve a decrypted device credential for a target host.
- Used by `msp-client-context`.
- **Tenant-scoped** — every query is bound to the agent's assigned `tenantId`.

## Design Constraints

- **Tenant isolation:** every tool is scoped to the agent's assigned tenant. No cross-tenant access.
- **No PHI to cloud models:** tools must sanitize output before it reaches any model.
- **Credential handling:** device credentials are decrypted only at the point of use, never stored or sent to models.
- **Quorum awareness:** destructive tools must check quorum + human confirmation before acting; read-only tools bypass quorum but still log to the audit trail.
- **Audit logging:** every tool action records to the audit trail (SSH_CONNECT, COMMAND_EXEC, PASSWORD_RESET, CONFIG_CHANGE, QUORUM_DECISION, CHECKPOINT_TRANSITION).

## Build Status

Placeholder. The tool implementations will be added to this plugin as the fork is extended. The skills in `skills/msp-*` are written against the tool names above and will light up once the tools are implemented.
