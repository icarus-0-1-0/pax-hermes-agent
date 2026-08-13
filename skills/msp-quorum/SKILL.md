---
name: msp-quorum
description: 3-agent quorum protocol for MSP destructive actions. Use before any password reset, config change, reboot, or user create/delete.
version: 1.0.0
author: PAX + Hermes Agent
created: 2026-08-13
license: Proprietary (pax-hermes-agent fork)
platforms: [linux]
metadata:
  hermes:
    tags: [msp, quorum, consensus, safety, destructive-actions]
    category: msp
    requires_toolsets: [msp-tools]
---

# MSP 3-Agent Quorum Protocol

Safety gate for all destructive actions in the pax-msp-portal platform. Three independent agents review every proposed destructive action; all three must agree, and a human confirms before anything executes. Non-destructive read-only actions bypass quorum entirely.

## When to Use

Use this skill whenever an agent proposes an action that changes state on a client system:

- Password resets
- Config changes
- Reboots / service restarts
- User create / delete
- Any write to a client device or directory

Do NOT use it for read-only actions (status checks, diagnostics, inventory queries) — those execute directly and are logged to the audit trail.

## Core Rule

> **3 agents review every action. 1 human confirms. No exceptions in v1.**

## Consensus Flow

1. Ticket arrives → Agent 1 assesses → Agent 2 assesses → Agent 3 assesses.
2. **All 3 agree on the action?** → Human confirms → Execute.
3. **2 agree, 1 disagrees?** → Human reviews (tiebreaker) → Human decides.
4. **All 3 say destructive?** → Human must confirm before execute.

## Agent Diversity

- Initially all 3 agents use the same model.
- Later, use different models to avoid shared blind spots.
- PAX decides when to remove the human from the loop (not in v1).

## Independent Review

Each agent must form its own verdict without copying the others. Do not anchor on the first agent's conclusion. Consider:

- Is the action correct for the ticket?
- Is the target system correctly identified?
- Is the plan consistent with the client's topology and credentials?
- Are there side effects or rollback risks?
- Does the action respect tenant isolation?

## Destructive vs Non-Destructive

| Action class | Examples | Quorum required |
|---|---|---|
| Destructive | password reset, config change, reboot, user create/delete | Yes — 3 agents + human |
| Non-destructive (read-only) | status check, diagnostics, inventory query | No — execute directly, log to audit |

## Human Tiebreaker

When agents disagree (2 vs 1), escalate to a human supervisor. Present:

- Each agent's verdict and reasoning.
- The disputed facts.
- A clear recommendation.
- The human decides; the decision is recorded in the audit log.

## Pitfalls

- **Never skip quorum for a destructive action**, even under time pressure.
- **Do not let one agent's verdict bias the others** — review independently.
- **Read-only actions still get logged** to the audit trail; they are not invisible.
- **A human tiebreaker is mandatory** on disagreement — do not pick a majority and proceed.
- **Record every quorum decision** (QUORUM_DECISION) in the audit log for SOC2.

## Verification

- All 3 agents recorded an independent verdict.
- Consensus reached (3/3) or escalated to human tiebreaker.
- Human confirmation captured before any destructive execute.
- Audit log contains the quorum decision and the human confirmation.
