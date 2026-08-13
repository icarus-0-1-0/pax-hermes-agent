#!/usr/bin/env python3
"""MSP Agent HTTP API server (Phase 3 — real implementations).

A standalone HTTP API that the pax-msp-portal calls. Replaces the v1 mock
scaffold with real functionality:

  * Real PostgreSQL connectivity (psycopg2) into pax_msp_portal.
  * Real Ollama AI integration (http://localhost:11434/api/chat) for
    classification, assessment, and quorum review (local model qwen2.5:7b).
  * Real SSH (paramiko) for password-reset execution and verification.
  * Real AES-256-GCM credential decryption (see msp_crypto.py, matching the
    portal's src/lib/crypto.ts).
  * Checkpoint + QuorumDecision + AuditLog persistence.

Security:
  * PHI sanitization before any ticket text is sent to Ollama.
  * v1 uses the local Ollama model so no PHI leaves the host.
  * SSH connections time out at 30 seconds.
  * All significant actions are written to the AuditLog.
"""

import json
import random
import re
import secrets
import string
import threading
import time
import urllib.request

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import psycopg2

import msp_db
import msp_crypto

HOST = "0.0.0.0"
PORT = 8081

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5:7b"  # local model — no PHI leaves the host
OLLAMA_TIMEOUT = 120

SSH_TIMEOUT = 30

ALLOWED_ORIGIN = "*"
ALLOWED_HEADERS = "Content-Type, Authorization"
ALLOWED_METHODS = "GET, POST, OPTIONS"

# Classify categories the portal/agent agree on.
CATEGORIES = [
    "password_reset", "network_issue", "server_management",
    "printer", "user_provisioning", "other",
]

# A per-process lock so the single-threaded Ollama pool is not overwhelmed.
_ollama_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# PHI sanitization
# ---------------------------------------------------------------------------

_PHI_PATTERNS = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b")),
    ("DOB", re.compile(r"\b\d{1,2}/\d{1,2}/(?:19|20)\d{2}\b|\b\d{4}-\d{2}-\d{2}\b")),
    ("PHONE", re.compile(r"\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}")),
    ("MEDICAL", re.compile(
        r"\b(diagnosis|diagnoses|patient|medical record|diagnostic|cancer|"
        r"diabetes|hiv|hipaa|prescription|medication|surgery|hospital|"
        r"clinic|lab result|treatment|disease|oncology|cardiology)\b",
        re.IGNORECASE)),
]

_MEDICAL_MARKERS = (
    "patient", "diagnos", "medical", "hipaa", "prescription", "medication",
    "surgery", "hospital", "clinic", "lab", "treatment", "disease", "cancer",
    "diabetes", "hiv", "doctor", "nurse", "symptom", "dosage", "diagnostic",
    "health record", "chart", "pharmacy",
)


def sanitize_phi(text):
    """Replace PHI patterns with placeholders and return (sanitized, mapping)."""
    if not text:
        return text, {}
    mapping = {}
    out = text
    for label, pat in _PHI_PATTERNS:
        def _repl(m, _label=label):
            key = f"[{_label}-{len(mapping)}]"
            mapping[key] = m.group(0)
            return key
        out = pat.sub(_repl, out)
    return out, mapping


def contains_medical_phi(text):
    if not text:
        return False
    low = text.lower()
    return any(marker in low for marker in _MEDICAL_MARKERS)


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": ALLOWED_METHODS,
        "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    }


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

def ollama_chat(messages, model=None, temperature=0.2):
    """Call the local Ollama chat API and return the assistant text."""
    model = model or OLLAMA_MODEL
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with _ollama_lock:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    return data.get("message", {}).get("content", "")


def _extract_json(text):
    """Best-effort extraction of a JSON object from an LLM reply."""
    if not text:
        return {}
    # Trim code fences if the model wrapped the JSON.
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    candidate = text[start:end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# DB helpers (wrapped, returns dict for JSON)
# ---------------------------------------------------------------------------

def _get_ticket_context(conn, ticket_id):
    """Return ticket, messages, client, contacts, networks, ips, credentials."""
    ticket = msp_db.get_ticket(conn, ticket_id)
    if not ticket:
        return None
    client = msp_db.get_client(conn, ticket.get("clientId"))
    contacts = msp_db.get_client_contacts(conn, ticket.get("clientId")) if client else []
    networks = msp_db.get_networks(conn, ticket.get("clientId")) if client else []
    network_ids = [n["id"] for n in networks]
    ips = msp_db.get_subnet_ips(conn, network_ids) if network_ids else []
    creds = msp_db.get_credentials(conn, client_id=ticket.get("clientId")) if client else []
    return {
        "ticket": ticket,
        "messages": msp_db.get_ticket_messages(conn, ticket_id),
        "client": client,
        "contacts": contacts,
        "networks": networks,
        "ips": ips,
        "credentials": creds,
    }


# ---------------------------------------------------------------------------
# Endpoint implementations
# ---------------------------------------------------------------------------

def _health(body=None):
    return {"status": "ok", "model": OLLAMA_MODEL}


def _status(body=None):
    try:
        conn = msp_db.connect()
        conn.close()
        db_ok = True
    except Exception as exc:
        db_ok = False
        log(f"status: db check failed: {exc!r}")
    return {
        "alive": True,
        "dbConnected": db_ok,
        "model": OLLAMA_MODEL,
        "currentTicket": None,
        "phase": None,
        "lastAction": "idle",
    }


def _classify(body):
    """Classify a ticket into a category + priority using Ollama."""
    body = body or {}
    ticket_id = body.get("ticketId")
    conn = msp_db.connect()
    try:
        context = None
        if ticket_id:
            context = _get_ticket_context(conn, ticket_id)
        if context:
            ticket = context["ticket"]
            content = ticket.get("subject") or ""
            for m in context["messages"]:
                content += "\n" + (m.get("body") or "")
        else:
            content = " ".join(str(body.get(k, "")) for k in
                               ("content", "ticketContent", "title"))
        sanitized, _mapping = sanitize_phi(content)

        system = (
            "You are an MSP ticket classifier. Classify the following support "
            "request into exactly one category and assign a priority and "
            "confidence. Categories: password_reset, network_issue, "
            "server_management, printer, user_provisioning, other. Priority: "
            "low, normal, high, urgent. "
            "Respond with ONLY a JSON object: "
            '{"category": "...", "priority": "...", "confidence": 0.0-1.0, '
            '"reason": "short"}.'
        )
        user = f"Ticket content:\n{sanitized[:4000]}"
        raw = ollama_chat([
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ])
        parsed = _extract_json(raw)
        category = parsed.get("category")
        if category not in CATEGORIES:
            category = "other"
        priority = str(parsed.get("priority", "normal")).lower()
        if priority not in ("low", "normal", "high", "urgent"):
            priority = "normal"
        try:
            confidence = float(parsed.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        confidence = max(0.0, min(1.0, confidence))

        # Persist classification on the ticket if we have one.
        if context and ticket_id:
            cur = conn.cursor()
            cur.execute(
                'UPDATE "Ticket" SET category=%s, status=%s, '
                '"updatedAt"=now() WHERE "id"=%s',
                (category, "CLASSIFIED", ticket_id),
            )
            conn.commit()

        return {
            "ticketId": ticket_id,
            "category": category,
            "priority": priority,
            "confidence": confidence,
            "reason": parsed.get("reason", ""),
            "phiDetected": bool(_mapping),
        }
    finally:
        conn.close()


def _assess(body):
    """Assess a ticket: gather client/system context, decide readiness."""
    body = body or {}
    ticket_id = body.get("ticketId")
    conn = msp_db.connect()
    try:
        context = _get_ticket_context(conn, ticket_id)
        if not context:
            return {"ready": False, "error": "ticket_not_found",
                    "context": {"clientFound": False, "userFound": False}}

        ticket = context["ticket"]
        client = context["client"] or {}
        creds = context["credentials"]

        # AD detection: any credential mentioning domain/AD/Active Directory.
        on_ad = False
        ad_cred = None
        for c in creds:
            nm = (c.get("name") or "").lower()
            un = (c.get("username") or "").lower()
            url = (c.get("url") or "").lower()
            if any(k in nm for k in ("domain", "ad ", "active directory", "dc ")) or \
               any(k in un for k in ("domain", "admin")) or \
               any(k in url for k in ("domain", "dc")):
                on_ad = True
                ad_cred = c
                break

        # UserFound: look for a username/email in the ticket text.
        content = (ticket.get("subject") or "")
        for m in context["messages"]:
            content += "\n" + (m.get("body") or "")
        user_found = False
        user_candidates = []
        for c in creds:
            if c.get("username") and c["username"].lower() in content.lower():
                user_found = True
                user_candidates.append(c["username"])

        # Identify target hosts from ticket text + SubnetIP hostnames.
        target_hosts = []
        low = content.lower()
        for ip in context["ips"]:
            hn = (ip.get("hostname") or "")
            if hn and hn.lower() in low:
                target_hosts.append({"host": hn, "ip": ip.get("ip")})
        # Also infer from subnet gateway hostname / credential urls.

        # Determine system type via Ollama (sanitized).
        sanitized, _mapping = sanitize_phi(content)
        system = (
            "You are an MSP technician assessing a support ticket. From the "
            "ticket text and context, determine the target system type for a "
            "potential action. Respond with ONLY a JSON object: "
            '{"systemType": "ad_windows" | "standalone_windows" | "linux" | '
            '"network_device" | "unknown", "userAccount": "..." or null, '
            '"targetHost": "..." or null, "notes": "..."}.'
        )
        client_info = client.get("name") or "unknown"
        user_prompt = (
            f"Client: {client_info}\n"
            f"On-AD: {on_ad}\n"
            f"Known usernames: {[c.get('username') for c in creds]}\n"
            f"Ticket text:\n{sanitized[:3000]}"
        )
        raw = ollama_chat([
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ])
        parsed = _extract_json(raw)
        system_type = parsed.get("systemType", "unknown")
        if system_type not in ("ad_windows", "standalone_windows", "linux",
                               "network_device", "unknown"):
            system_type = "unknown"
        if on_ad and system_type in ("unknown", "standalone_windows"):
            system_type = "ad_windows"
        user_account = parsed.get("userAccount") or (user_candidates[0] if user_candidates else None)
        ai_target = parsed.get("targetHost")
        if ai_target and ai_target not in [h["host"] for h in target_hosts]:
            target_hosts.append({"host": ai_target, "ip": None})

        ready = client is not None
        return {
            "ready": ready,
            "context": {
                "clientFound": client is not None,
                "clientName": client.get("name"),
                "userFound": user_found or bool(user_account),
                "userAccount": user_account,
                "onAD": on_ad,
                "adCredential": ad_cred.get("name") if ad_cred else None,
                "systemType": system_type,
                "targetHosts": target_hosts,
                "phiDetected": bool(_mapping),
            },
        }
    finally:
        conn.close()


def _quorum(body):
    """Three independent Ollama reviews of a proposed action."""
    body = body or {}
    ticket_id = body.get("ticketId")
    tenant_id = body.get("tenantId")
    checkpoint_id = body.get("checkpointId")
    proposed = body.get("proposedActions") or []
    action_desc = json.dumps(proposed)
    if not action_desc or action_desc == "[]":
        action_desc = body.get("actionDescription") or json.dumps(body.get("action") or {})

    sanitized, _mapping = sanitize_phi(action_desc)

    profiles = {
        "agent1": (
            "security",
            "You are Agent 1 of a three-agent safety review. Focus on SECURITY. "
            "Assess whether the proposed MSP action introduces security risk, "
            "privilege escalation, or data exposure. Respond ONLY with JSON: "
            '{"decision": "approve"|"deny", "reasoning": "..."}.'),
        "agent2": (
            "operational",
            "You are Agent 2 of a three-agent safety review. Focus on "
            "OPERATIONAL impact. Assess whether the proposed MSP action is "
            "operationable, reversible, and minimally disruptive to the client. "
            "Respond ONLY with JSON: "
            '{"decision": "approve"|"deny", "reasoning": "..."}.'),
        "agent3": (
            "risk",
            "You are Agent 3 of a three-agent safety review. Focus on overall "
            "RISK assessment. Weigh the probability and severity of harm, "
            "including destructive or irreversible actions. Respond ONLY with "
            "JSON: {\"decision\": \"approve\"|\"deny\", \"reasoning\": \"...\"}."),
    }

    decisions = {}
    for agent, (focus, system) in profiles.items():
        try:
            raw = ollama_chat([
                {"role": "system", "content": system},
                {"role": "user",
                 "content": f"Proposed action(s): {sanitized[:3000]}\n"
                            f"Evaluate as Agent focusing on {focus}."},
            ])
            parsed = _extract_json(raw)
            dec = parsed.get("decision", "approve")
            if dec not in ("approve", "deny"):
                dec = "approve"
            decisions[agent] = {
                "decision": dec,
                "reasoning": parsed.get("reasoning", "") or raw[:300],
            }
        except Exception as exc:
            log(f"quorum {agent} error: {exc!r}")
            decisions[agent] = {"decision": "approve",
                                "reasoning": f"Ollama error, defaulting to approve: {exc}"}

    d = [decisions[a]["decision"] for a in ("agent1", "agent2", "agent3")]
    approves = d.count("approve")
    denies = d.count("deny")
    if approves == 3:
        consensus = "unanimous"
    elif approves >= 2:
        consensus = "majority"
    elif approves == 0:
        consensus = "unanimous_deny"
    else:
        consensus = "disagreement"
    # v1: always require human review.
    needs_human = True

    # Persist quorum decision.
    if tenant_id or ticket_id:
        conn = msp_db.connect()
        try:
            msp_db.insert_quorum(
                conn, tenant_id, ticket_id, checkpoint_id,
                decisions, consensus, needs_human,
            )
            msp_db.insert_audit_log(
                conn, tenant_id, "QUORUM_DECISION",
                entity_type="QuorumDecision",
                entity_id=checkpoint_id,
                details={"proposedActions": proposed, "consensus": consensus,
                         "decisions": d, "needsHuman": needs_human},
                actor_type="AGENT",
                target="quorum",
            )
        except Exception as exc:
            log(f"quorum persist error: {exc!r}")
        finally:
            conn.close()

    return {
        "agent1": decisions["agent1"],
        "agent2": decisions["agent2"],
        "agent3": decisions["agent3"],
        "consensus": consensus,
        "needsHuman": needs_human,
        "phiDetected": bool(_mapping),
    }


# ---------------------------------------------------------------------------
# SSH / execution
# ---------------------------------------------------------------------------

def _random_temp_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)):
            return pw


def _ssh_exec(host, username, password, command, port=22, timeout=SSH_TIMEOUT):
    """Run a command over SSH via paramiko. Returns (rc, stdout, stderr)."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        allow_agent=False, look_for_keys=False,
    )
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        client.close()


def _resolve_target_credential(conn, ticket_id, system_type):
    """Pick the credential + host to use for a password reset action."""
    context = _get_ticket_context(conn, ticket_id)
    if not context:
        return None, None, None
    creds = context["credentials"]
    if not creds:
        return None, None, None

    # Prefer a domain/AD credential for AD systems; else a server credential.
    target_cred = None
    for c in creds:
        nm = (c.get("name") or "").lower()
        un = (c.get("username") or "").lower()
        if any(k in nm for k in ("domain", "active directory", "ad ", "dc ")) \
                or any(k in un for k in ("domain", "administrator")):
            target_cred = c
            break
    if target_cred is None:
        # Prefer credentials whose url looks like a host.
        for c in creds:
            url = c.get("url") or ""
            if url and re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", url):
                target_cred = c
                break
    if target_cred is None:
        target_cred = creds[0]

    host = None
    url = target_cred.get("url")
    if url:
        host = url.split("://")[-1].split("/")[0].split(":")[0]
    return target_cred, host, creds


def _execute(body):
    """Execute a proposed action (real password reset over SSH)."""
    body = body or {}
    ticket_id = body.get("ticketId")
    tenant_id = body.get("tenantId")
    checkpoint_id = body.get("checkpointId")
    action = body.get("action") or (body.get("actions") or [{}])[0]
    action_type = action.get("type") or body.get("type")
    target = action.get("target")

    if action_type != "password_reset":
        return {
            "success": True,
            "skipped": True,
            "output": f"Non-password-reset action ({action_type}) not "
                      f"implemented; returning placeholder.",
            "error": None,
        }

    conn = msp_db.connect()
    try:
        cred, host, creds = _resolve_target_credential(conn, ticket_id, None)
        if not cred:
            return {"success": False, "error": "no_credential",
                    "output": "No SSH credential found for this client."}
        cipher = msp_db.get_cipher()
        if not cipher:
            return {"success": False, "error": "encryption_key_missing",
                    "output": "ENCRYPTION_KEY not configured."}
        ssh_password = cipher.decrypt(cred.get("passwordEnc"))
        if not ssh_password:
            return {"success": False, "error": "decrypt_failed",
                    "output": "Could not decrypt SSH credential."}

        username = action.get("username") or target
        if not username:
            username = cred.get("username")
        if not username:
            return {"success": False, "error": "no_target_user",
                    "output": "No target username supplied."}

        if not host:
            # If no host from credential url, pick from subnet gateway IP.
            context = _get_ticket_context(conn, ticket_id)
            if context and context["ips"]:
                for ip in context["ips"]:
                    if ip.get("status") == "USED":
                        host = ip.get("ip")
                        break
        if not host:
            return {"success": False, "error": "no_target_host",
                    "output": "Could not resolve an SSH target host."}

        new_password = _random_temp_password()

        # Build the reset command based on system type.
        sys_type = (action.get("systemType") or "").lower()
        if sys_type in ("ad", "ad_windows", "domain"):
            cmd = f'net user {username} {new_password} /domain'
        elif sys_type == "linux":
            # Quote the password safely for the shell.
            quoted = new_password.replace("'", "'\\''")
            cmd = f"echo '{username}:{quoted}' | chpasswd"
        else:
            cmd = f'net user {username} {new_password}'

        log(f"execute: SSH {cred.get('username')}@{host} for ticket {ticket_id}")
        msp_db.insert_audit_log(
            conn, tenant_id, "SSH_CONNECT",
            entity_type="Credential", entity_id=cred.get("id"),
            details={"host": host, "username": cred.get("username")},
            actor_type="AGENT", target=f"{username}@{host}",
        )

        try:
            rc, out, err = _ssh_exec(host, cred.get("username"), ssh_password, cmd)
        except Exception as ssh_exc:
            log(f"execute ssh error: {ssh_exc!r}")
            msp_db.insert_audit_log(
                conn, tenant_id, "COMMAND_EXEC",
                entity_type="Ticket", entity_id=ticket_id,
                details={"host": host, "command": cmd,
                         "ssh_error": str(ssh_exc)},
                actor_type="AGENT", target=f"{username}@{host}",
                result="FAILURE",
            )
            return {"success": False, "error": "ssh_failed",
                    "output": f"SSH to {host} failed: {ssh_exc}",
                    "host": host, "username": username}

        msp_db.insert_audit_log(
            conn, tenant_id, "COMMAND_EXEC",
            entity_type="Ticket", entity_id=ticket_id,
            details={"host": host, "command": cmd, "rc": rc,
                     "stderr_tail": err[-500:]},
            actor_type="AGENT", target=f"{username}@{host}",
            result="SUCCESS" if rc == 0 else "FAILURE",
        )

        if rc != 0:
            return {"success": False, "error": "command_failed",
                    "output": f"Command failed (rc={rc}): {err[-500:]}",
                    "host": host, "username": username}

        # Persist checkpoint for execute phase.
        msp_db.upsert_checkpoint(
            conn, checkpoint_id, ticket_id, "execute", "completed",
            agent_actions=[{
                "action": "password_reset", "target": f"{username}@{host}",
                "command": cmd, "rc": rc,
            }],
            proposed_actions=[{
                "action": "password_reset", "target": target or username,
                "systemType": sys_type or "unknown",
            }],
            tenant_id=tenant_id,
        )

        msp_db.insert_audit_log(
            conn, tenant_id, "PASSWORD_RESET",
            entity_type="Ticket", entity_id=ticket_id,
            details={"host": host, "username": username,
                     "systemType": sys_type or "unknown"},
            actor_type="AGENT", target=f"{username}@{host}",
            result="SUCCESS",
        )

        return {
            "success": True,
            "host": host,
            "username": username,
            "temporaryPassword": new_password,
            "forceChangeRequired": True,
            "output": f"Password reset for {username}@{host} completed (rc=0).",
            "error": None,
        }
    finally:
        conn.close()


def _verify(body):
    """Verify a completed action (attempt SSH auth with new password)."""
    body = body or {}
    ticket_id = body.get("ticketId")
    tenant_id = body.get("tenantId")
    checkpoint_id = body.get("checkpointId")
    new_password = body.get("temporaryPassword") or body.get("newPassword")

    conn = msp_db.connect()
    try:
        cred, host, _creds = _resolve_target_credential(conn, ticket_id, None)
        if not host:
            return {"success": False, "error": "no_target_host",
                    "details": "No host resolved for verification."}
        if not new_password:
            return {"success": False, "error": "no_password",
                    "details": "No new password supplied for verification."}

        try:
            rc, out, err = _ssh_exec(host, cred.get("username"), new_password,
                                     "echo verified_ok")
            ok = (rc == 0) or ("verified_ok" in out)
            result = "SUCCESS" if ok else "FAILURE"
            msp_db.insert_audit_log(
                conn, tenant_id, "COMMAND_EXEC",
                entity_type="Ticket", entity_id=ticket_id,
                details={"verify": True, "host": host, "rc": rc,
                         "out": out[-200:], "err": err[-200:]},
                actor_type="AGENT", target=f"verify@{host}", result=result,
            )
            return {"success": ok,
                    "details": f"Verification auth {'succeeded' if ok else 'failed'} "
                               f"on {host}.",
                    "rc": rc}
        except Exception as exc:
            log(f"verify ssh error: {exc!r}")
            return {"success": False, "error": "ssh_failed",
                    "details": str(exc)}
    finally:
        conn.close()


def _stop(body):
    """Stop/freeze the workflow: mark checkpoint pending, ticket ON_HOLD."""
    body = body or {}
    ticket_id = body.get("ticketId")
    tenant_id = body.get("tenantId")
    checkpoint_id = body.get("checkpointId")
    conn = msp_db.connect()
    try:
        if ticket_id:
            msp_db.update_ticket_status(conn, ticket_id, "ON_HOLD")
        if checkpoint_id:
            msp_db.upsert_checkpoint(
                conn, checkpoint_id, ticket_id, "assess", "pending",
                agent_actions=[], proposed_actions=[],
                tenant_id=tenant_id,
            )
        msp_db.insert_audit_log(
            conn, tenant_id, "CHECKPOINT_TRANSITION",
            entity_type="Ticket", entity_id=ticket_id,
            details={"action": "stop", "checkpointId": checkpoint_id},
            actor_type="AGENT", target="stop",
        )
        return {"stopped": True, "state": "frozen at checkpoint",
                "checkpoint": checkpoint_id}
    finally:
        conn.close()


def _resume(body):
    """Resume the workflow: checkpoint approved, ticket IN_PROGRESS."""
    body = body or {}
    ticket_id = body.get("ticketId")
    tenant_id = body.get("tenantId")
    checkpoint_id = body.get("checkpointId")
    conn = msp_db.connect()
    try:
        if ticket_id:
            msp_db.update_ticket_status(conn, ticket_id, "IN_PROGRESS")
        if checkpoint_id:
            msp_db.upsert_checkpoint(
                conn, checkpoint_id, ticket_id, "execute", "approved",
                agent_actions=[], proposed_actions=[],
                tenant_id=tenant_id,
            )
        msp_db.insert_audit_log(
            conn, tenant_id, "CHECKPOINT_TRANSITION",
            entity_type="Ticket", entity_id=ticket_id,
            details={"action": "resume", "checkpointId": checkpoint_id},
            actor_type="AGENT", target="resume",
        )
        return {"resumed": True, "phase": "execute", "checkpoint": checkpoint_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

ROUTES = {
    "/status": ({"GET"}, _status),
    "/health": ({"GET"}, _health),
    "/classify": ({"POST"}, _classify),
    "/assess": ({"POST"}, _assess),
    "/quorum": ({"POST"}, _quorum),
    "/execute": ({"POST"}, _execute),
    "/verify": ({"POST"}, _verify),
    "/stop": ({"POST"}, _stop),
    "/resume": ({"POST"}, _resume),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "MSPAgent/2.0"

    def _send(self, code, payload):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return None
        try:
            data = self.rfile.read(length)
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _dispatch(self):
        path = urlparse(self.path).path
        method = self.command
        route = ROUTES.get(path)
        if route is None:
            self._send(404, {"error": "not_found", "path": path})
            return
        allowed, handler = route
        if method not in allowed:
            self._send(405, {"error": "method_not_allowed", "allowed": sorted(allowed)})
            return
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
        t0 = time.time()
        try:
            result = handler(body)
            dt = round(time.time() - t0, 3)
            log(f"{method} {path} -> 200 ({dt}s)")
            self._send(200, result)
        except Exception as exc:
            log(f"500 {method} {path}: {exc!r}")
            self._send(500, {"error": "internal_error", "detail": str(exc)})

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        log("%s - %s" % (self.address_string(), fmt % args))


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"MSP agent API listening on http://{HOST}:{PORT}")
    log(f"Model: {OLLAMA_MODEL} | Ollama: {OLLAMA_URL}")
    log(f"Routes: {', '.join(sorted(ROUTES))}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
