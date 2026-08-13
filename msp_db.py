#!/usr/bin/env python3
"""Database helpers for the MSP agent API server.

Connects to the pax_msp_portal PostgreSQL database using psycopg2. The DB URL
is taken from the DATABASE_URL env var, or (fallback) parsed from the portal's
.env.local file. The ENCRYPTION_KEY is read the same way and exposed for
credential decryption via msp_crypto.

Note: the portal schema uses mixed-case camelCase column names, so every
column identifier is double-quoted in generated SQL.
"""

import os
import re
import uuid

import psycopg2
import psycopg2.extras

from msp_crypto import Cipher

# Portal location on FRIES (used when env vars are not set).
ENV_FILE = os.path.expanduser("~/Documents/Dev/pax-msp-portal/.env.local")

_db_url_cache = None
_enc_key_cache = None
_cipher_cache = None


def _read_env_file():
    """Read key=value pairs from the portal's .env.local file."""
    data = {}
    try:
        with open(ENV_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def get_database_url() -> str:
    """Return the PostgreSQL URL from env or the portal .env.local."""
    global _db_url_cache
    if _db_url_cache:
        return _db_url_cache
    url = os.environ.get("DATABASE_URL")
    if not url:
        url = _read_env_file().get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL not set and not found in portal .env.local")
    _db_url_cache = url
    return url


def get_encryption_key() -> str | None:
    """Return the ENCRYPTION_KEY from env or the portal .env.local."""
    global _enc_key_cache
    if _enc_key_cache is not None:
        return _enc_key_cache
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        key = _read_env_file().get("ENCRYPTION_KEY")
    _enc_key_cache = key
    return key


def get_cipher() -> Cipher | None:
    """Return a cached Cipher bound to the ENCRYPTION_KEY (or None if unset)."""
    global _cipher_cache
    if _cipher_cache is None:
        key = get_encryption_key()
        if key:
            _cipher_cache = Cipher(key)
    return _cipher_cache


def connect():
    """Open and return a new psycopg2 connection."""
    return psycopg2.connect(get_database_url())


def _cols(cols):
    """Quote a list of column names for INSERT/UPDATE."""
    return ", ".join('"%s"' % c for c in cols)


def _placeholders(n):
    return ", ".join(["%s"] * n)


def _new_id():
    return "ag" + uuid.uuid4().hex[:20]


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------

def get_ticket(conn, ticket_id):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'SELECT * FROM "Ticket" WHERE "id" = %s', (ticket_id,)
    )
    return cur.fetchone()


def get_ticket_messages(conn, ticket_id):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'SELECT * FROM "TicketMessage" WHERE "ticketId" = %s '
        'ORDER BY "createdAt" ASC',
        (ticket_id,),
    )
    return cur.fetchall()


def get_client(conn, client_id):
    if not client_id:
        return None
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM "Client" WHERE "id" = %s', (client_id,))
    return cur.fetchone()


def get_client_contacts(conn, client_id):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'SELECT * FROM "ClientContact" WHERE "clientId" = %s', (client_id,)
    )
    return cur.fetchall()


def get_credentials(conn, client_id=None, tenant_id=None):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    sql = 'SELECT * FROM "Credential"'
    conds, args = [], []
    if client_id:
        conds.append('"clientId" = %s')
        args.append(client_id)
    if tenant_id:
        conds.append('"tenantId" = %s')
        args.append(tenant_id)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    cur.execute(sql, args)
    return cur.fetchall()


def get_networks(conn, client_id=None):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    sql = 'SELECT * FROM "Network"'
    if client_id:
        sql += ' WHERE "clientId" = %s'
        cur.execute(sql, (client_id,))
    else:
        cur.execute(sql)
    return cur.fetchall()


def get_subnet_ips(conn, network_ids=None):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if network_ids:
        cur.execute(
            'SELECT * FROM "SubnetIP" WHERE "networkId" = ANY(%s) '
            'ORDER BY ip',
            (list(network_ids),),
        )
    else:
        cur.execute('SELECT * FROM "SubnetIP" ORDER BY ip')
    return cur.fetchall()


def get_checkpoints(conn, ticket_id):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        'SELECT * FROM "Checkpoint" WHERE "ticketId" = %s '
        'ORDER BY "createdAt" DESC',
        (ticket_id,),
    )
    return cur.fetchall()


# --------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------

def upsert_checkpoint(conn, checkpoint_id, ticket_id, phase, status,
                      agent_actions, proposed_actions, human_review=None,
                      tenant_id=None):
    """Create or update a Checkpoint row. Returns the row id."""
    if not checkpoint_id:
        checkpoint_id = _new_id()
    cur = conn.cursor()
    # Check existence
    cur.execute('SELECT 1 FROM "Checkpoint" WHERE "id" = %s', (checkpoint_id,))
    exists = cur.fetchone() is not None
    if exists:
        cur.execute(
            'UPDATE "Checkpoint" SET phase=%s, status=%s, '
            '"agentActions"=%s, "proposedActions"=%s, "humanReview"=%s '
            'WHERE "id" = %s',
            (phase, status, psycopg2.extras.Json(agent_actions),
             psycopg2.extras.Json(proposed_actions),
             psycopg2.extras.Json(human_review) if human_review is not None else None,
             checkpoint_id),
        )
    else:
        resolved = "now()" if status in ("resolved", "approved", "completed") else "NULL"
        cur.execute(
            f'INSERT INTO "Checkpoint" (id, "tenantId", "ticketId", phase, '
            f'status, "agentActions", "proposedActions", "humanReview", '
            f'"createdAt", "resolvedAt") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),'
            f'{resolved})',
            (checkpoint_id, tenant_id, ticket_id, phase, status,
             psycopg2.extras.Json(agent_actions),
             psycopg2.extras.Json(proposed_actions),
             psycopg2.extras.Json(human_review) if human_review is not None else None),
        )
    conn.commit()
    return checkpoint_id


def insert_quorum(conn, tenant_id, ticket_id, checkpoint_id, decisions,
                  consensus, needs_human):
    """Insert a QuorumDecision row. decisions is a dict with per-agent fields."""
    qid = _new_id()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO "QuorumDecision" (id, "tenantId", "ticketId", '
        '"checkpointId", "agent1Decision", "agent1Reasoning", '
        '"agent2Decision", "agent2Reasoning", "agent3Decision", '
        '"agent3Reasoning", consensus, "createdAt") '
        'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())',
        (qid, tenant_id, ticket_id, checkpoint_id,
         decisions.get("agent1", {}).get("decision"),
         decisions.get("agent1", {}).get("reasoning"),
         decisions.get("agent2", {}).get("decision"),
         decisions.get("agent2", {}).get("reasoning"),
         decisions.get("agent3", {}).get("decision"),
         decisions.get("agent3", {}).get("reasoning"),
         consensus),
    )
    conn.commit()
    return qid


def update_ticket_status(conn, ticket_id, status):
    cur = conn.cursor()
    cur.execute(
        'UPDATE "Ticket" SET status=%s, "updatedAt"=now() WHERE "id" = %s',
        (status, ticket_id),
    )
    conn.commit()


def insert_audit_log(conn, tenant_id, action, entity_type=None, entity_id=None,
                     details=None, ip_address=None, actor_type="AGENT",
                     target=None, result="SUCCESS", user_id=None):
    """Insert a row into AuditLog. Returns the new id."""
    aid = _new_id()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO "AuditLog" (id, "tenantId", "userId", action, '
        '"entityType", "entityId", details, "ipAddress", "createdAt", '
        '"actorType", target, result) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),'
        '%s,%s,%s)',
        (aid, tenant_id, user_id, action, entity_type, entity_id,
         psycopg2.extras.Json(details) if details is not None else None,
         ip_address, actor_type, target, result),
    )
    conn.commit()
    return aid
