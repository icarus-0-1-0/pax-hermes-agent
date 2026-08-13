#!/usr/bin/env python3
"""MSP Agent HTTP API server.

A lightweight standalone HTTP API for the MSP agent. Serves the endpoints
the pax-msp-portal calls. This is a v1 scaffold: classification, assessment,
quorum, execution, and verification are all mock/placeholder responses so the
portal -> agent round-trip can be proven end-to-end before the real AI logic
(Ollama, skills, SSH to devices) is wired in during Phase 3.

Uses only the Python standard library (http.server, json) so it runs anywhere
including a minimal Docker image.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = 8081

# CORS: the portal runs on :12000, the agent on :8080.
ALLOWED_ORIGIN = "*"
ALLOWED_HEADERS = "Content-Type, Authorization"
ALLOWED_METHODS = "GET, POST, OPTIONS"


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": ALLOWED_METHODS,
        "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    }


def log(msg):
    print(msg, flush=True)


def _classify(body):
    """Mock classification: pick a plausible category from keywords in the ticket."""
    content = " ".join(
        str(body.get(k, "")) for k in ("ticketContent", "content", "title")
    ).lower()

    if any(k in content for k in ("password", "reset pass", "login", "credential")):
        category, priority = "password_reset", "normal"
    elif any(k in content for k in ("lock", "locked", "account lock")):
        category, priority = "account_unlock", "high"
    elif any(k in content for k in ("vpn", "connect", "network", "wifi")):
        category, priority = "connectivity", "normal"
    elif any(k in content for k in ("email", "outlook", "mailbox")):
        category, priority = "email_issue", "normal"
    elif any(k in content for k in ("slow", "crash", "error", "bsod", "blue screen")):
        category, priority = "hardware_issue", "high"
    else:
        category, priority = "general_request", "low"

    return {
        "category": category,
        "priority": priority,
        "confidence": 0.85,
    }


def _assess(body):
    """Mock assessment of a ticket before action planning."""
    return {
        "context": {
            "clientFound": True,
            "userFound": False,
            "systemType": "standalone",
        },
        "ready": True,
    }


def _quorum(body):
    """Mock three-agent quorum review."""
    return {
        "agent1": {
            "decision": "approve",
            "reasoning": "Action is safe and well-defined",
        },
        "agent2": {
            "decision": "approve",
            "reasoning": "Password reset with force-change is standard procedure",
        },
        "agent3": {
            "decision": "approve",
            "reasoning": "No risk to system integrity",
        },
        "consensus": "unanimous",
        "needsHuman": True,
    }


def _execute(body):
    """Mock execution. Does NOT touch any real system in v1."""
    return {
        "success": True,
        "output": "Password reset successfully. Force-change flag set.",
        "error": None,
    }


def _verify(body):
    return {
        "success": True,
        "details": "Password changed, force-change-at-next-login flag is set",
    }


def _stop(body):
    return {"stopped": True, "state": "frozen at checkpoint", "checkpoint": "execute"}


def _resume(body):
    return {"resumed": True, "phase": "verify"}


def _status(body=None):
    return {"alive": True, "currentTicket": None, "phase": None, "lastAction": "idle"}


def _health(body=None):
    return {"status": "ok"}


# Route table: path -> (methods, handler). Handlers take a parsed JSON body
# (or None) and return a JSON-serializable dict.
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
    server_version = "MSPAgent/1.0"

    # ---- plumbing --------------------------------------------------------

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        """Parse the request body as JSON; return dict or None."""
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return None
        try:
            data = self.rfile.read(length)
            return json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ---- routing ---------------------------------------------------------

    def _dispatch(self):
        path = urlparse(self.path).path
        method = self.command
        route = ROUTES.get(path)

        if route is None:
            log(f"404 {method} {path}")
            self._send(404, {"error": "not_found", "path": path})
            return

        allowed, handler = route
        if method not in allowed:
            log(f"405 {method} {path}")
            self._send(405, {"error": "method_not_allowed", "allowed": sorted(allowed)})
            return

        body = self._read_body() if method in ("POST", "PUT", "PATCH") else None
        log(f"{method} {path} body={json.dumps(body) if body else None}")

        try:
            result = handler(body)
            self._send(200, result)
        except Exception as exc:  # graceful error handling
            log(f"500 {method} {path}: {exc!r}")
            self._send(500, {"error": "internal_error", "detail": str(exc)})

    # ---- http methods ----------------------------------------------------

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_OPTIONS(self):
        # Preflight for CORS.
        self.send_response(204)
        for k, v in _cors_headers().items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        # Redirect BaseHTTPRequestHandler's built-in log to our stdout logging.
        log("%s - %s" % (self.address_string(), fmt % args))


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"MSP agent API listening on http://{HOST}:{PORT}")
    log(f"Registered routes: {', '.join(sorted(ROUTES))}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
