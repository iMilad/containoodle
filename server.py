#!/usr/bin/env python3
"""
Orbiting Turnip — local developer tool for federated SSO console access.

Generates AWS federated sign-in URLs for the Orbiting Turnip extension.
Binds to 127.0.0.1 only. Never logs session URLs to disk.
"""

import http.server
import json
import os
import subprocess
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

PORT = int(os.environ.get("PORT", 8421))
HOST = "127.0.0.1"
DEFAULT_ROLE = os.environ.get("ORBITING_TURNIP_DEFAULT_ROLE", "AdministratorAccess")
DEFAULT_REGION = "eu-west-1"
ACCOUNTS_FILE = Path.home() / ".aws" / "accounts.json"
SSO_CACHE_DIR = Path.home() / ".aws" / "sso" / "cache"

import re
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")
_ROLE_RE = re.compile(r"^[\w+=,.@-]{1,64}$")


# ─── SSO helpers ─────────────────────────────────────────────────────────────

def _find_sso_cache_file() -> dict:
    """Find the SSO cache JSON data containing an accessToken (most recent)."""
    candidates = []
    for path in SSO_CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text())
            if "accessToken" in data:
                candidates.append((path.stat().st_mtime, data))
        except (json.JSONDecodeError, OSError):
            continue
    if not candidates:
        raise RuntimeError(
            "No SSO cache file found. Run: aws sso login"
        )
    candidates.sort(key=lambda c: c[0], reverse=True)
    return candidates[0][1]


def _check_token_expiry(cache_data: dict) -> None:
    """Raise if the SSO token has expired or will within 5 minutes."""
    expires_str = cache_data.get("expiresAt", "")
    if not expires_str:
        raise RuntimeError("SSO cache has no expiresAt field")
    # Handle both formats: with and without trailing Z
    expires_str = expires_str.replace("Z", "+00:00")
    expires_at = datetime.fromisoformat(expires_str)
    now = datetime.now(timezone.utc)

    if expires_at < now:
        raise RuntimeError(
            "SSO token expired. Run: aws sso login"
        )

    # Do not move, delete, or otherwise mutate the user's AWS CLI cache.
    # A fresh interactive login is the reliable way to renew the SSO token.
    if expires_at < now + timedelta(minutes=5):
        raise RuntimeError(
            "SSO token expires within 5 minutes. Run: aws sso login"
        )


def _get_role_credentials(access_token: str, account_id: str, role: str, region: str) -> dict:
    """Call aws sso get-role-credentials and return the credentials dict."""
    result = subprocess.run(
        [
            "aws", "sso", "get-role-credentials",
            "--access-token", access_token,
            "--account-id", account_id,
            "--role-name", role,
            "--region", region,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"aws sso get-role-credentials failed: {result.stderr.strip()}"
        )
    data = json.loads(result.stdout)
    creds = data["roleCredentials"]
    return {
        "sessionId": creds["accessKeyId"],
        "sessionKey": creds["secretAccessKey"],
        "sessionToken": creds["sessionToken"],
    }


def _list_account_roles(access_token: str, account_id: str, region: str) -> list[str]:
    """Call aws sso list-account-roles and return the role names."""
    result = subprocess.run(
        [
            "aws", "sso", "list-account-roles",
            "--access-token", access_token,
            "--account-id", account_id,
            "--region", region,
            "--output", "json",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"aws sso list-account-roles failed: {result.stderr.strip()}"
        )
    data = json.loads(result.stdout)
    return [r["roleName"] for r in data.get("roleList", []) if r.get("roleName")]


def _build_signin_url(session_creds: dict, region: str) -> str:
    """Build the federated sign-in URL via AWS federation endpoint."""
    session_json = json.dumps(session_creds)
    session_encoded = urllib.parse.quote(session_json, safe="")

    # Step 1: get signin token
    token_url = (
        "https://signin.aws.amazon.com/federation"
        f"?Action=getSigninToken&Session={session_encoded}"
    )
    with urllib.request.urlopen(token_url) as resp:
        token_data = json.loads(resp.read().decode())
    signin_token = token_data["SigninToken"]

    # Step 2: build login URL with a pre-encoded console destination
    destination = f"https%3A%2F%2F{region}.console.aws.amazon.com%2Fconsole%2Fhome%3Fregion%3D{region}"
    signin_token_encoded = urllib.parse.quote(signin_token, safe="")
    login_url = (
        "https://signin.aws.amazon.com/federation"
        f"?Action=login&Issuer=&Destination={destination}"
        f"&SigninToken={signin_token_encoded}"
    )
    return login_url


def generate_signin_url(account_id: str, role: str = DEFAULT_ROLE,
                        region: str = DEFAULT_REGION) -> str:
    """Full pipeline: cache → expiry check → credentials → sign-in URL."""
    cache_data = _find_sso_cache_file()
    _check_token_expiry(cache_data)
    access_token = cache_data["accessToken"]
    creds = _get_role_credentials(access_token, account_id, role, region)
    url = _build_signin_url(creds, region)
    return url


# ─── Firefox container helper ─────────────────────────────────────────────────


def _build_container_url(container_name: str, signin_url: str) -> str:
    """Build the ext+container: protocol URL."""
    return (
        f"ext+container:name={urllib.parse.quote(container_name)}"
        f"&url={urllib.parse.quote(signin_url, safe='')}"
    )


# ─── HTTP server ──────────────────────────────────────────────────────────────


class OrbitingTurnipHandler(http.server.BaseHTTPRequestHandler):
    """Request handler for Orbiting Turnip."""

    # Suppress default stderr access log and strip query params (for security)
    def log_request(self, code='-', size='-'):
        method = getattr(self, "command", "")
        path = getattr(self, "path", "").split("?")[0]
        print(f"  {method} {path} → {code}")

    def log_error(self, format, *args):
        print(f"  ERROR: {format % args}")

    def log_message(self, format, *args):
        print(f"  {format % args}")

    def _check_origin(self) -> bool:
        """Reject cross-origin requests (CSRF protection)."""
        origin = self.headers.get("Origin")
        # Browser requests from the extension will have Origin set.
        # Non-browser requests (curl) won't have Origin — allow those
        # since they require local access anyway.
        if origin is not None:
            # Allow local Firefox extensions (moz-extension:// is only
            # granted to locally-installed add-ons)
            if not origin.startswith("moz-extension://"):
                self.send_error(403, "Forbidden: cross-origin request")
                return False
        return True

    def _add_cors_headers(self):
        """Add CORS headers for allowed origins (including moz-extension)."""
        origin = self.headers.get("Origin")
        if origin and origin.startswith("moz-extension://"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self._add_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _get_account_meta(self, account_id: str) -> dict | None:
        """Look up account metadata from accounts.json."""
        try:
            accounts = json.loads(ACCOUNTS_FILE.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        for acc in accounts:
            if acc["accountId"] == account_id:
                return acc
        return None

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        origin = self.headers.get("Origin")
        if origin and origin.startswith("moz-extension://"):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()
        else:
            self.send_error(403)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        # ── /accounts → return accounts list ──
        if path == "/accounts":
            if not self._check_origin():
                return
            try:
                accounts = json.loads(ACCOUNTS_FILE.read_text())
                self._send_json(accounts)
            except FileNotFoundError:
                self._send_json({"error": "accounts.json not found"}, 404)
            except json.JSONDecodeError:
                self._send_json({"error": "accounts.json is invalid"}, 500)
            return

        # ── /roles?account=... → list SSO roles available on the account ──
        if path == "/roles":
            if not self._check_origin():
                return
            account_id = qs.get("account", [None])[0]
            if not account_id or not _ACCOUNT_ID_RE.match(account_id):
                self._send_json({"error": "Invalid or missing account ID (expected 12-digit number)"}, 400)
                return
            meta = self._get_account_meta(account_id)
            if not meta:
                self._send_json({"error": "Account not found in accounts.json"}, 404)
                return
            region = meta.get("region", DEFAULT_REGION)
            if not _REGION_RE.match(region):
                self._send_json({"error": "Invalid region in account config"}, 400)
                return
            try:
                cache_data = _find_sso_cache_file()
                _check_token_expiry(cache_data)
                roles = _list_account_roles(cache_data["accessToken"], account_id, region)
            except RuntimeError:
                self._send_json({"error": "Failed to list roles. Is your SSO token valid?"}, 500)
                return
            except Exception:
                self._send_json({"error": "Unexpected error listing roles"}, 500)
                return
            self._send_json({"ok": True, "roles": roles})
            return

        # ── /generate-url?account=...[&role=...] → return container URL ──
        if path == "/generate-url":
            if not self._check_origin():
                return
            account_id = qs.get("account", [None])[0]
            if not account_id or not _ACCOUNT_ID_RE.match(account_id):
                self._send_json({"error": "Invalid or missing account ID (expected 12-digit number)"}, 400)
                return

            meta = self._get_account_meta(account_id)
            if not meta:
                self._send_json({"error": "Account not found in accounts.json"}, 404)
                return
            # Explicit role (e.g. the sidebar's discovered/remembered pick)
            # overrides accounts.json / ORBITING_TURNIP_DEFAULT_ROLE
            role_param = qs.get("role", [None])[0]
            role = role_param or meta.get("role", DEFAULT_ROLE)
            region = meta.get("region", DEFAULT_REGION)
            account_name = meta.get("accountName", account_id)

            if not _ROLE_RE.match(role):
                self._send_json({"error": "Invalid role name in account config"}, 400)
                return
            if not _REGION_RE.match(region):
                self._send_json({"error": "Invalid region in account config"}, 400)
                return

            try:
                signin_url = generate_signin_url(account_id, role, region)
            except RuntimeError:
                self._send_json({"error": "Failed to generate session. Is your SSO token valid?"}, 500)
                return
            except Exception:
                self._send_json({"error": "Unexpected error generating session"}, 500)
                return

            container_url = _build_container_url(account_name, signin_url)
            self._send_json({
                "ok": True,
                "containerUrl": container_url,
                "account": account_name,
            })
            return

        self.send_error(404)


def main():
    if not ACCOUNTS_FILE.exists():
        print(f"⚠  {ACCOUNTS_FILE} not found — create it first.")
        sys.exit(1)

    server = http.server.HTTPServer((HOST, PORT), OrbitingTurnipHandler)
    print(f"╔══════════════════════════════════════════╗")
    print(f"║        Orbiting Turnip — ready            ║")
    print(f"║             http://{HOST}:{PORT}        ║")
    print(f"╚══════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
