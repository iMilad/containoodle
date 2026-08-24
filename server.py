#!/usr/bin/env python3
"""
Containoodle — local developer tool for federated SSO console access.

Generates AWS federated sign-in URLs for the Containoodle extension.
Binds to 127.0.0.1 only. Never logs session URLs to disk.
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from pathlib import Path

PORT = int(os.environ.get("PORT", 8421))
HOST = "127.0.0.1"
DEFAULT_ROLE = os.environ.get("CONTAINOODLE_DEFAULT_ROLE", "AdministratorAccess")
DEFAULT_REGION = "eu-west-1"
ACCOUNTS_FILE = Path.home() / ".aws" / "accounts.json"
SSO_CACHE_DIR = Path.home() / ".aws" / "sso" / "cache"
HELPER_TOKEN_FILE = Path(
    os.environ.get(
        "CONTAINOODLE_HELPER_TOKEN_FILE",
        Path.home() / ".containoodle" / "helper-token",
    )
).expanduser()
HELPER_TOKEN = None

import re
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")
_ROLE_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
_HELPER_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HELPER_PROOF_RE = re.compile(r"^[0-9a-f]{64}$")
_EXTENSION_ORIGIN_RE = re.compile(r"^moz-extension://[A-Za-z0-9._-]+$")

_AUTH_CHALLENGE_PATH = "/auth/challenge"
_AUTH_CHALLENGE_TTL_SECONDS = 30.0
_AUTH_CHALLENGE_LIMIT = 128
_AUTH_CHALLENGES = OrderedDict()
_AUTH_CHALLENGE_LOCK = threading.Lock()

_CHALLENGE_HEADER = "X-Containoodle-Challenge"
_REQUEST_PROOF_HEADER = "X-Containoodle-Request-Proof"
_RESPONSE_PROOF_HEADER = "X-Containoodle-Response-Proof"
_INVALID_CHALLENGE = "A" * 43
_INVALID_PROOF = "0" * 64


# ─── Helper authentication ──────────────────────────────────────────────────

def _decode_helper_token(token: str) -> bytes:
    """Decode one canonical unpadded base64url representation of 32 bytes."""
    if not _HELPER_TOKEN_RE.fullmatch(token):
        raise RuntimeError(
            "Helper token is invalid; remove the token file and create a new one"
        )
    try:
        key = base64.urlsafe_b64decode(f"{token}=")
    except (ValueError, TypeError) as error:
        raise RuntimeError(
            "Helper token is invalid; remove the token file and create a new one"
        ) from error
    canonical = base64.urlsafe_b64encode(key).rstrip(b"=")
    if len(key) != 32 or canonical != token.encode("ascii"):
        raise RuntimeError(
            "Helper token is invalid; remove the token file and create a new one"
        )
    return key


def _validate_helper_token(token: str) -> str:
    """Validate the exact URL-safe encoding produced from 32 random bytes."""
    _decode_helper_token(token)
    return token


def _validate_helper_token_path(path: Path) -> Path:
    """Keep the persistent helper secret out of the source checkout."""
    path = path.expanduser()
    if not path.is_absolute():
        raise RuntimeError("Helper token file path must be absolute")
    project_directory = Path(__file__).resolve().parent
    resolved = path.resolve(strict=False)
    if resolved == project_directory or project_directory in resolved.parents:
        raise RuntimeError("Helper token file must be outside the project directory")
    return path


def _ensure_private_token_directory(directory: Path) -> None:
    """Create the token directory privately and reject unsafe existing modes."""
    created = False
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        created = True
    except FileExistsError:
        pass

    if created and os.name == "posix":
        directory.chmod(0o700)

    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("Helper token directory must be a real directory")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError(
            "Helper token directory must not allow group or other access"
        )
    if (
        os.name == "posix"
        and hasattr(os, "getuid")
        and metadata.st_uid != os.getuid()
    ):
        raise PermissionError(
            "Helper token directory must be owned by the current user"
        )


def _read_helper_token(path: Path) -> str:
    """Read a regular user-only token file without following a final symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Helper token path must be a regular file")
        if os.name == "posix":
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PermissionError(
                    "Helper token file must not allow group or other access"
                )
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise PermissionError("Helper token file must be owned by the current user")
        with os.fdopen(descriptor, "r", encoding="ascii", newline="") as token_file:
            descriptor = None
            try:
                token = token_file.read().rstrip("\r\n")
            except UnicodeError as error:
                raise RuntimeError("Helper token file is not valid ASCII") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return _validate_helper_token(token)


def _fsync_directory(directory: Path) -> None:
    """Persist a same-directory publication on POSIX filesystems."""
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_helper_token(path: Path) -> str:
    """Publish a fully written 256-bit token atomically without overwriting."""
    token = _validate_helper_token(secrets.token_urlsafe(32))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    published = False
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise PermissionError("Helper token file permissions must be 0600")
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as token_file:
            descriptor = None
            token_file.write(f"{token}\n")
            token_file.flush()
            os.fsync(token_file.fileno())
        os.link(temporary_path, path, follow_symlinks=False)
        _fsync_directory(path.parent)
        published = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        if published:
            _fsync_directory(path.parent)
    return token


def _load_or_create_helper_token(path: Path = HELPER_TOKEN_FILE) -> str:
    """Load the persistent helper token, creating it once when absent."""
    path = _validate_helper_token_path(path)
    _ensure_private_token_directory(path.parent)
    try:
        return _read_helper_token(path)
    except FileNotFoundError:
        try:
            return _create_helper_token(path)
        except FileExistsError:
            # Another helper won the atomic create race.
            return _read_helper_token(path)


def _join_auth_fields(*fields) -> bytes:
    """Encode an unambiguous protocol-v1 canonical string."""
    return "\n".join(str(field) for field in fields).encode("utf-8")


def _hmac_hex(*fields) -> str:
    """Return a lowercase HMAC-SHA256 proof under the configured helper key."""
    if not isinstance(HELPER_TOKEN, str):
        raise RuntimeError("Helper authentication is unavailable")
    return hmac.new(
        _decode_helper_token(HELPER_TOKEN),
        _join_auth_fields(*fields),
        hashlib.sha256,
    ).hexdigest()


def _server_proof(challenge: str, expires_at: int, host: str, origin: str) -> str:
    return _hmac_hex(
        "containoodle-server-v1",
        challenge,
        expires_at,
        host,
        origin,
    )


def _request_proof(
    challenge: str,
    method: str,
    target: str,
    host: str,
    origin: str,
) -> str:
    return _hmac_hex(
        "containoodle-request-v1",
        challenge,
        method,
        target,
        host,
        origin,
    )


def _response_proof(
    challenge: str,
    status: int,
    target: str,
    body: bytes,
    host: str,
    origin: str,
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return _hmac_hex(
        "containoodle-response-v1",
        challenge,
        status,
        target,
        body_hash,
        host,
        origin,
    )


def _prune_auth_challenges_locked(now_monotonic: float) -> None:
    """Drop expired challenges."""
    expired = [
        challenge
        for challenge, state in _AUTH_CHALLENGES.items()
        if state["deadline"] <= now_monotonic
    ]
    for challenge in expired:
        _AUTH_CHALLENGES.pop(challenge, None)


def _issue_auth_challenge(host: str, origin: str) -> dict:
    """Create one short-lived, instance-local challenge and server proof."""
    now_monotonic = time.monotonic()
    expires_at = int(time.time() * 1000) + int(
        _AUTH_CHALLENGE_TTL_SECONDS * 1000
    )
    with _AUTH_CHALLENGE_LOCK:
        _prune_auth_challenges_locked(now_monotonic)
        for _attempt in range(8):
            challenge = _validate_helper_token(secrets.token_urlsafe(32))
            if challenge not in _AUTH_CHALLENGES:
                break
        else:
            raise RuntimeError("Could not create a unique helper challenge")
        while len(_AUTH_CHALLENGES) >= _AUTH_CHALLENGE_LIMIT:
            _AUTH_CHALLENGES.popitem(last=False)
        server_proof = _server_proof(challenge, expires_at, host, origin)
        _AUTH_CHALLENGES[challenge] = {
            "deadline": now_monotonic + _AUTH_CHALLENGE_TTL_SECONDS,
            "expiresAt": expires_at,
            "host": host,
            "origin": origin,
        }
    return {
        "version": 1,
        "challenge": challenge,
        "expiresAt": expires_at,
        "serverProof": server_proof,
    }


def _consume_auth_challenge(
    challenge_value,
    proof_value,
    method: str,
    target: str,
    host: str,
    origin: str,
) -> str | None:
    """Verify and atomically consume one target-bound request authorization."""
    challenge_valid = (
        isinstance(challenge_value, str)
        and _HELPER_TOKEN_RE.fullmatch(challenge_value) is not None
    )
    proof_valid = (
        isinstance(proof_value, str)
        and _HELPER_PROOF_RE.fullmatch(proof_value) is not None
    )
    challenge = challenge_value if challenge_valid else _INVALID_CHALLENGE
    candidate = proof_value if proof_valid else _INVALID_PROOF
    expected = _request_proof(challenge, method, target, host, origin)
    proof_matches = hmac.compare_digest(candidate, expected)

    now_monotonic = time.monotonic()
    with _AUTH_CHALLENGE_LOCK:
        _prune_auth_challenges_locked(now_monotonic)
        state = _AUTH_CHALLENGES.get(challenge)
        authenticated = bool(
            challenge_valid
            and proof_valid
            and proof_matches
            and state
            and state["deadline"] > now_monotonic
            and state["host"] == host
            and state["origin"] == origin
        )
        if authenticated:
            # Consumption happens while locked and before any route work.
            del _AUTH_CHALLENGES[challenge]
            return challenge
    return None


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


class ContainoodleHandler(http.server.BaseHTTPRequestHandler):
    """Request handler for Containoodle."""

    # Suppress default stderr access log and strip query params (for security)
    def log_request(self, code='-', size='-'):
        method = getattr(self, "command", "")
        path = getattr(self, "path", "").split("?")[0]
        print(f"  {method} {path} → {code}")

    def log_error(self, format, *args):
        print(f"  ERROR: {format % args}")

    def log_message(self, format, *args):
        print(f"  {format % args}")

    def _check_host(self) -> bool:
        """Reject requests addressed to anything except the bound loopback host."""
        if self.headers.get_all("Host", []) != [f"{HOST}:{PORT}"]:
            self.send_error(403, "Forbidden: invalid Host header")
            return False
        return True

    def _canonical_origin(self) -> str:
        """Return the exact extension Origin, or '-' for a no-Origin client."""
        values = self.headers.get_all("Origin", [])
        if not values:
            return "-"
        if len(values) != 1 or not _EXTENSION_ORIGIN_RE.fullmatch(values[0]):
            raise ValueError("invalid Origin")
        return values[0]

    def _check_origin(self) -> bool:
        """Reject web Origins and malformed or duplicate extension Origins."""
        try:
            self._canonical_origin()
            return True
        except ValueError:
            self.send_error(403, "Forbidden: cross-origin request")
            return False

    def _check_request_auth(self, target: str, origin: str) -> bool:
        """Require one fresh target-bound HMAC proof without exposing the key."""
        challenges = self.headers.get_all(_CHALLENGE_HEADER, [])
        proofs = self.headers.get_all(_REQUEST_PROOF_HEADER, [])
        has_legacy_authorization = bool(self.headers.get_all("Authorization", []))
        challenge = (
            challenges[0]
            if len(challenges) == 1 and not has_legacy_authorization
            else None
        )
        proof = (
            proofs[0]
            if len(proofs) == 1 and not has_legacy_authorization
            else None
        )
        consumed = _consume_auth_challenge(
            challenge,
            proof,
            "GET",
            target,
            f"{HOST}:{PORT}",
            origin,
        )
        if consumed is None:
            self._send_json({"error": "Authentication required"}, 401)
            return False
        self._response_auth = {
            "challenge": consumed,
            "target": target,
            "host": f"{HOST}:{PORT}",
            "origin": origin,
        }
        return True

    def _add_cors_headers(self):
        """Add protocol-v1 CORS headers only for one valid extension Origin."""
        try:
            origin = self._canonical_origin()
        except ValueError:
            return
        if origin != "-":
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                f"{_CHALLENGE_HEADER}, {_REQUEST_PROOF_HEADER}",
            )
            self.send_header("Access-Control-Expose-Headers", _RESPONSE_PROOF_HEADER)
            self.send_header("Vary", "Origin")

    def _send_json(
        self,
        data: dict,
        status: int = 200,
    ):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        response_auth = getattr(self, "_response_auth", None)
        if response_auth:
            self.send_header(
                _RESPONSE_PROOF_HEADER,
                _response_proof(
                    response_auth["challenge"],
                    status,
                    response_auth["target"],
                    body,
                    response_auth["host"],
                    response_auth["origin"],
                ),
            )
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
        self._response_auth = None
        if not self._check_host():
            return
        if not self._check_origin():
            return
        origin = self._canonical_origin()
        methods = self.headers.get_all("Access-Control-Request-Method", [])
        requested_header_values = self.headers.get_all(
            "Access-Control-Request-Headers",
            [],
        )
        requested_headers = {
            header.strip().lower()
            for value in requested_header_values
            for header in value.split(",")
            if header.strip()
        }
        expected_headers = {
            _CHALLENGE_HEADER.lower(),
            _REQUEST_PROOF_HEADER.lower(),
        }
        if (
            origin != "-"
            and methods == ["GET"]
            and len(requested_header_values) == 1
            and requested_headers == expected_headers
        ):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                f"{_CHALLENGE_HEADER}, {_REQUEST_PROOF_HEADER}",
            )
            self.send_header("Access-Control-Expose-Headers", _RESPONSE_PROOF_HEADER)
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Vary", "Origin")
            self.end_headers()
        else:
            self.send_error(403)

    def do_GET(self):
        self._response_auth = None
        if not self._check_host():
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            self.send_error(404)
            return
        path = parsed.path

        protected_route = path in {"/accounts", "/roles", "/generate-url"}
        challenge_route = path == _AUTH_CHALLENGE_PATH and not parsed.query
        if not (protected_route or challenge_route):
            self.send_error(404)
            return

        if not self._check_origin():
            return
        origin = self._canonical_origin()

        if challenge_route:
            try:
                payload = _issue_auth_challenge(f"{HOST}:{PORT}", origin)
            except RuntimeError:
                self._send_json({"error": "Helper authentication unavailable"}, 503)
                return
            self._send_json(payload)
            return

        if not self._check_request_auth(self.path, origin):
            return

        # Query parsing and all filesystem/AWS work happen only after a valid
        # proof has been atomically consumed.
        qs = urllib.parse.parse_qs(parsed.query)

        # ── /accounts → return accounts list ──
        if path == "/accounts":
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
            account_id = qs.get("account", [None])[0]
            if not account_id or not _ACCOUNT_ID_RE.match(account_id):
                self._send_json({"error": "Invalid or missing account ID (expected 12-digit number)"}, 400)
                return

            meta = self._get_account_meta(account_id)
            if not meta:
                self._send_json({"error": "Account not found in accounts.json"}, 404)
                return
            # Explicit role (e.g. the sidebar's discovered/remembered pick)
            # overrides accounts.json / CONTAINOODLE_DEFAULT_ROLE
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


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run the Containoodle local helper")
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="print the helper access token to copy into extension settings and exit",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    try:
        helper_token = _load_or_create_helper_token(HELPER_TOKEN_FILE)
    except (OSError, RuntimeError) as error:
        print(f"Helper authentication unavailable: {error}", file=sys.stderr)
        return 1

    if args.show_token:
        print(helper_token)
        return 0

    global HELPER_TOKEN
    HELPER_TOKEN = helper_token
    with _AUTH_CHALLENGE_LOCK:
        _AUTH_CHALLENGES.clear()

    if not ACCOUNTS_FILE.exists():
        print(f"⚠  {ACCOUNTS_FILE} not found — create it first.")
        return 1

    server = http.server.HTTPServer((HOST, PORT), ContainoodleHandler)
    print(f"╔══════════════════════════════════════════╗")
    print(f"║        Containoodle — ready            ║")
    print(f"║             http://{HOST}:{PORT}        ║")
    print(f"╚══════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
