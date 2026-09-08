#!/usr/bin/env python3
"""
Containoodle — local developer tool for federated SSO console access.

Generates AWS federated sign-in URLs for the Containoodle extension.
Binds to 127.0.0.1 only. Never logs session URLs to disk.
"""

import argparse
import base64
import configparser
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from pathlib import Path

PORT = int(os.environ.get("PORT", 8421))
HOST = "127.0.0.1"
DEFAULT_ROLE = os.environ.get("CONTAINOODLE_DEFAULT_ROLE", "AdministratorAccess")
DEFAULT_REGION = "eu-west-1"
ACCOUNTS_FILE = Path.home() / ".aws" / "accounts.json"
AWS_CONFIG_FILE = Path(
    os.environ.get("AWS_CONFIG_FILE", Path.home() / ".aws" / "config")
).expanduser()
SSO_CACHE_DIR = Path.home() / ".aws" / "sso" / "cache"
HELPER_TOKEN_FILE = Path(
    os.environ.get(
        "CONTAINOODLE_HELPER_TOKEN_FILE",
        Path.home() / ".containoodle" / "helper-token",
    )
).expanduser()
HELPER_TOKEN = None

# A stalled CLI process is killed and reaped by subprocess.run. Federation
# applies a socket-operation timeout to both connecting and reading the reply.
AWS_CLI_TIMEOUT_SECONDS = 30
FEDERATION_TIMEOUT_SECONDS = 15
FEDERATION_RESPONSE_LIMIT_BYTES = 64 * 1024
# A browser can preopen a connection before sending HTTP headers. Keep those
# sockets from monopolizing the helper, without allowing unlimited workers.
REQUEST_SOCKET_TIMEOUT_SECONDS = 5
MAX_CONCURRENT_REQUESTS = 8

import re
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,64}$")
_ACCOUNT_NAME_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ACCOUNT_NAME_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
# Match JavaScript String.trim() in shared/accounts.js, including U+FEFF but
# excluding U+0085 (Python's default str.strip() differs for these characters).
_ACCOUNT_NAME_TRIM_CHARS = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_HELPER_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HELPER_PROOF_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
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

_ROUTE_QUERY_KEYS = {
    "/accounts": set(),
    "/sso-identity": {"profile"},
    "/roles": {"account", "identity", "profile"},
    "/generate-url": {"account", "identity", "profile", "role"},
}


class AccountsFileError(RuntimeError):
    """An actionable accounts-file failure with no user data in its message."""

    def __init__(self, public_message: str, status: int = 500):
        super().__init__(public_message)
        self.public_message = public_message
        self.status = status


class AwsRequestTimeout(RuntimeError):
    """An upstream operation expired; expose no secret-bearing diagnostics."""


def _reject_non_json_constant(_value):
    raise ValueError("Non-JSON constant")


def _load_accounts() -> list[dict]:
    """Load and validate the entire document before exposing or using any row.

    Do not coerce or rewrite valid values: IDs must remain exact strings, and
    optional/extra fields are preserved for existing extension consumers.
    """
    try:
        accounts = json.loads(
            ACCOUNTS_FILE.read_text(encoding="utf-8"),
            parse_constant=_reject_non_json_constant,
        )
    except FileNotFoundError:
        raise AccountsFileError("accounts.json not found", 404) from None
    except (UnicodeError, ValueError, RecursionError):
        raise AccountsFileError("accounts.json is invalid") from None
    except OSError:
        raise AccountsFileError("accounts.json could not be read") from None

    if not isinstance(accounts, list):
        raise AccountsFileError("accounts.json must contain an array of accounts")
    seen_ids = set()
    for index, account in enumerate(accounts, start=1):
        prefix = f"accounts.json entry {index}"
        if not isinstance(account, dict):
            raise AccountsFileError(f"{prefix} must be an object")
        account_id = account.get("accountId")
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise AccountsFileError(f"{prefix}: accountId must be a 12-digit string")
        name = account.get("accountName")
        if not isinstance(name, str) or not name.strip(_ACCOUNT_NAME_TRIM_CHARS):
            raise AccountsFileError(f"{prefix}: accountName must be a nonempty string")
        if len(name) > 256 or _ACCOUNT_NAME_CONTROL_RE.search(name):
            raise AccountsFileError(f"{prefix}: accountName is too long or contains control characters")
        if _ACCOUNT_NAME_SURROGATE_RE.search(name):
            raise AccountsFileError(f"{prefix}: accountName contains invalid Unicode")
        for field, pattern in (("role", _ROLE_RE), ("region", _REGION_RE)):
            if field in account and (
                not isinstance(account[field], str)
                or not pattern.fullmatch(account[field])
            ):
                raise AccountsFileError(f"{prefix}: invalid {field}")
        if account_id in seen_ids:
            raise AccountsFileError(f"{prefix}: duplicate accountId")
        seen_ids.add(account_id)
    return accounts


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

class SsoSelectionError(RuntimeError):
    """An expected, sanitized SSO-selection failure safe for API clients."""

    def __init__(self, public_message: str, status: int = 409):
        super().__init__(public_message)
        self.public_message = public_message
        self.status = status


def _nonblank_string(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_profile_name(profile: str) -> str:
    """Accept a bounded CLI profile alias without allowing control characters."""
    if (
        not _nonblank_string(profile)
        or profile != profile.strip()
        or len(profile) > 128
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159
            for character in profile
        )
    ):
        raise ValueError("Invalid AWS CLI profile selection")
    return profile


def _load_aws_config() -> configparser.RawConfigParser:
    """Read the AWS shared config without interpolation or implicit defaults."""
    parser = configparser.RawConfigParser(
        default_section="__CONTAINOODLE_UNUSED_DEFAULT__",
        interpolation=None,
        strict=True,
    )
    try:
        with AWS_CONFIG_FILE.open(encoding="utf-8") as config_file:
            parser.read_file(config_file)
    except (OSError, UnicodeError, configparser.Error) as error:
        raise SsoSelectionError(
            "AWS CLI configuration is unavailable or invalid."
        ) from error
    return parser


def _required_config_value(
    parser: configparser.RawConfigParser,
    section: str,
    option: str,
) -> str:
    if not parser.has_section(section):
        raise SsoSelectionError(
            "The selected AWS CLI profile is not configured for SSO."
        )
    value = parser.get(section, option, raw=True, fallback=None)
    if not _nonblank_string(value):
        raise SsoSelectionError(
            "The selected AWS CLI profile is not configured for SSO."
        )
    return value.strip()


def _resolve_sso_profile(profile: str) -> dict:
    """Resolve a CLI profile to its exact modern or legacy cache namespace."""
    profile = _validate_profile_name(profile)
    parser = _load_aws_config()
    profile_section = "default" if profile == "default" else f"profile {profile}"
    if not parser.has_section(profile_section):
        raise SsoSelectionError(
            "The selected AWS CLI profile is not configured for SSO."
        )

    session_name = parser.get(
        profile_section,
        "sso_session",
        raw=True,
        fallback=None,
    )
    if session_name is not None:
        if not _nonblank_string(session_name):
            raise SsoSelectionError(
                "The selected AWS CLI profile is not configured for SSO."
            )
        session_name = session_name.strip()
        session_section = f"sso-session {session_name}"
        start_url = _required_config_value(
            parser,
            session_section,
            "sso_start_url",
        )
        region = _required_config_value(parser, session_section, "sso_region")
        return {
            "cacheNamespace": session_name,
            "identityNamespace": session_name,
            "startUrl": start_url,
            "region": region,
        }

    start_url = _required_config_value(parser, profile_section, "sso_start_url")
    region = _required_config_value(parser, profile_section, "sso_region")
    return {
        "cacheNamespace": start_url,
        "identityNamespace": start_url,
        "startUrl": start_url,
        "region": region,
    }


def _check_token_expiry(cache_data: dict) -> None:
    """Raise if the SSO token has expired or will within 5 minutes."""
    expires_str = cache_data.get("expiresAt", "")
    if not _canonical_cache_string(expires_str):
        raise RuntimeError("SSO cache has no expiresAt field")
    # Handle both formats: with and without trailing Z
    if expires_str.endswith("Z"):
        expires_str = f"{expires_str[:-1]}+00:00"
    try:
        expires_at = datetime.fromisoformat(expires_str)
    except ValueError as error:
        raise RuntimeError("SSO cache has an invalid expiresAt field") from error
    if expires_at.tzinfo is None:
        raise RuntimeError("SSO cache has an invalid expiresAt field")
    now = datetime.now(timezone.utc)

    if expires_at <= now:
        raise RuntimeError(
            "SSO token expired. Run: aws sso login"
        )

    # Do not move, delete, or otherwise mutate the user's AWS CLI cache.
    # A fresh interactive login is the reliable way to renew the SSO token.
    if expires_at <= now + timedelta(minutes=5):
        raise RuntimeError(
            "SSO token expires within 5 minutes. Run: aws sso login"
        )


def _canonical_cache_string(value) -> bool:
    """Accept only nonempty printable ASCII without surrounding whitespace."""
    return bool(
        isinstance(value, str)
        and value
        and value == value.strip()
        and value.isascii()
        and all(32 < ord(character) < 127 for character in value)
    )


def _valid_sso_start_url(value) -> bool:
    if not _canonical_cache_string(value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
    )


def _validate_sso_cache(
    cache_data,
    *,
    expected_start_url: str | None = None,
    expected_region: str | None = None,
) -> tuple[str, str, str]:
    """Validate one usable cached token and its identity metadata."""
    if not isinstance(cache_data, dict):
        raise RuntimeError("SSO cache entry is invalid")
    access_token = cache_data.get("accessToken")
    start_url = cache_data.get("startUrl")
    region = cache_data.get("region")
    if not _canonical_cache_string(access_token):
        raise RuntimeError("SSO cache entry has no usable access token")
    if not _valid_sso_start_url(start_url) or not (
        _canonical_cache_string(region) and _REGION_RE.fullmatch(region)
    ):
        raise RuntimeError("SSO cache entry has invalid identity metadata")
    if expected_start_url is not None and start_url != expected_start_url:
        raise RuntimeError("SSO cache entry does not match the selected profile")
    if expected_region is not None and region != expected_region:
        raise RuntimeError("SSO cache entry does not match the selected profile")
    _check_token_expiry(cache_data)
    return access_token, start_url, region


def _sso_identity_key(namespace: str, access_token: str) -> str:
    """Create a helper-local opaque identity binding without exposing metadata."""
    return _hmac_hex(
        "containoodle-sso-identity-v1",
        namespace,
        access_token,
    )


def _select_profile_sso_identity(profile: str) -> dict:
    resolved = _resolve_sso_profile(profile)
    cache_key = hashlib.sha1(
        resolved["cacheNamespace"].encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    cache_path = SSO_CACHE_DIR / f"{cache_key}.json"
    try:
        cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SsoSelectionError(
            "The selected AWS SSO login is unavailable. "
            "Run aws sso login for the selected profile."
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SsoSelectionError(
            "The selected AWS SSO login is invalid. "
            "Run aws sso login for the selected profile."
        ) from error

    try:
        access_token, _, sso_region = _validate_sso_cache(
            cache_data,
            expected_start_url=resolved["startUrl"],
            expected_region=resolved["region"],
        )
    except (RuntimeError, TypeError) as error:
        raise SsoSelectionError(
            "The selected AWS SSO login is invalid or expiring soon. "
            "Run aws sso login for the selected profile."
        ) from error
    return {
        "cache": cache_data,
        "accessToken": access_token,
        "region": sso_region,
        "identityKey": _sso_identity_key(
            resolved["identityNamespace"],
            access_token,
        ),
    }


def _select_automatic_sso_identity() -> dict:
    """Select only when exactly one distinct usable cached token exists."""
    candidates = {}
    try:
        cache_paths = list(SSO_CACHE_DIR.glob("*.json"))
    except OSError:
        cache_paths = []

    for cache_path in cache_paths:
        try:
            cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
            access_token, start_url, region = _validate_sso_cache(cache_data)
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RuntimeError,
            TypeError,
        ):
            continue
        identity = (access_token, start_url, region)
        candidates.setdefault(identity, cache_data)

    if not candidates:
        raise SsoSelectionError(
            "No usable AWS SSO login was found. Run aws sso login."
        )
    if len(candidates) != 1:
        raise SsoSelectionError(
            "Multiple AWS SSO logins were found. Choose an AWS CLI profile."
        )

    (access_token, start_url, sso_region), cache_data = next(iter(candidates.items()))
    return {
        "cache": cache_data,
        "accessToken": access_token,
        "region": sso_region,
        "identityKey": _sso_identity_key(
            start_url,
            access_token,
        ),
    }


def _select_sso_identity(profile: str | None = None) -> dict:
    """Select one usable SSO identity deterministically and fail closed."""
    if profile is None:
        return _select_automatic_sso_identity()
    return _select_profile_sso_identity(profile)


def _verify_sso_identity(selection: dict, expected_identity: str | None) -> None:
    if expected_identity is None:
        return
    if not _IDENTITY_KEY_RE.fullmatch(expected_identity):
        raise ValueError("Invalid AWS SSO identity selection")
    if not hmac.compare_digest(selection["identityKey"], expected_identity):
        raise SsoSelectionError(
            "The AWS SSO login changed. Refresh the selected identity and try again."
        )


def _get_role_credentials(access_token: str, account_id: str, role: str, region: str) -> dict:
    """Call aws sso get-role-credentials and return the credentials dict."""
    data = _run_aws_cli(
        [
            "aws", "sso", "get-role-credentials",
            "--access-token", access_token,
            "--account-id", account_id,
            "--role-name", role,
            "--region", region,
            "--output", "json",
        ],
    )
    creds = data["roleCredentials"]
    return {
        "sessionId": creds["accessKeyId"],
        "sessionKey": creds["secretAccessKey"],
        "sessionToken": creds["sessionToken"],
    }


def _list_account_roles(access_token: str, account_id: str, region: str) -> list[str]:
    """Call aws sso list-account-roles and return the role names."""
    data = _run_aws_cli(
        [
            "aws", "sso", "list-account-roles",
            "--access-token", access_token,
            "--account-id", account_id,
            "--region", region,
            "--output", "json",
        ],
    )
    return [r["roleName"] for r in data.get("roleList", []) if r.get("roleName")]


def _run_aws_cli(command: list[str]) -> dict:
    """Bound both CLI calls and discard credential-bearing failure details."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=AWS_CLI_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise AwsRequestTimeout("AWS CLI request timed out") from None
    except (OSError, UnicodeError):
        raise RuntimeError("AWS CLI could not be run") from None
    if result.returncode != 0:
        raise RuntimeError("AWS CLI request failed")
    try:
        return json.loads(result.stdout)
    except (ValueError, RecursionError):
        raise RuntimeError("AWS CLI returned an invalid response") from None


def _build_signin_url(session_creds: dict, region: str) -> str:
    """Build the federated sign-in URL via AWS federation endpoint."""
    session_json = json.dumps(session_creds)
    session_encoded = urllib.parse.quote(session_json, safe="")

    # Step 1: get signin token
    token_url = (
        "https://signin.aws.amazon.com/federation"
        f"?Action=getSigninToken&Session={session_encoded}"
    )
    try:
        with urllib.request.urlopen(token_url, timeout=FEDERATION_TIMEOUT_SECONDS) as resp:
            payload = resp.read(FEDERATION_RESPONSE_LIMIT_BYTES + 1)
            if len(payload) > FEDERATION_RESPONSE_LIMIT_BYTES:
                raise RuntimeError("AWS federation response is too large")
            token_data = json.loads(payload.decode())
    except TimeoutError:
        raise AwsRequestTimeout("AWS federation request timed out") from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise AwsRequestTimeout("AWS federation request timed out") from None
        raise RuntimeError("AWS federation request failed") from None
    except (OSError, ValueError, RecursionError):
        raise RuntimeError("AWS federation returned an invalid response") from None
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


def generate_signin_url(
    account_id: str,
    role: str = DEFAULT_ROLE,
    region: str = DEFAULT_REGION,
    profile: str | None = None,
    expected_identity: str | None = None,
) -> str:
    """Full pipeline: cache → expiry check → credentials → sign-in URL."""
    selection = _select_sso_identity(profile)
    _verify_sso_identity(selection, expected_identity)
    creds = _get_role_credentials(
        selection["accessToken"],
        account_id,
        role,
        selection["region"],
    )
    url = _build_signin_url(creds, region)
    return url


# ─── Firefox container helper ─────────────────────────────────────────────────


def _build_container_url(container_name: str, signin_url: str) -> str:
    """Build the ext+container: protocol URL."""
    return (
        f"ext+container:name={urllib.parse.quote(container_name)}"
        f"&url={urllib.parse.quote(signin_url, safe='')}"
    )


def _optional_query_value(query: dict, name: str) -> str | None:
    values = query.get(name)
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"Invalid {name} selection")
    return values[0]


def _sso_query_values(query: dict) -> tuple[str | None, str | None]:
    profile = _optional_query_value(query, "profile")
    identity = _optional_query_value(query, "identity")
    if profile is not None:
        _validate_profile_name(profile)
    if identity is not None and not _IDENTITY_KEY_RE.fullmatch(identity):
        raise ValueError("Invalid AWS SSO identity selection")
    return profile, identity


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
        """Look up metadata only after validating the complete accounts file."""
        for acc in _load_accounts():
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

        protected_route = path in {
            "/accounts",
            "/sso-identity",
            "/roles",
            "/generate-url",
        }
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
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        allowed_query_keys = _ROUTE_QUERY_KEYS[path]
        if any(
            key not in allowed_query_keys or len(values) != 1
            for key, values in qs.items()
        ):
            self._send_json({"error": "Invalid request parameters"}, 400)
            return

        # ── /accounts → return accounts list ──
        if path == "/accounts":
            try:
                accounts = _load_accounts()
                self._send_json(accounts)
            except AccountsFileError as error:
                self._send_json({"error": error.public_message}, error.status)
            return

        # ── /sso-identity[?profile=...] → opaque selected identity key ──
        if path == "/sso-identity":
            try:
                profile = _optional_query_value(qs, "profile")
                if profile is not None:
                    _validate_profile_name(profile)
                selection = _select_sso_identity(profile)
                identity_key = selection.get("identityKey")
                if not isinstance(identity_key, str) or not _IDENTITY_KEY_RE.fullmatch(
                    identity_key
                ):
                    raise RuntimeError("Invalid internal SSO identity")
            except ValueError:
                self._send_json({"error": "Invalid AWS CLI profile selection"}, 400)
                return
            except SsoSelectionError as error:
                self._send_json({"error": error.public_message}, error.status)
                return
            except Exception:
                self._send_json({"error": "Unexpected error selecting AWS SSO login"}, 500)
                return
            self._send_json({
                "ok": True,
                "identityKey": identity_key,
            })
            return

        # ── /roles?account=... → list SSO roles available on the account ──
        if path == "/roles":
            try:
                profile, expected_identity = _sso_query_values(qs)
            except ValueError:
                self._send_json({"error": "Invalid AWS SSO selection"}, 400)
                return
            account_id = qs.get("account", [None])[0]
            if not account_id or not _ACCOUNT_ID_RE.fullmatch(account_id):
                self._send_json({"error": "Invalid or missing account ID (expected 12-digit number)"}, 400)
                return
            try:
                meta = self._get_account_meta(account_id)
            except AccountsFileError as error:
                self._send_json({"error": error.public_message}, error.status)
                return
            if not meta:
                self._send_json({"error": "Account not found in accounts.json"}, 404)
                return
            region = meta.get("region", DEFAULT_REGION)
            if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
                self._send_json({"error": "Invalid region in account config"}, 400)
                return
            try:
                selection = _select_sso_identity(profile)
                _verify_sso_identity(selection, expected_identity)
                roles = _list_account_roles(
                    selection["accessToken"],
                    account_id,
                    selection["region"],
                )
            except SsoSelectionError as error:
                self._send_json({"error": error.public_message}, error.status)
                return
            except AwsRequestTimeout:
                self._send_json({"error": "AWS request timed out. Check your connection and try again."}, 504)
                return
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
            try:
                profile, expected_identity = _sso_query_values(qs)
            except ValueError:
                self._send_json({"error": "Invalid AWS SSO selection"}, 400)
                return
            account_id = qs.get("account", [None])[0]
            if not account_id or not _ACCOUNT_ID_RE.fullmatch(account_id):
                self._send_json({"error": "Invalid or missing account ID (expected 12-digit number)"}, 400)
                return

            try:
                meta = self._get_account_meta(account_id)
            except AccountsFileError as error:
                self._send_json({"error": error.public_message}, error.status)
                return
            if not meta:
                self._send_json({"error": "Account not found in accounts.json"}, 404)
                return
            # Explicit role (e.g. the sidebar's discovered/remembered pick)
            # overrides accounts.json / CONTAINOODLE_DEFAULT_ROLE
            role_param = qs.get("role", [None])[0]
            role = role_param or meta.get("role", DEFAULT_ROLE)
            region = meta.get("region", DEFAULT_REGION)
            account_name = meta.get("accountName", account_id)

            if not isinstance(role, str) or not _ROLE_RE.fullmatch(role):
                self._send_json({"error": "Invalid role name in account config"}, 400)
                return
            if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
                self._send_json({"error": "Invalid region in account config"}, 400)
                return

            try:
                signin_url = generate_signin_url(
                    account_id,
                    role,
                    region,
                    profile,
                    expected_identity,
                )
            except SsoSelectionError as error:
                self._send_json({"error": error.public_message}, error.status)
                return
            except AwsRequestTimeout:
                self._send_json({"error": "AWS request timed out. Check your connection and try again."}, 504)
                return
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


class ContainoodleHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Serve independent local requests with bounded workers and socket waits."""

    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, client_address = super().get_request()
        try:
            request.settimeout(REQUEST_SOCKET_TIMEOUT_SECONDS)
        except OSError:
            request.close()
            raise
        return request, client_address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            # Do not queue unbounded sockets or create an extra worker to reply.
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


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

    try:
        _load_accounts()
    except AccountsFileError as error:
        print(f"Accounts unavailable: {error.public_message}", file=sys.stderr)
        return 1

    server = ContainoodleHTTPServer((HOST, PORT), ContainoodleHandler)
    print(f"╔══════════════════════════════════════════╗")
    print(f"║        Containoodle — ready            ║")
    print(f"║             http://{HOST}:{PORT}        ║")
    print(f"╚══════════════════════════════════════════╝")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
