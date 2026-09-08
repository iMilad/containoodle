#!/usr/bin/env python3
"""Isolated, AWS-free helper fixture for real Firefox acceptance tests.

This is test code, not an alternative production helper. It preserves the real
HTTP routes, request authentication and response signing from server.py, while
all identity/account data is synthetic and production outbound TCP/DNS/URL and
process paths fail closed. The runner must also install and verify the Firefox
network guard; these Python stubs are not operating-system isolation.
It never reads the user's AWS configuration, cache or helper key.

Run with Python 3.10+. A single JSON line on stdout reports its ephemeral
loopback URL and two *test-only* in-memory keys. Configure it using a no-Origin
POST to /__fixture/control with X-Containoodle-Fixture-Control and a JSON body.
For example: {"action":"configure","mode":"bad-schema"}. A GET never changes
fixture state. Send {"action":"status"} to retrieve counts and current state.

Synthetic sign-in URL generation is disabled by default. Enable it only after
the Firefox runner has installed a fail-closed, externally verified browser
network block: {"action":"configure","allowSyntheticLaunches":true,
"networkBlocked":true}. The returned AWS-shaped URL contains only a fake token;
it must still be intercepted by that browser block before any external request.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


SYNTHETIC_ACCOUNTS = [
    {
        "accountId": "000000000000",
        "accountName": "__CONTAINOODLE_TEST_ACCOUNT_ALPHA__",
        "role": "__CONTAINOODLE_TEST_ROLE_ALPHA__",
        "region": "eu-west-1",
    },
    {
        "accountId": "000000000001",
        "accountName": "__CONTAINOODLE_TEST_ACCOUNT_BETA__",
        # No fixed role: Firefox can exercise real role discovery and its picker.
        "region": "us-west-2",
    },
]
SYNTHETIC_ROLES = [
    "__CONTAINOODLE_TEST_ROLE_ALPHA__",
    "__CONTAINOODLE_TEST_ROLE_BETA__",
]
SYNTHETIC_PROFILES = [
    "__CONTAINOODLE_TEST_PROFILE_ALPHA__",
    "__CONTAINOODLE_TEST_PROFILE_BETA__",
]
SYNTHETIC_ACCESS_TOKEN = "__CONTAINOODLE_TEST_ACCESS_TOKEN_ONLY__"
SYNTHETIC_SIGNIN_TOKEN = "__CONTAINOODLE_TEST_SIGNIN_TOKEN_NOT_VALID__"
CONTROL_PATH = "/__fixture/control"
CONTROL_HEADER = "X-Containoodle-Fixture-Control"
MODES = frozenset({
    "good", "unavailable", "disconnect", "empty", "bad-schema", "bad-json", "bad-proof",
    "challenge-delay", "challenge-body-delay", "accounts-delay",
    "accounts-body-delay",
})


def forbidden_io(*_args, **_kwargs):
    raise AssertionError("Synthetic Firefox fixture forbids real AWS, file and outbound I/O")


class SyntheticHelper:
    """One fixture process: temporary paths, in-memory state and guarded I/O."""

    def __init__(self):
        self.guards = ExitStack()
        self.root = Path(self.guards.enter_context(
            tempfile.TemporaryDirectory(prefix="containoodle-firefox-helper-")
        ))
        self.lock = threading.Lock()
        self.state = {
            "mode": "good",
            "delaySeconds": 65.0,
            "identity": "alpha",
            "allowSyntheticLaunches": False,
        }
        self.counts = {}
        self.control_token = secrets.token_urlsafe(32)
        self.helper_token = secrets.token_urlsafe(32)

        # server.py computes default paths at import time, but does not read
        # them. Give even those initial defaults an empty temporary location;
        # do not repurpose HOME or inspect the inherited AWS environment.
        with patch.dict(os.environ, {"PORT": "0"}, clear=True), patch.object(
            Path, "home", return_value=self.root
        ):
            spec = importlib.util.spec_from_file_location(
                "containoodle_firefox_fixture_server",
                Path(__file__).resolve().parents[1] / "server.py",
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("Cannot load the local helper source")
            self.server = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.server)

        self.server.HOST = "127.0.0.1"
        self.server.PORT = 0
        self.server.DEFAULT_ROLE = SYNTHETIC_ROLES[0]
        self.server.ACCOUNTS_FILE = self.root / "accounts.json"
        self.server.AWS_CONFIG_FILE = self.root / "config"
        self.server.SSO_CACHE_DIR = self.root / "sso-cache"
        self.server.HELPER_TOKEN_FILE = self.root / "helper-token"
        self.server.HELPER_TOKEN = self.helper_token

        # These files are deliberately never created. An accidental unmocked
        # file read cannot find user data even if an upstream code path changes.
        for name in (
            "_load_aws_config", "_resolve_sso_profile", "_select_profile_sso_identity",
            "_select_automatic_sso_identity", "_load_or_create_helper_token",
            "_read_helper_token", "_create_helper_token", "_get_role_credentials",
            "_run_aws_cli", "_build_signin_url", "main",
        ):
            self.guards.enter_context(patch.object(self.server, name, forbidden_io))
        for owner, name in (
            (subprocess, "run"), (subprocess, "Popen"), (os, "system"),
            (urllib.request, "urlopen"), (urllib.request.OpenerDirector, "open"),
            (socket, "create_connection"), (socket, "getaddrinfo"),
            (socket.socket, "connect"), (socket.socket, "connect_ex"),
        ):
            self.guards.enter_context(patch.object(owner, name, forbidden_io))
        for name in ("posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                self.guards.enter_context(patch.object(os, name, forbidden_io))
        for name in ("sendto", "sendmsg"):
            if hasattr(socket.socket, name):
                self.guards.enter_context(patch.object(socket.socket, name, forbidden_io))
        # HTTPServer asks for its own name during bind. Keep that operation
        # deterministic rather than permitting a reverse-DNS resolver query.
        self.guards.enter_context(patch.object(socket, "getfqdn", return_value="localhost"))
        self.server._load_accounts = self.load_accounts
        self.server._select_sso_identity = self.select_identity
        self.server._list_account_roles = self.list_roles
        self.server.generate_signin_url = self.generate_url
        self.handler_class = self.make_handler()
        self.httpd = None

    def snapshot(self):
        with self.lock:
            return {**self.state, "counts": dict(self.counts), "synthetic": True}

    def count(self, name):
        with self.lock:
            self.counts[name] = self.counts.get(name, 0) + 1

    def configure(self, command):
        if not isinstance(command, dict):
            raise ValueError("Fixture command must be an object")
        if command.get("action") == "status" and set(command) == {"action"}:
            return self.snapshot()
        allowed = {"action", "mode", "delaySeconds", "identity",
                   "allowSyntheticLaunches", "networkBlocked", "resetCounts"}
        if command.get("action") != "configure" or not set(command) <= allowed:
            raise ValueError("Unknown fixture command")
        proposed = {key: value for key, value in self.snapshot().items()
                    if key not in {"counts", "synthetic"}}
        if "mode" in command:
            if command["mode"] not in MODES:
                raise ValueError("Unknown fixture mode")
            proposed["mode"] = command["mode"]
        if "delaySeconds" in command:
            seconds = command["delaySeconds"]
            if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) \
                    or not 0 <= seconds <= 75:
                raise ValueError("Fixture delay must be between 0 and 75 seconds")
            proposed["delaySeconds"] = float(seconds)
        if "identity" in command:
            if command["identity"] not in {"alpha", "beta", "expired"}:
                raise ValueError("Unknown synthetic identity")
            proposed["identity"] = command["identity"]
        if "allowSyntheticLaunches" in command:
            enabled = command["allowSyntheticLaunches"]
            if not isinstance(enabled, bool):
                raise ValueError("Synthetic launch flag must be boolean")
            if enabled and command.get("networkBlocked") is not True:
                raise ValueError("Install the Firefox network block before enabling synthetic launches")
            proposed["allowSyntheticLaunches"] = enabled
        if "resetCounts" in command and not isinstance(command["resetCounts"], bool):
            raise ValueError("Counter reset flag must be boolean")
        with self.lock:
            self.state = proposed
            if command.get("resetCounts"):
                self.counts.clear()
        return self.snapshot()

    def load_accounts(self):
        self.count("loadAccounts")
        mode = self.snapshot()["mode"]
        if mode == "unavailable":
            raise self.server.AccountsFileError("accounts.json could not be read", 503)
        if mode == "empty":
            return []
        if mode == "bad-schema":
            return [{"accountId": "__NOT_AN_ACCOUNT__", "accountName": "__INVALID_FIXTURE__"}]
        return copy.deepcopy(SYNTHETIC_ACCOUNTS)

    def select_identity(self, profile=None):
        self.count("selectIdentity")
        if profile is not None and profile not in SYNTHETIC_PROFILES:
            raise self.server.SsoSelectionError("Selected AWS CLI profile was not found")
        identity = self.snapshot()["identity"]
        if identity == "expired":
            raise self.server.SsoSelectionError("AWS SSO login has expired. Run aws sso login and try again.")
        if profile is not None:
            identity += ":" + profile
        return {
            "identityKey": hashlib.sha256(("synthetic-firefox:" + identity).encode()).hexdigest(),
            "accessToken": SYNTHETIC_ACCESS_TOKEN,
            "region": "eu-central-1",
            "cache": {"region": "eu-central-1"},
        }

    def list_roles(self, access_token, account_id, region):
        self.count("listRoles")
        if access_token != SYNTHETIC_ACCESS_TOKEN \
                or account_id not in {account["accountId"] for account in SYNTHETIC_ACCOUNTS} \
                or region != "eu-central-1":
            raise AssertionError("Unexpected non-synthetic role request")
        return list(SYNTHETIC_ROLES)

    def generate_url(self, account_id, role, region, profile=None, expected_identity=None):
        self.count("generateUrl")
        if not self.snapshot()["allowSyntheticLaunches"]:
            raise RuntimeError("Synthetic launch is disabled until browser egress is blocked")
        if account_id not in {account["accountId"] for account in SYNTHETIC_ACCOUNTS} \
                or role not in SYNTHETIC_ROLES or region not in {"eu-west-1", "us-west-2"}:
            raise AssertionError("Unexpected non-synthetic launch request")
        selection = self.select_identity(profile)
        self.server._verify_sso_identity(selection, expected_identity)
        return "https://signin.aws.amazon.com/federation?" + urllib.parse.urlencode({
            "Action": "login", "Issuer": "__CONTAINOODLE_SYNTHETIC_FIREFOX_TEST__",
            "Destination": f"https://{region}.console.aws.amazon.com/console/home?region={region}",
            "SigninToken": SYNTHETIC_SIGNIN_TOKEN,
        })

    def make_handler(self):
        fixture = self
        server = self.server

        class FixtureHandler(server.ContainoodleHandler):
            def log_request(self, *_args, **_kwargs):
                pass

            def log_error(self, *_args, **_kwargs):
                pass

            def log_message(self, *_args, **_kwargs):
                pass

            def do_GET(self):
                fixture.count("GET " + urllib.parse.urlparse(self.path).path)
                path = urllib.parse.urlparse(self.path).path
                if path in {"/__fixture/favicon-page", "/__fixture/favicon.svg"} and self._check_host():
                    # Public loopback-only image fixtures. No AWS assets, real
                    # identities, tokens or user cookies are inspected here.
                    origin = "http://127.0.0.1:" + str(self.server.server_port)
                    trap = origin + "/__fixture/forbidden-svg-resource"
                    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16">'
                           '<circle cx="8" cy="8" r="6" fill="#9ea7ff"/>'
                           '<path d="M5 8h6M8 5v6" stroke="white"/>'
                           '<image href="' + trap + '" width="1" height="1"/>'
                           '<script>fetch("' + trap + '")</script></svg>')
                    if path.endswith("favicon-page"):
                        name = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("service", ["fixture"])[0]
                        if name not in {"sagemaker", "s3", "systems-manager", "lambda", "inspector", "fixture"}:
                            self.send_error(400)
                            return
                        body = ('<!doctype html><title>' + name + ' | Synthetic favicon test</title>'
                                '<link rel="icon" href="data:image/svg+xml,' + urllib.parse.quote(svg, safe="") + '">'
                                '<p>Synthetic favicon fixture. No AWS connection.</p>').encode()
                        content_type = "text/html; charset=utf-8"
                    else:
                        body = svg.encode()
                        content_type = "image/svg+xml"
                        if self.headers.get("Cookie"):
                            fixture.count("faviconCookieReceived")
                        if self.headers.get("Referer"):
                            fixture.count("faviconReferrerReceived")
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    if path.endswith("favicon-page"):
                        self.send_header("Set-Cookie", "__CONTAINOODLE_TEST_FAVICON__=fixture; Path=/; SameSite=Lax")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if fixture.snapshot()["mode"] == "disconnect":
                    # Simulate a transport outage on this accepted connection
                    # only. The listener and guarded POST control stay alive,
                    # preserving the fixture URL/key for recovery checks.
                    self.close_connection = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.connection.close()
                    return
                try:
                    super().do_GET()
                except (BrokenPipeError, ConnectionResetError, TimeoutError):
                    # Expected when Firefox aborts a deliberately delayed body.
                    pass

            def do_POST(self):
                self._response_auth = None
                if self.path != CONTROL_PATH or not self._check_host():
                    self.send_error(404)
                    return
                supplied = self.headers.get_all(CONTROL_HEADER, [])
                if self.headers.get_all("Origin", []) or len(supplied) != 1 \
                        or not hmac.compare_digest(supplied[0], fixture.control_token):
                    self.send_error(403)
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get_all("Transfer-Encoding", []) or len(lengths) != 1:
                    self.send_error(400)
                    return
                try:
                    length = int(lengths[0])
                    if not 0 < length <= 4096:
                        raise ValueError("Invalid control body size")
                    command = json.loads(self.rfile.read(length))
                    result = fixture.configure(command)
                except (ValueError, TypeError):
                    server.ContainoodleHandler._send_json(self, {"error": "Invalid fixture control command"}, 400)
                    return
                server.ContainoodleHandler._send_json(self, result)

            def _send_json(self, data, status=200):
                state = fixture.snapshot()
                mode = state["mode"]
                path = urllib.parse.urlparse(self.path).path
                challenge = path == "/auth/challenge"
                accounts = path == "/accounts" and getattr(self, "_response_auth", None)
                before_headers = (challenge and mode == "challenge-delay") \
                    or (accounts and mode == "accounts-delay")
                delayed_body = (challenge and mode == "challenge-body-delay") \
                    or (accounts and mode == "accounts-body-delay")
                if before_headers:
                    time.sleep(state["delaySeconds"])
                if not delayed_body and not (accounts and mode in {"bad-json", "bad-proof"}):
                    return super()._send_json(data, status)
                # Only deliberately corrupted/delayed responses use the custom
                # writer. All normal responses retain the production writer.
                body = b"{__CONTAINOODLE_MALFORMED_JSON_FIXTURE__" \
                    if accounts and mode == "bad-json" else json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                auth = getattr(self, "_response_auth", None)
                if auth:
                    proof = server._response_proof(auth["challenge"], status, auth["target"], body,
                                                   auth["host"], auth["origin"])
                    if mode == "bad-proof":
                        proof = "0" * 64
                    self.send_header(server._RESPONSE_PROOF_HEADER, proof)
                self._add_cors_headers()
                self.end_headers()
                self.wfile.flush()
                if delayed_body:
                    time.sleep(state["delaySeconds"])
                self.wfile.write(body)

        return FixtureHandler

    def bind(self):
        if self.httpd is not None:
            raise RuntimeError("Fixture is already bound")
        self.httpd = self.server.ContainoodleHTTPServer(("127.0.0.1", 0), self.handler_class)
        self.server.PORT = self.httpd.server_address[1]
        return {
            "synthetic": True,
            "fixture": "containoodle-firefox-offline-v1",
            "url": f"http://127.0.0.1:{self.server.PORT}",
            "helperToken": self.helper_token,
            "controlToken": self.control_token,
            "controlPath": CONTROL_PATH,
            "controlHeader": CONTROL_HEADER,
            "accounts": copy.deepcopy(SYNTHETIC_ACCOUNTS),
            "roles": list(SYNTHETIC_ROLES),
            "profiles": list(SYNTHETIC_PROFILES),
            "modes": sorted(MODES),
            "syntheticLaunchesEnabled": False,
            "userFilesRead": False,
            "outboundNetworking": "production TCP/DNS/URL/process paths stubbed; runner must also block egress",
        }

    def close(self):
        if self.httpd is not None:
            self.httpd.server_close()
        self.guards.close()


def main():
    fixture = SyntheticHelper()

    def terminate(_signal, _frame):
        # The Firefox runner normally stops children with SIGTERM. Raising a
        # normal exit lets finally close the listener and remove only this
        # fixture's owned TemporaryDirectory, just as Ctrl-C does.
        raise SystemExit(0)

    previous_term_handler = signal.signal(signal.SIGTERM, terminate)
    try:
        handshake = fixture.bind()
        print(json.dumps(handshake), flush=True)
        fixture.httpd.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            fixture.close()
        finally:
            signal.signal(signal.SIGTERM, previous_term_handler)


if __name__ == "__main__":
    main()
