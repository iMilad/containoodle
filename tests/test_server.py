import base64
import hashlib
import io
import json
import os
import runpy
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import server


TEST_ACCOUNT_ID = "0" * 12
TEST_OTHER_ACCOUNT_ID = "not-a-real-account"
TEST_UNKNOWN_ACCOUNT_ID = "definitely-not-an-account"
TEST_ROLE_ALPHA = "__CONTAINOODLE_TEST_ROLE_ALPHA__"
TEST_ROLE_BETA = "__CONTAINOODLE_TEST_ROLE_BETA__"
TEST_ROLE_QUERY = "__CONTAINOODLE_TEST_ROLE_QUERY__"
TEST_ROLE_DEFAULT = "__CONTAINOODLE_TEST_ROLE_DEFAULT__"
TEST_PROFILE_ALPHA = "__CONTAINOODLE_TEST_PROFILE_ALPHA__"
TEST_PROFILE_BETA = "__CONTAINOODLE_TEST_PROFILE_BETA__"
TEST_SESSION_ALPHA = "__CONTAINOODLE_TEST_SESSION_ALPHA__"
TEST_SESSION_BETA = "__CONTAINOODLE_TEST_SESSION_BETA__"
TEST_START_URL_ALPHA = "https://__containoodle_test_alpha__.invalid/start"
TEST_START_URL_BETA = "https://__containoodle_test_beta__.invalid/start"
TEST_ACCESS_TOKEN_ALPHA = "__CONTAINOODLE_TEST_ACCESS_TOKEN_ALPHA__"
TEST_ACCESS_TOKEN_BETA = "__CONTAINOODLE_TEST_ACCESS_TOKEN_BETA__"


def _test_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


TEST_HELPER_KEY = bytes(range(32))
TEST_HELPER_TOKEN = _test_base64url(TEST_HELPER_KEY)
TEST_OTHER_HELPER_TOKEN = _test_base64url(bytes([255]) + TEST_HELPER_KEY[1:])
TEST_CHALLENGE = _test_base64url(bytes(range(32, 64)))
TEST_OTHER_CHALLENGE = _test_base64url(bytes(range(64, 96)))
TEST_EXTENSION_ORIGIN = "moz-extension://containoodle-test-origin"


_DEFAULT_HEADER = object()


_GUARD_DIRECTORY = None
_GUARD_PATCHERS = []


def setUpModule():
    """Fail closed if a test reaches the user's AWS state or external I/O."""
    global _GUARD_DIRECTORY
    _GUARD_DIRECTORY = tempfile.TemporaryDirectory()
    safe_root = Path(_GUARD_DIRECTORY.name)
    _GUARD_PATCHERS.extend([
        patch.object(server, "ACCOUNTS_FILE", safe_root / "accounts.json"),
        patch.object(server, "AWS_CONFIG_FILE", safe_root / "config"),
        patch.object(server, "SSO_CACHE_DIR", safe_root / "sso-cache"),
        patch.object(server, "HELPER_TOKEN", TEST_HELPER_TOKEN),
        patch.object(
            server.subprocess,
            "run",
            side_effect=AssertionError("unexpected AWS CLI invocation"),
        ),
        patch.object(
            server.urllib.request,
            "urlopen",
            side_effect=AssertionError("unexpected federation request"),
        ),
        patch.object(
            server.http.server,
            "HTTPServer",
            side_effect=AssertionError("unexpected server socket creation"),
        ),
    ])
    for patcher in _GUARD_PATCHERS:
        patcher.start()


def tearDownModule():
    for patcher in reversed(_GUARD_PATCHERS):
        patcher.stop()
    _GUARD_PATCHERS.clear()
    _GUARD_DIRECTORY.cleanup()


class FakeUrlResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self.payload


class RecordingHandler(server.ContainoodleHandler):
    """Socket-free recorder for the production request-handler methods."""

    def __init__(
        self,
        path="/",
        origin=None,
        command="GET",
        host=_DEFAULT_HEADER,
        authenticated=True,
        authorization=None,
    ):
        self.path = path
        self.command = command
        self.headers = Message()
        if host is _DEFAULT_HEADER:
            host = f"{server.HOST}:{server.PORT}"
        if host is not None:
            self.headers["Host"] = host
        if origin is not None:
            self.headers["Origin"] = origin
        if authorization is not None:
            self.headers["Authorization"] = authorization
        if authenticated:
            canonical_host = host if host is not None else ""
            canonical_origin = origin if origin is not None else "-"
            challenge_payload = server._issue_auth_challenge(
                canonical_host,
                canonical_origin,
            )
            challenge = challenge_payload["challenge"]
            proof = server._request_proof(
                challenge,
                "GET",
                path,
                canonical_host,
                canonical_origin,
            )
            self.headers[server._CHALLENGE_HEADER] = challenge
            self.headers[server._REQUEST_PROOF_HEADER] = proof
        self.wfile = io.BytesIO()
        self.response_status = None
        self.response_headers = []
        self.response_ended = False
        self.error = None

    def send_response(self, code, message=None):
        self.response_status = code

    def send_header(self, keyword, value):
        self.response_headers.append((keyword, value))

    def end_headers(self):
        self.response_ended = True

    def send_error(self, code, message=None, explain=None):
        self.response_status = code
        self.error = (code, message)

    def header_values(self):
        return dict(self.response_headers)

    def json_body(self):
        return json.loads(self.wfile.getvalue().decode())


class FixedDateTime(datetime):
    current = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current if tz else cls.current.replace(tzinfo=None)


class HelperTokenFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.token_file = (
            Path(self.temporary_directory.name)
            / "containoodle-config"
            / "helper-token"
        )

    def test_creates_a_persistent_256_bit_token_with_private_permissions(self):
        with (
            patch.object(
                server.secrets,
                "token_urlsafe",
                return_value=TEST_HELPER_TOKEN,
            ) as generate_token,
            patch.object(
                server,
                "_fsync_directory",
                wraps=server._fsync_directory,
            ) as fsync_directory,
        ):
            created = server._load_or_create_helper_token(self.token_file)
            loaded = server._load_or_create_helper_token(self.token_file)

        self.assertEqual(created, TEST_HELPER_TOKEN)
        self.assertEqual(loaded, TEST_HELPER_TOKEN)
        generate_token.assert_called_once_with(32)
        self.assertEqual(fsync_directory.call_count, 2)
        self.assertEqual(self.token_file.read_text(), f"{TEST_HELPER_TOKEN}\n")
        if os.name == "posix":
            self.assertEqual(
                self.token_file.parent.stat().st_mode & 0o777,
                0o700,
            )
            self.assertEqual(self.token_file.stat().st_mode & 0o777, 0o600)

    def test_rejects_invalid_generated_or_persisted_tokens(self):
        with (
            patch.object(server.secrets, "token_urlsafe", return_value="too-short"),
            self.assertRaisesRegex(RuntimeError, "Helper token is invalid"),
        ):
            server._load_or_create_helper_token(self.token_file)

        self.token_file.parent.mkdir(mode=0o700, exist_ok=True)
        self.token_file.write_text("not-a-valid-helper-token\n")
        if os.name == "posix":
            self.token_file.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "Helper token is invalid"):
            server._load_or_create_helper_token(self.token_file)

    def test_rejects_noncanonical_encoding_of_the_same_256_bit_key(self):
        noncanonical = f"{TEST_HELPER_TOKEN[:-1]}9"
        self.assertEqual(
            base64.urlsafe_b64decode(f"{noncanonical}="),
            TEST_HELPER_KEY,
        )
        with self.assertRaisesRegex(RuntimeError, "Helper token is invalid"):
            server._validate_helper_token(noncanonical)

    def test_atomic_publication_never_replaces_an_existing_token(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text(f"{TEST_HELPER_TOKEN}\n")
        if os.name == "posix":
            self.token_file.chmod(0o600)

        with (
            patch.object(
                server.secrets,
                "token_urlsafe",
                return_value=TEST_OTHER_HELPER_TOKEN,
            ),
            self.assertRaises(FileExistsError),
        ):
            server._create_helper_token(self.token_file)

        self.assertEqual(self.token_file.read_text(), f"{TEST_HELPER_TOKEN}\n")
        self.assertEqual(
            list(self.token_file.parent.glob(f".{self.token_file.name}.*.tmp")),
            [],
        )

    def test_concurrent_creators_publish_one_complete_token(self):
        self.token_file.parent.mkdir(mode=0o700)
        publication_barrier = threading.Barrier(2)
        values = iter((TEST_HELPER_TOKEN, TEST_OTHER_HELPER_TOKEN))
        values_lock = threading.Lock()
        real_link = os.link
        results = []
        errors = []

        def next_token(_byte_count):
            with values_lock:
                return next(values)

        def synchronized_link(source, destination, **kwargs):
            source_path = Path(source)
            self.assertIn(
                source_path.read_text(),
                (f"{TEST_HELPER_TOKEN}\n", f"{TEST_OTHER_HELPER_TOKEN}\n"),
            )
            if os.name == "posix":
                self.assertEqual(source_path.stat().st_mode & 0o777, 0o600)
            publication_barrier.wait(timeout=5)
            return real_link(source, destination, **kwargs)

        def create():
            try:
                results.append(server._load_or_create_helper_token(self.token_file))
            except Exception as error:  # pragma: no cover - asserted below
                errors.append(error)

        with (
            patch.object(server.secrets, "token_urlsafe", side_effect=next_token),
            patch.object(server.os, "link", side_effect=synchronized_link),
        ):
            threads = [threading.Thread(target=create) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.token_file.read_text(), f"{results[0]}\n")
        self.assertEqual(
            list(self.token_file.parent.glob(f".{self.token_file.name}.*.tmp")),
            [],
        )

    def test_failed_publication_leaves_no_partial_final_file(self):
        self.token_file.parent.mkdir(mode=0o700)
        with (
            patch.object(
                server.secrets,
                "token_urlsafe",
                return_value=TEST_HELPER_TOKEN,
            ),
            patch.object(
                server.os,
                "link",
                side_effect=OSError("synthetic publication failure"),
            ),
            self.assertRaisesRegex(OSError, "synthetic publication failure"),
        ):
            server._create_helper_token(self.token_file)

        self.assertFalse(self.token_file.exists())
        self.assertEqual(
            list(self.token_file.parent.glob(f".{self.token_file.name}.*.tmp")),
            [],
        )

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_rejects_group_or_world_access_to_the_token_file(self):
        self.token_file.parent.mkdir(mode=0o700)
        self.token_file.write_text(f"{TEST_HELPER_TOKEN}\n")
        self.token_file.chmod(0o640)

        with self.assertRaisesRegex(PermissionError, "group or other"):
            server._load_or_create_helper_token(self.token_file)

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_rejects_group_or_world_access_to_the_token_directory(self):
        self.token_file.parent.mkdir(mode=0o755)
        self.token_file.parent.chmod(0o755)

        with self.assertRaisesRegex(PermissionError, "group or other"):
            server._load_or_create_helper_token(self.token_file)

    def test_rejects_relative_or_in_checkout_token_paths(self):
        with self.assertRaisesRegex(RuntimeError, "absolute"):
            server._validate_helper_token_path(Path("relative-helper-token"))

        checkout_token = Path(server.__file__).resolve().parent / "synthetic-token"
        with self.assertRaisesRegex(RuntimeError, "outside the project"):
            server._validate_helper_token_path(checkout_token)


class HelperStartupTests(unittest.TestCase):
    def test_invalid_token_state_fails_before_binding_the_server(self):
        with (
            patch.object(
                server,
                "_load_or_create_helper_token",
                side_effect=RuntimeError("synthetic token failure"),
            ),
            patch.object(server.http.server, "HTTPServer") as http_server,
            patch("builtins.print") as print_message,
        ):
            result = server.main([])

        self.assertEqual(result, 1)
        http_server.assert_not_called()
        rendered = " ".join(str(call) for call in print_message.call_args_list)
        self.assertNotIn(TEST_HELPER_TOKEN, rendered)

    def test_invalid_persisted_token_fails_before_binding_the_server(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            token_file = Path(temporary_directory) / "config" / "helper-token"
            token_file.parent.mkdir(mode=0o700)
            token_file.write_text("invalid-token\n")
            if os.name == "posix":
                token_file.parent.chmod(0o700)
                token_file.chmod(0o600)

            with (
                patch.object(server, "HELPER_TOKEN_FILE", token_file),
                patch.object(server.http.server, "HTTPServer") as http_server,
                patch("builtins.print"),
            ):
                result = server.main([])

        self.assertEqual(result, 1)
        http_server.assert_not_called()

    def test_show_token_is_the_explicit_non_binding_onboarding_path(self):
        with (
            patch.object(
                server,
                "_load_or_create_helper_token",
                return_value=TEST_HELPER_TOKEN,
            ),
            patch.object(server.http.server, "HTTPServer") as http_server,
            patch("builtins.print") as print_message,
        ):
            result = server.main(["--show-token"])

        self.assertEqual(result, 0)
        print_message.assert_called_once_with(TEST_HELPER_TOKEN)
        http_server.assert_not_called()

    def test_normal_startup_never_prints_the_token(self):
        fake_server = Mock()
        fake_server.serve_forever.side_effect = KeyboardInterrupt
        accounts_file = Mock()
        accounts_file.exists.return_value = True
        with server._AUTH_CHALLENGE_LOCK:
            server._AUTH_CHALLENGES[TEST_CHALLENGE] = {
                "deadline": 999_999.0,
                "expiresAt": 999_999_000,
                "host": f"{server.HOST}:{server.PORT}",
                "origin": TEST_EXTENSION_ORIGIN,
            }
        with (
            patch.object(
                server,
                "_load_or_create_helper_token",
                return_value=TEST_HELPER_TOKEN,
            ),
            patch.object(server, "ACCOUNTS_FILE", accounts_file),
            patch.object(
                server.http.server,
                "HTTPServer",
                return_value=fake_server,
            ),
            patch("builtins.print") as print_message,
        ):
            result = server.main([])

        self.assertEqual(result, 0)
        self.assertEqual(server.HELPER_TOKEN, TEST_HELPER_TOKEN)
        self.assertEqual(server._AUTH_CHALLENGES, {})
        fake_server.serve_forever.assert_called_once_with()
        fake_server.server_close.assert_called_once_with()
        rendered = " ".join(str(call) for call in print_message.call_args_list)
        self.assertNotIn(TEST_HELPER_TOKEN, rendered)


class TokenExpiryTests(unittest.TestCase):
    def check(self, expires_at):
        with patch.object(server, "datetime", FixedDateTime):
            server._check_token_expiry({
                "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
            })

    def test_accepts_a_token_with_more_than_five_minutes_remaining(self):
        self.check(FixedDateTime.current + timedelta(minutes=6))

    def test_rejects_an_expired_token(self):
        with self.assertRaisesRegex(RuntimeError, "expired"):
            self.check(FixedDateTime.current - timedelta(seconds=1))

    def test_rejects_a_near_expiry_token_without_refreshing_cli_state(self):
        with self.assertRaisesRegex(RuntimeError, "expires within 5 minutes"):
            self.check(FixedDateTime.current + timedelta(minutes=4))

        with self.assertRaisesRegex(RuntimeError, "expires within 5 minutes"):
            self.check(FixedDateTime.current + timedelta(minutes=5))

    def test_accepts_an_expiry_with_an_explicit_utc_offset(self):
        expires_at = FixedDateTime.current + timedelta(minutes=6)
        with patch.object(server, "datetime", FixedDateTime):
            server._check_token_expiry({"expiresAt": expires_at.isoformat()})

    def test_rejects_a_cache_entry_without_an_expiry(self):
        with self.assertRaisesRegex(RuntimeError, "no expiresAt"):
            with patch.object(server, "datetime", FixedDateTime):
                server._check_token_expiry({"accessToken": "synthetic-token"})

    def test_rejects_malformed_or_timezone_free_expiry_values(self):
        for expires_at in (
            "not-a-time",
            " 2030-01-01T00:00:00Z",
            "2030-01-01T00:00:00",
            123,
        ):
            with self.subTest(expires_at=expires_at):
                with (
                    patch.object(server, "datetime", FixedDateTime),
                    self.assertRaisesRegex(RuntimeError, "expiresAt"),
                ):
                    server._check_token_expiry({"expiresAt": expires_at})


class SsoCacheSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.cache_directory = self.root / "sso-cache"
        self.cache_directory.mkdir()
        self.config_file = self.root / "config"

    def write_json(self, name, data):
        path = self.cache_directory / name
        path.write_text(json.dumps(data))
        return path

    def write_namespace_cache(self, namespace, data):
        cache_key = hashlib.sha1(
            namespace.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest()
        return self.write_json(f"{cache_key}.json", data)

    def usable_cache(
        self,
        token=TEST_ACCESS_TOKEN_ALPHA,
        start_url=TEST_START_URL_ALPHA,
        region="eu-west-1",
        expires_at="2030-01-01T00:00:00Z",
    ):
        return {
            "accessToken": token,
            "startUrl": start_url,
            "region": region,
            "expiresAt": expires_at,
        }

    def select(self, profile=None):
        with (
            patch.object(server, "AWS_CONFIG_FILE", self.config_file),
            patch.object(server, "SSO_CACHE_DIR", self.cache_directory),
            patch.object(server, "datetime", FixedDateTime),
        ):
            return server._select_sso_identity(profile)

    def test_standard_aws_config_file_override_is_honored(self):
        configured_path = self.root / "__containoodle_test_aws_config__"
        with patch.dict(
            os.environ,
            {"AWS_CONFIG_FILE": str(configured_path)},
        ):
            namespace = runpy.run_path(
                server.__file__,
                run_name="__containoodle_test_server_import__",
            )

        self.assertEqual(namespace["AWS_CONFIG_FILE"], configured_path)

    def test_resolves_modern_profile_to_the_session_cache_namespace(self):
        self.config_file.write_text(
            f"""
[profile {TEST_PROFILE_ALPHA}]
sso_session = {TEST_SESSION_ALPHA}

[sso-session {TEST_SESSION_ALPHA}]
sso_start_url = {TEST_START_URL_ALPHA}
sso_region = eu-west-1
""".strip()
        )
        expected = self.usable_cache()
        self.write_namespace_cache(TEST_SESSION_ALPHA, expected)
        self.write_namespace_cache(
            TEST_START_URL_ALPHA,
            self.usable_cache(token=TEST_ACCESS_TOKEN_BETA),
        )

        selected = self.select(TEST_PROFILE_ALPHA)

        self.assertEqual(selected["cache"], expected)
        self.assertEqual(selected["accessToken"], TEST_ACCESS_TOKEN_ALPHA)
        self.assertRegex(selected["identityKey"], r"^[0-9a-f]{64}$")

    def test_resolves_default_and_named_legacy_profiles_by_start_url(self):
        self.config_file.write_text(
            f"""
[default]
sso_start_url = {TEST_START_URL_ALPHA}
sso_region = eu-west-1

[profile {TEST_PROFILE_BETA}]
sso_start_url = {TEST_START_URL_BETA}
sso_region = eu-central-1
""".strip()
        )
        alpha = self.usable_cache()
        beta = self.usable_cache(
            token=TEST_ACCESS_TOKEN_BETA,
            start_url=TEST_START_URL_BETA,
            region="eu-central-1",
        )
        self.write_namespace_cache(TEST_START_URL_ALPHA, alpha)
        self.write_namespace_cache(TEST_START_URL_BETA, beta)

        self.assertEqual(self.select("default")["cache"], alpha)
        self.assertEqual(self.select(TEST_PROFILE_BETA)["cache"], beta)

    def test_explicit_profile_never_falls_back_to_another_cache(self):
        self.config_file.write_text(
            f"""
[profile {TEST_PROFILE_ALPHA}]
sso_session = {TEST_SESSION_ALPHA}

[sso-session {TEST_SESSION_ALPHA}]
sso_start_url = {TEST_START_URL_ALPHA}
sso_region = eu-west-1
""".strip()
        )
        self.write_json("unrelated.json", self.usable_cache())

        with self.assertRaisesRegex(
            server.SsoSelectionError,
            "selected AWS SSO login is unavailable",
        ):
            self.select(TEST_PROFILE_ALPHA)

    def test_explicit_profile_rejects_mismatched_or_unusable_exact_cache(self):
        self.config_file.write_text(
            f"""
[profile {TEST_PROFILE_ALPHA}]
sso_session = {TEST_SESSION_ALPHA}

[sso-session {TEST_SESSION_ALPHA}]
sso_start_url = {TEST_START_URL_ALPHA}
sso_region = eu-west-1
""".strip()
        )
        cases = (
            self.usable_cache(start_url=TEST_START_URL_BETA),
            self.usable_cache(region="eu-central-1"),
            self.usable_cache(token="   "),
            self.usable_cache(token=f" {TEST_ACCESS_TOKEN_ALPHA}"),
            self.usable_cache(start_url="not-an-https-url"),
            self.usable_cache(region="not-a-region"),
            self.usable_cache(expires_at="2020-01-01T00:00:00Z"),
            ["__CONTAINOODLE_TEST_NOT_AN_OBJECT__"],
        )
        cache_path = self.write_namespace_cache(TEST_SESSION_ALPHA, cases[0])

        for cache_data in cases:
            with self.subTest(cache_data=cache_data):
                cache_path.write_text(json.dumps(cache_data))
                with self.assertRaisesRegex(
                    server.SsoSelectionError,
                    "invalid or expiring soon",
                ):
                    self.select(TEST_PROFILE_ALPHA)

    def test_missing_or_invalid_profile_configuration_fails_closed(self):
        cases = (
            "",
            f"[profile {TEST_PROFILE_ALPHA}]\nsso_session = ",
            f"[profile {TEST_PROFILE_ALPHA}]\nsso_start_url = {TEST_START_URL_ALPHA}",
            "[profile broken",
        )
        for config_text in cases:
            with self.subTest(config_text=config_text):
                self.config_file.write_text(config_text)
                with self.assertRaises(server.SsoSelectionError):
                    self.select(TEST_PROFILE_ALPHA)

    def test_automatic_selection_ignores_invalid_entries_and_file_recency(self):
        expected = self.usable_cache()
        usable_path = self.write_json("usable.json", expected)
        os.utime(usable_path, (100, 100))
        expired_path = self.write_json("expired.json", self.usable_cache(
            token=TEST_ACCESS_TOKEN_BETA,
            start_url=TEST_START_URL_BETA,
            expires_at="2020-01-01T00:00:00Z",
        ))
        os.utime(expired_path, (500, 500))
        self.write_json("near-expiry.json", self.usable_cache(
            token="__CONTAINOODLE_TEST_NEAR_EXPIRY_TOKEN__",
            start_url="https://__containoodle_test_near__.invalid/start",
            expires_at="2026-07-24T10:04:00Z",
        ))
        self.write_json("registration.json", {
            "clientId": "__CONTAINOODLE_TEST_CLIENT_REGISTRATION__",
        })
        self.write_json("not-an-object.json", ["__CONTAINOODLE_TEST_VALUE__"])
        self.write_json("missing-start-url.json", {
            "accessToken": "__CONTAINOODLE_TEST_MISSING_START_URL_TOKEN__",
            "region": "eu-west-1",
            "expiresAt": "2030-01-01T00:00:00Z",
        })
        self.write_json("missing-region.json", {
            "accessToken": "__CONTAINOODLE_TEST_MISSING_REGION_TOKEN__",
            "startUrl": "https://__containoodle_test_missing_region__.invalid/start",
            "expiresAt": "2030-01-01T00:00:00Z",
        })
        self.write_json("malformed-identity.json", self.usable_cache(
            token=" __CONTAINOODLE_TEST_PADDED_TOKEN__",
            start_url="not-an-https-url",
            region="not-a-region",
        ))
        (self.cache_directory / "malformed.json").write_text("{")
        unreadable = self.write_json("unreadable.json", self.usable_cache(
            token="__CONTAINOODLE_TEST_UNREADABLE_TOKEN__",
            start_url="https://__containoodle_test_unreadable__.invalid/start",
        ))
        original_read_text = Path.read_text

        def controlled_read_text(path, *args, **kwargs):
            if path == unreadable:
                raise OSError("synthetic read failure")
            return original_read_text(path, *args, **kwargs)

        with (
            patch.object(server, "AWS_CONFIG_FILE", self.config_file),
            patch.object(server, "SSO_CACHE_DIR", self.cache_directory),
            patch.object(server, "datetime", FixedDateTime),
            patch.object(Path, "read_text", controlled_read_text),
        ):
            selected = server._select_sso_identity()

        self.assertEqual(selected["cache"], expected)

    def test_duplicate_files_for_the_exact_same_token_are_not_ambiguous(self):
        duplicate = self.usable_cache()
        self.write_json("duplicate-alpha.json", duplicate)
        self.write_json("duplicate-beta.json", duplicate)

        self.assertEqual(self.select()["cache"], duplicate)

    def test_selection_never_modifies_or_deletes_cache_files(self):
        cache_path = self.write_json("usable.json", self.usable_cache())
        before_bytes = cache_path.read_bytes()
        before_mtime = cache_path.stat().st_mtime_ns

        self.select()

        self.assertTrue(cache_path.exists())
        self.assertEqual(cache_path.read_bytes(), before_bytes)
        self.assertEqual(cache_path.stat().st_mtime_ns, before_mtime)

    def test_multiple_distinct_usable_tokens_fail_closed(self):
        self.write_json("alpha.json", self.usable_cache())
        self.write_json("beta.json", self.usable_cache(
            token=TEST_ACCESS_TOKEN_BETA,
            start_url=TEST_START_URL_BETA,
        ))

        with self.assertRaisesRegex(
            server.SsoSelectionError,
            "Multiple AWS SSO logins",
        ):
            self.select()

    def test_no_usable_token_fails_closed(self):
        self.write_json("registration.json", {
            "clientId": "__CONTAINOODLE_TEST_CLIENT_REGISTRATION__",
        })

        with self.assertRaisesRegex(
            server.SsoSelectionError,
            "Run aws sso login",
        ):
            self.select()

    def test_identity_key_is_opaque_domain_separated_and_verified(self):
        selection = {
            "identityKey": server._sso_identity_key(
                TEST_START_URL_ALPHA,
                TEST_ACCESS_TOKEN_ALPHA,
            ),
        }
        self.assertRegex(selection["identityKey"], r"^[0-9a-f]{64}$")
        self.assertNotIn(TEST_ACCESS_TOKEN_ALPHA, selection["identityKey"])
        self.assertNotEqual(
            selection["identityKey"],
            server._hmac_hex(
                "containoodle-request-v1",
                TEST_START_URL_ALPHA,
                TEST_ACCESS_TOKEN_ALPHA,
            ),
        )
        server._verify_sso_identity(selection, selection["identityKey"])
        with self.assertRaisesRegex(server.SsoSelectionError, "login changed"):
            server._verify_sso_identity(selection, "0" * 64)


class AwsCliContractTests(unittest.TestCase):
    def test_get_role_credentials_maps_the_aws_cli_response(self):
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "roleCredentials": {
                    "accessKeyId": "SYNTHETIC-ID",
                    "secretAccessKey": "SYNTHETIC-KEY",
                    "sessionToken": "SYNTHETIC-TOKEN",
                },
            }),
            stderr="",
        )

        with patch.object(server.subprocess, "run", return_value=completed) as run:
            result = server._get_role_credentials(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                TEST_ROLE_ALPHA,
                "eu-west-1",
            )

        self.assertEqual(result, {
            "sessionId": "SYNTHETIC-ID",
            "sessionKey": "SYNTHETIC-KEY",
            "sessionToken": "SYNTHETIC-TOKEN",
        })
        run.assert_called_once_with(
            [
                "aws", "sso", "get-role-credentials",
                "--access-token", "synthetic-access-token",
                "--account-id", TEST_ACCOUNT_ID,
                "--role-name", TEST_ROLE_ALPHA,
                "--region", "eu-west-1",
            ],
            capture_output=True,
            text=True,
        )

    def test_get_role_credentials_strips_and_surfaces_a_cli_failure(self):
        completed = SimpleNamespace(
            returncode=255,
            stdout="",
            stderr="  synthetic CLI failure\n",
        )

        with (
            patch.object(server.subprocess, "run", return_value=completed),
            self.assertRaisesRegex(
                RuntimeError,
                "get-role-credentials failed: synthetic CLI failure$",
            ),
        ):
            server._get_role_credentials(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                TEST_ROLE_ALPHA,
                "eu-west-1",
            )

    def test_get_role_credentials_rejects_malformed_cli_json(self):
        completed = SimpleNamespace(returncode=0, stdout="{", stderr="")

        with (
            patch.object(server.subprocess, "run", return_value=completed),
            self.assertRaises(json.JSONDecodeError),
        ):
            server._get_role_credentials(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                TEST_ROLE_ALPHA,
                "eu-west-1",
            )

    def test_list_account_roles_filters_missing_and_blank_names(self):
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "roleList": [
                    {"roleName": TEST_ROLE_ALPHA},
                    {"roleName": ""},
                    {},
                    {"roleName": TEST_ROLE_BETA},
                ],
            }),
            stderr="",
        )

        with patch.object(server.subprocess, "run", return_value=completed) as run:
            roles = server._list_account_roles(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                "eu-west-1",
            )

        self.assertEqual(roles, [TEST_ROLE_ALPHA, TEST_ROLE_BETA])
        run.assert_called_once_with(
            [
                "aws", "sso", "list-account-roles",
                "--access-token", "synthetic-access-token",
                "--account-id", TEST_ACCOUNT_ID,
                "--region", "eu-west-1",
                "--output", "json",
            ],
            capture_output=True,
            text=True,
        )

    def test_list_account_roles_defaults_to_an_empty_list(self):
        completed = SimpleNamespace(returncode=0, stdout="{}", stderr="")

        with patch.object(server.subprocess, "run", return_value=completed):
            roles = server._list_account_roles(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                "eu-west-1",
            )

        self.assertEqual(roles, [])

    def test_list_account_roles_strips_and_surfaces_a_cli_failure(self):
        completed = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=" synthetic role-list failure ",
        )

        with (
            patch.object(server.subprocess, "run", return_value=completed),
            self.assertRaisesRegex(
                RuntimeError,
                "list-account-roles failed: synthetic role-list failure$",
            ),
        ):
            server._list_account_roles(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                "eu-west-1",
            )

    def test_list_account_roles_rejects_malformed_cli_json(self):
        completed = SimpleNamespace(returncode=0, stdout="not-json", stderr="")

        with (
            patch.object(server.subprocess, "run", return_value=completed),
            self.assertRaises(json.JSONDecodeError),
        ):
            server._list_account_roles(
                "synthetic-access-token",
                TEST_ACCOUNT_ID,
                "eu-west-1",
            )


class FederationUrlTests(unittest.TestCase):
    def test_build_signin_url_round_trips_credentials_destination_and_token(self):
        credentials = {
            "sessionId": "SYNTHETIC-ID",
            "sessionKey": "SYNTHETIC-KEY",
            "sessionToken": "synthetic token +/=",
        }
        signin_token = "synthetic signin token +/="
        response = FakeUrlResponse(
            json.dumps({"SigninToken": signin_token}).encode(),
        )

        with patch.object(server.urllib.request, "urlopen", return_value=response) as urlopen:
            login_url = server._build_signin_url(credentials, "eu-west-1")

        token_url = urlopen.call_args.args[0]
        urlopen.assert_called_once_with(token_url)
        parsed_token_url = urllib.parse.urlparse(token_url)
        self.assertEqual(parsed_token_url.scheme, "https")
        self.assertEqual(parsed_token_url.netloc, "signin.aws.amazon.com")
        self.assertEqual(parsed_token_url.path, "/federation")
        token_query = urllib.parse.parse_qs(parsed_token_url.query)
        self.assertEqual(token_query["Action"], ["getSigninToken"])
        self.assertEqual(json.loads(token_query["Session"][0]), credentials)

        parsed_login_url = urllib.parse.urlparse(login_url)
        self.assertEqual(parsed_login_url.scheme, "https")
        self.assertEqual(parsed_login_url.netloc, "signin.aws.amazon.com")
        self.assertEqual(parsed_login_url.path, "/federation")
        login_query = urllib.parse.parse_qs(
            parsed_login_url.query,
            keep_blank_values=True,
        )
        self.assertEqual(login_query["Action"], ["login"])
        self.assertEqual(login_query["Issuer"], [""])
        self.assertEqual(login_query["SigninToken"], [signin_token])
        self.assertEqual(
            login_query["Destination"],
            ["https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1"],
        )

    def test_build_signin_url_propagates_a_network_failure(self):
        with (
            patch.object(
                server.urllib.request,
                "urlopen",
                side_effect=urllib.error.URLError("synthetic offline failure"),
            ) as urlopen,
            self.assertRaises(urllib.error.URLError),
        ):
            server._build_signin_url(
                {
                    "sessionId": "SYNTHETIC-ID",
                    "sessionKey": "SYNTHETIC-KEY",
                    "sessionToken": "SYNTHETIC-TOKEN",
                },
                "eu-west-1",
            )

        self.assertEqual(urlopen.call_count, 1)

    def test_build_signin_url_rejects_malformed_token_json(self):
        response = FakeUrlResponse(b"{")

        with (
            patch.object(server.urllib.request, "urlopen", return_value=response),
            self.assertRaises(json.JSONDecodeError),
        ):
            server._build_signin_url(
                {
                    "sessionId": "SYNTHETIC-ID",
                    "sessionKey": "SYNTHETIC-KEY",
                    "sessionToken": "SYNTHETIC-TOKEN",
                },
                "eu-west-1",
            )

    def test_generate_signin_url_runs_the_complete_pipeline(self):
        selection = {
            "accessToken": TEST_ACCESS_TOKEN_ALPHA,
            "identityKey": "a" * 64,
        }
        credentials = {
            "sessionId": "SYNTHETIC-ID",
            "sessionKey": "SYNTHETIC-KEY",
            "sessionToken": "SYNTHETIC-TOKEN",
        }

        with (
            patch.object(
                server,
                "_select_sso_identity",
                return_value=selection,
            ) as select_identity,
            patch.object(server, "_verify_sso_identity") as verify_identity,
            patch.object(
                server,
                "_get_role_credentials",
                return_value=credentials,
            ) as get_credentials,
            patch.object(
                server,
                "_build_signin_url",
                return_value="https://signin.aws.amazon.com/synthetic-login",
            ) as build_url,
        ):
            result = server.generate_signin_url(
                TEST_ACCOUNT_ID,
                TEST_ROLE_ALPHA,
                "eu-west-1",
                TEST_PROFILE_ALPHA,
                "a" * 64,
            )

        self.assertEqual(result, "https://signin.aws.amazon.com/synthetic-login")
        select_identity.assert_called_once_with(TEST_PROFILE_ALPHA)
        verify_identity.assert_called_once_with(selection, "a" * 64)
        get_credentials.assert_called_once_with(
            TEST_ACCESS_TOKEN_ALPHA,
            TEST_ACCOUNT_ID,
            TEST_ROLE_ALPHA,
            "eu-west-1",
        )
        build_url.assert_called_once_with(credentials, "eu-west-1")

    def test_generate_signin_url_stops_when_selection_fails(self):
        with (
            patch.object(
                server,
                "_select_sso_identity",
                side_effect=server.SsoSelectionError(
                    "__CONTAINOODLE_TEST_SELECTION_FAILURE__"
                ),
            ),
            patch.object(server, "_get_role_credentials") as get_credentials,
            patch.object(server, "_build_signin_url") as build_url,
            self.assertRaisesRegex(
                server.SsoSelectionError,
                "__CONTAINOODLE_TEST_SELECTION_FAILURE__",
            ),
        ):
            server.generate_signin_url(
                TEST_ACCOUNT_ID,
                TEST_ROLE_ALPHA,
                "eu-west-1",
            )

        get_credentials.assert_not_called()
        build_url.assert_not_called()

    def test_build_container_url_round_trips_name_and_signin_url(self):
        signin_url = (
            "https://signin.aws.amazon.com/federation"
            "?Action=login&SigninToken=synthetic%20token"
        )
        result = server._build_container_url("Team & QA", signin_url)
        prefix, encoded_signin_url = result.split("&url=", 1)

        self.assertEqual(prefix, "ext+container:name=Team%20%26%20QA")
        self.assertEqual(urllib.parse.unquote(encoded_signin_url), signin_url)


class AccountMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.accounts_file = Path(self.temporary_directory.name) / "accounts.json"

    def test_get_account_meta_returns_the_exact_matching_account(self):
        expected = {
            "accountId": TEST_ACCOUNT_ID,
            "accountName": "synthetic-shared",
            "role": TEST_ROLE_ALPHA,
            "region": "eu-west-1",
        }
        self.accounts_file.write_text(json.dumps([
            expected,
            {"accountId": TEST_OTHER_ACCOUNT_ID, "accountName": "synthetic-other"},
        ]))
        handler = RecordingHandler()

        with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
            self.assertEqual(handler._get_account_meta(TEST_ACCOUNT_ID), expected)
            self.assertIsNone(handler._get_account_meta(TEST_UNKNOWN_ACCOUNT_ID))

    def test_get_account_meta_treats_missing_or_invalid_json_as_unavailable(self):
        handler = RecordingHandler()

        with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
            self.assertIsNone(handler._get_account_meta(TEST_ACCOUNT_ID))
            self.accounts_file.write_text("{")
            self.assertIsNone(handler._get_account_meta(TEST_ACCOUNT_ID))


class HandlerTransportTests(unittest.TestCase):
    def setUp(self):
        with server._AUTH_CHALLENGE_LOCK:
            server._AUTH_CHALLENGES.clear()

    def test_host_policy_requires_the_exact_bound_loopback_authority(self):
        self.assertTrue(RecordingHandler()._check_host())

        for host in (
            None,
            "localhost:8421",
            "127.0.0.1",
            "synthetic-rebind.invalid:8421",
        ):
            with self.subTest(host=host):
                rejected = RecordingHandler(host=host)
                self.assertFalse(rejected._check_host())
                self.assertEqual(rejected.response_status, 403)
                self.assertEqual(
                    rejected.error,
                    (403, "Forbidden: invalid Host header"),
                )

        duplicate = RecordingHandler()
        duplicate.headers["Host"] = f"{server.HOST}:{server.PORT}"
        self.assertFalse(duplicate._check_host())
        self.assertEqual(duplicate.response_status, 403)

    def test_origin_policy_allows_extension_or_no_origin_and_rejects_web_origins(self):
        self.assertTrue(RecordingHandler()._check_origin())
        self.assertTrue(
            RecordingHandler(origin=TEST_EXTENSION_ORIGIN)._check_origin(),
        )

        for origin in (
            "https://example.invalid",
            "moz-extension://synthetic-extension-id/path",
            "moz-extension://",
        ):
            with self.subTest(origin=origin):
                rejected = RecordingHandler(origin=origin)
                self.assertFalse(rejected._check_origin())
                self.assertEqual(rejected.response_status, 403)
                self.assertEqual(
                    rejected.error,
                    (403, "Forbidden: cross-origin request"),
                )

        duplicate = RecordingHandler(origin=TEST_EXTENSION_ORIGIN)
        duplicate.headers["Origin"] = TEST_EXTENSION_ORIGIN
        self.assertFalse(duplicate._check_origin())
        self.assertEqual(duplicate.response_status, 403)

    def test_request_proof_is_single_use_and_legacy_authorization_is_rejected(self):
        target = f"/roles?account={TEST_ACCOUNT_ID}"
        accepted = RecordingHandler(path=target, origin=TEST_EXTENSION_ORIGIN)
        self.assertTrue(accepted._check_request_auth(target, TEST_EXTENSION_ORIGIN))
        self.assertIsNotNone(accepted._response_auth)

        replay = RecordingHandler(
            path=target,
            origin=TEST_EXTENSION_ORIGIN,
            authenticated=False,
        )
        replay.headers[server._CHALLENGE_HEADER] = accepted.headers[
            server._CHALLENGE_HEADER
        ]
        replay.headers[server._REQUEST_PROOF_HEADER] = accepted.headers[
            server._REQUEST_PROOF_HEADER
        ]
        self.assertFalse(replay._check_request_auth(target, TEST_EXTENSION_ORIGIN))
        self.assertEqual(replay.response_status, 401)
        self.assertEqual(replay.json_body(), {"error": "Authentication required"})
        self.assertNotIn(server._RESPONSE_PROOF_HEADER, replay.header_values())

        legacy = RecordingHandler(
            path=target,
            origin=TEST_EXTENSION_ORIGIN,
            authorization=f"Bearer {TEST_HELPER_TOKEN}",
        )
        self.assertFalse(legacy._check_request_auth(target, TEST_EXTENSION_ORIGIN))
        self.assertEqual(legacy.response_status, 401)
        self.assertNotIn("WWW-Authenticate", legacy.header_values())
        self.assertNotIn(TEST_HELPER_TOKEN, legacy.wfile.getvalue().decode())

    def test_request_proof_comparison_runs_for_missing_malformed_and_wrong_proofs(self):
        target = "/accounts"
        for case in ("missing", "malformed", "wrong"):
            with self.subTest(case=case):
                handler = RecordingHandler(path=target)
                if case == "missing":
                    del handler.headers[server._REQUEST_PROOF_HEADER]
                elif case == "malformed":
                    handler.headers.replace_header(
                        server._REQUEST_PROOF_HEADER,
                        "not-a-proof",
                    )
                else:
                    proof = handler.headers[server._REQUEST_PROOF_HEADER]
                    handler.headers.replace_header(
                        server._REQUEST_PROOF_HEADER,
                        ("1" if proof[0] != "1" else "2") + proof[1:],
                    )
                with patch.object(
                    server.hmac,
                    "compare_digest",
                    wraps=server.hmac.compare_digest,
                ) as compare_digest:
                    self.assertFalse(handler._check_request_auth(target, "-"))
                compare_digest.assert_called_once()
                self.assertEqual(handler.response_status, 401)
                self.assertNotIn(
                    server._RESPONSE_PROOF_HEADER,
                    handler.header_values(),
                )

    def test_duplicate_auth_headers_fail_without_consuming_the_challenge(self):
        for duplicated_header in (
            server._CHALLENGE_HEADER,
            server._REQUEST_PROOF_HEADER,
        ):
            with self.subTest(duplicated_header=duplicated_header):
                handler = RecordingHandler(
                    path="/accounts",
                    origin=TEST_EXTENSION_ORIGIN,
                )
                challenge = handler.headers[server._CHALLENGE_HEADER]
                handler.headers[duplicated_header] = handler.headers[
                    duplicated_header
                ]

                self.assertFalse(
                    handler._check_request_auth(
                        "/accounts",
                        TEST_EXTENSION_ORIGIN,
                    )
                )
                self.assertEqual(handler.response_status, 401)
                self.assertIn(challenge, server._AUTH_CHALLENGES)

    def test_send_json_sets_transport_security_and_extension_cors_headers(self):
        handler = RecordingHandler(origin=TEST_EXTENSION_ORIGIN)
        payload = {"ok": True, "roles": [TEST_ROLE_ALPHA]}

        handler._send_json(payload, 201)

        expected_body = json.dumps(payload).encode()
        headers = handler.header_values()
        self.assertEqual(handler.response_status, 201)
        self.assertTrue(handler.response_ended)
        self.assertEqual(handler.wfile.getvalue(), expected_body)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Content-Length"], str(len(expected_body)))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(
            headers["Access-Control-Allow-Origin"],
            TEST_EXTENSION_ORIGIN,
        )
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, OPTIONS")
        self.assertEqual(
            headers["Access-Control-Allow-Headers"],
            "X-Containoodle-Challenge, X-Containoodle-Request-Proof",
        )
        self.assertEqual(
            headers["Access-Control-Expose-Headers"],
            "X-Containoodle-Response-Proof",
        )
        self.assertEqual(headers["Vary"], "Origin")

    def test_send_json_omits_cors_headers_without_an_origin(self):
        handler = RecordingHandler()

        handler._send_json({"ok": True})

        self.assertEqual(handler.response_status, 200)
        headers = handler.header_values()
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertNotIn("Access-Control-Allow-Methods", headers)
        self.assertNotIn("Access-Control-Allow-Headers", headers)

    def test_options_allows_extension_origins_and_rejects_other_callers(self):
        allowed = RecordingHandler(
            origin=TEST_EXTENSION_ORIGIN,
            command="OPTIONS",
            authenticated=False,
        )
        allowed.headers["Access-Control-Request-Method"] = "GET"
        allowed.headers["Access-Control-Request-Headers"] = (
            "x-containoodle-request-proof, x-containoodle-challenge"
        )
        allowed.do_OPTIONS()

        self.assertEqual(allowed.response_status, 204)
        self.assertTrue(allowed.response_ended)
        self.assertEqual(allowed.wfile.getvalue(), b"")
        self.assertEqual(allowed.header_values(), {
            "Access-Control-Allow-Origin": TEST_EXTENSION_ORIGIN,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": (
                "X-Containoodle-Challenge, X-Containoodle-Request-Proof"
            ),
            "Access-Control-Expose-Headers": "X-Containoodle-Response-Proof",
            "Access-Control-Max-Age": "600",
            "Cache-Control": "no-store",
            "Vary": "Origin",
        })

        for origin in (None, "https://example.invalid"):
            with self.subTest(origin=origin):
                rejected = RecordingHandler(
                    origin=origin,
                    command="OPTIONS",
                    authenticated=False,
                )
                rejected.do_OPTIONS()
                self.assertEqual(rejected.response_status, 403)
                self.assertIsNotNone(rejected.error)

        rejected_host = RecordingHandler(
            origin=TEST_EXTENSION_ORIGIN,
            command="OPTIONS",
            host="synthetic-rebind.invalid:8421",
            authenticated=False,
        )
        rejected_host.do_OPTIONS()
        self.assertEqual(rejected_host.response_status, 403)
        self.assertEqual(
            rejected_host.error,
            (403, "Forbidden: invalid Host header"),
        )

        invalid_preflights = (
            ("POST", "x-containoodle-challenge, x-containoodle-request-proof"),
            ("GET", "authorization"),
            ("GET", "x-containoodle-challenge"),
        )
        for method, requested_headers in invalid_preflights:
            with self.subTest(method=method, requested_headers=requested_headers):
                rejected = RecordingHandler(
                    origin=TEST_EXTENSION_ORIGIN,
                    command="OPTIONS",
                    authenticated=False,
                )
                rejected.headers["Access-Control-Request-Method"] = method
                rejected.headers[
                    "Access-Control-Request-Headers"
                ] = requested_headers
                rejected.do_OPTIONS()
                self.assertEqual(rejected.response_status, 403)

    def test_access_log_strips_the_complete_query_string(self):
        handler = RecordingHandler(
            path=(
                f"/generate-url?account={TEST_ACCOUNT_ID}"
                "&SigninToken=must-not-appear"
            ),
        )

        with patch("builtins.print") as print_message:
            handler.log_request(200)

        print_message.assert_called_once_with("  GET /generate-url → 200")


class HelperHmacProtocolTests(unittest.TestCase):
    def setUp(self):
        with server._AUTH_CHALLENGE_LOCK:
            server._AUTH_CHALLENGES.clear()

    def test_python_javascript_canonical_proof_vectors(self):
        host = "127.0.0.1:8421"
        origin = TEST_EXTENSION_ORIGIN
        target = (
            f"/generate-url?account={TEST_ACCOUNT_ID}"
            "&role=__CONTAINOODLE_TEST_ROLE__"
        )
        body = b'{"ok":true}'

        self.assertEqual(
            server._server_proof(TEST_CHALLENGE, 2_000_000_030_000, host, origin),
            "3a65edaffa3b75c35fd50b08cd767f2f230d26731b84b0d63436da4c9cf3fd93",
        )
        self.assertEqual(
            server._request_proof(TEST_CHALLENGE, "GET", target, host, origin),
            "c6782764d40751c6e26ea3ec9a5555b54e93471075a619106739f5e9a236ed65",
        )
        self.assertEqual(
            server._response_proof(
                TEST_CHALLENGE,
                200,
                target,
                body,
                host,
                origin,
            ),
            "cf971959cbc2a14a3c224a20f3f55f248b4012672121b78155b70153d08d6a7a",
        )

    def test_independently_calculated_authentication_vectors(self):
        key_token = "A" * 43
        challenge = f"E{'A' * 42}"
        expires_at = 2_000_000_000_000
        host = "127.0.0.1:8421"
        origin = "moz-extension://containoodle-test"
        target = f"/roles?account={TEST_ACCOUNT_ID}"
        body = b'{"ok":true}'

        with patch.object(server, "HELPER_TOKEN", key_token):
            self.assertEqual(
                server._server_proof(challenge, expires_at, host, origin),
                "9daaa0c5cf0423e064008d04d556d583cbe1a85d49686a2fb3ac95b82d9965f7",
            )
            self.assertEqual(
                server._request_proof(challenge, "GET", target, host, origin),
                "b720c08ea0105097044bb6b4dda370f8821672d1fcd2701644d19f58b49670f3",
            )
            self.assertEqual(
                hashlib.sha256(body).hexdigest(),
                "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",
            )
            self.assertEqual(
                server._response_proof(
                    challenge,
                    200,
                    target,
                    body,
                    host,
                    origin,
                ),
                "ebbf1fe5a09a44e2fb4be869f3302d3412e01e246e0b7dc562bf5aa466e761ff",
            )

    def test_challenge_route_returns_only_a_bound_server_proof(self):
        accounts_file = Mock()
        handler = RecordingHandler(
            path=server._AUTH_CHALLENGE_PATH,
            origin=TEST_EXTENSION_ORIGIN,
            authenticated=False,
        )
        with (
            patch.object(server, "ACCOUNTS_FILE", accounts_file),
            patch.object(server.secrets, "token_urlsafe", return_value=TEST_CHALLENGE),
            patch.object(server.time, "time", return_value=2_000_000_000.0),
            patch.object(server.time, "monotonic", return_value=100.0),
            patch.object(server, "_select_sso_identity") as select_identity,
            patch.object(server, "generate_signin_url") as generate_url,
        ):
            handler.do_GET()

        self.assertEqual(handler.response_status, 200)
        self.assertEqual(handler.json_body(), {
            "version": 1,
            "challenge": TEST_CHALLENGE,
            "expiresAt": 2_000_000_030_000,
            "serverProof": (
                "3a65edaffa3b75c35fd50b08cd767f2f"
                "230d26731b84b0d63436da4c9cf3fd93"
            ),
        })
        headers = handler.header_values()
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Access-Control-Allow-Origin"], TEST_EXTENSION_ORIGIN)
        self.assertNotIn(server._RESPONSE_PROOF_HEADER, headers)
        self.assertNotIn("Authorization", str(headers))
        rendered = handler.wfile.getvalue().decode() + str(headers)
        self.assertNotIn(TEST_HELPER_TOKEN, rendered)
        accounts_file.read_text.assert_not_called()
        select_identity.assert_not_called()
        generate_url.assert_not_called()
        self.assertIn(TEST_CHALLENGE, server._AUTH_CHALLENGES)

    def test_challenge_route_rejects_bad_bindings_without_allocating(self):
        cases = (
            {
                "name": "foreign host",
                "handler": RecordingHandler(
                    path=server._AUTH_CHALLENGE_PATH,
                    host="synthetic-rebind.invalid:8421",
                    authenticated=False,
                ),
            },
            {
                "name": "foreign origin",
                "handler": RecordingHandler(
                    path=server._AUTH_CHALLENGE_PATH,
                    origin="https://example.invalid",
                    authenticated=False,
                ),
            },
            {
                "name": "query string",
                "handler": RecordingHandler(
                    path=f"{server._AUTH_CHALLENGE_PATH}?unexpected=1",
                    origin=TEST_EXTENSION_ORIGIN,
                    authenticated=False,
                ),
            },
        )
        duplicate_origin = RecordingHandler(
            path=server._AUTH_CHALLENGE_PATH,
            origin=TEST_EXTENSION_ORIGIN,
            authenticated=False,
        )
        duplicate_origin.headers["Origin"] = TEST_EXTENSION_ORIGIN
        cases += ({"name": "duplicate origin", "handler": duplicate_origin},)

        for case in cases:
            with self.subTest(case=case["name"]):
                with server._AUTH_CHALLENGE_LOCK:
                    server._AUTH_CHALLENGES.clear()
                with patch.object(server.secrets, "token_urlsafe") as random_token:
                    case["handler"].do_GET()
                self.assertIn(case["handler"].response_status, (403, 404))
                random_token.assert_not_called()
                self.assertEqual(server._AUTH_CHALLENGES, {})

    def test_no_origin_challenge_uses_the_dash_binding(self):
        handler = RecordingHandler(
            path=server._AUTH_CHALLENGE_PATH,
            authenticated=False,
        )
        with patch.object(
            server.secrets,
            "token_urlsafe",
            return_value=TEST_CHALLENGE,
        ):
            handler.do_GET()

        payload = handler.json_body()
        self.assertEqual(
            payload["serverProof"],
            server._server_proof(
                payload["challenge"],
                payload["expiresAt"],
                f"{server.HOST}:{server.PORT}",
                "-",
            ),
        )
        self.assertNotIn("Access-Control-Allow-Origin", handler.header_values())

    def test_challenge_state_is_bounded_fifo_and_prunes_expiry(self):
        challenges = [
            _test_base64url(index.to_bytes(32, "big"))
            for index in range(server._AUTH_CHALLENGE_LIMIT + 2)
        ]
        with (
            patch.object(server.secrets, "token_urlsafe", side_effect=challenges),
            patch.object(server.time, "monotonic", return_value=100.0),
            patch.object(server.time, "time", return_value=2_000_000_000.0),
        ):
            for _ in range(server._AUTH_CHALLENGE_LIMIT + 1):
                server._issue_auth_challenge(
                    f"{server.HOST}:{server.PORT}",
                    TEST_EXTENSION_ORIGIN,
                )

        self.assertEqual(len(server._AUTH_CHALLENGES), server._AUTH_CHALLENGE_LIMIT)
        self.assertNotIn(challenges[0], server._AUTH_CHALLENGES)
        self.assertIn(challenges[1], server._AUTH_CHALLENGES)

        with (
            patch.object(server.secrets, "token_urlsafe", return_value=challenges[-1]),
            patch.object(server.time, "monotonic", return_value=131.0),
        ):
            server._issue_auth_challenge(
                f"{server.HOST}:{server.PORT}",
                TEST_EXTENSION_ORIGIN,
            )
        self.assertEqual(list(server._AUTH_CHALLENGES), [challenges[-1]])

    def test_target_and_origin_tampering_does_not_consume_the_challenge(self):
        target = f"/roles?account={TEST_ACCOUNT_ID}"
        handler = RecordingHandler(path=target, origin=TEST_EXTENSION_ORIGIN)
        challenge = handler.headers[server._CHALLENGE_HEADER]
        proof = handler.headers[server._REQUEST_PROOF_HEADER]

        self.assertIsNone(server._consume_auth_challenge(
            challenge,
            proof,
            "GET",
            f"/accounts?account={TEST_ACCOUNT_ID}",
            f"{server.HOST}:{server.PORT}",
            TEST_EXTENSION_ORIGIN,
        ))
        self.assertIsNone(server._consume_auth_challenge(
            challenge,
            proof,
            "GET",
            target,
            f"{server.HOST}:{server.PORT}",
            "moz-extension://different-synthetic-origin",
        ))
        self.assertIn(challenge, server._AUTH_CHALLENGES)
        self.assertEqual(
            server._consume_auth_challenge(
                challenge,
                proof,
                "GET",
                target,
                f"{server.HOST}:{server.PORT}",
                TEST_EXTENSION_ORIGIN,
            ),
            challenge,
        )

    def test_expired_challenge_is_rejected_and_removed(self):
        with patch.object(server.time, "monotonic", return_value=100.0):
            handler = RecordingHandler(path="/accounts")
        challenge = handler.headers[server._CHALLENGE_HEADER]
        proof = handler.headers[server._REQUEST_PROOF_HEADER]

        with patch.object(server.time, "monotonic", return_value=131.0):
            self.assertIsNone(server._consume_auth_challenge(
                challenge,
                proof,
                "GET",
                "/accounts",
                f"{server.HOST}:{server.PORT}",
                "-",
            ))
        self.assertNotIn(challenge, server._AUTH_CHALLENGES)

    def test_concurrent_replay_allows_exactly_one_consumer(self):
        handler = RecordingHandler(path="/accounts")
        challenge = handler.headers[server._CHALLENGE_HEADER]
        proof = handler.headers[server._REQUEST_PROOF_HEADER]
        start = threading.Barrier(2)
        results = []

        def consume():
            start.wait(timeout=5)
            results.append(server._consume_auth_challenge(
                challenge,
                proof,
                "GET",
                "/accounts",
                f"{server.HOST}:{server.PORT}",
                "-",
            ))

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(results.count(challenge), 1)
        self.assertEqual(results.count(None), 1)

    def test_valid_proof_is_consumed_before_route_validation(self):
        target = "/roles?account=not-an-account"
        accepted = RecordingHandler(path=target, origin=TEST_EXTENSION_ORIGIN)
        challenge = accepted.headers[server._CHALLENGE_HEADER]
        proof = accepted.headers[server._REQUEST_PROOF_HEADER]
        accepted.do_GET()
        self.assertEqual(accepted.response_status, 400)
        self.assertIn(server._RESPONSE_PROOF_HEADER, accepted.header_values())

        replay = RecordingHandler(
            path=target,
            origin=TEST_EXTENSION_ORIGIN,
            authenticated=False,
        )
        replay.headers[server._CHALLENGE_HEADER] = challenge
        replay.headers[server._REQUEST_PROOF_HEADER] = proof
        replay.do_GET()
        self.assertEqual(replay.response_status, 401)
        self.assertEqual(replay.json_body(), {"error": "Authentication required"})
        self.assertNotIn(server._RESPONSE_PROOF_HEADER, replay.header_values())

    def test_response_proof_binds_status_target_body_host_and_origin(self):
        target = f"/roles?account={TEST_ACCOUNT_ID}"
        body = b'{"ok":true}'
        host = f"{server.HOST}:{server.PORT}"
        proof = server._response_proof(
            TEST_CHALLENGE,
            200,
            target,
            body,
            host,
            TEST_EXTENSION_ORIGIN,
        )
        variants = (
            (201, target, body, host, TEST_EXTENSION_ORIGIN),
            (200, "/accounts", body, host, TEST_EXTENSION_ORIGIN),
            (200, target, b'{"ok":false}', host, TEST_EXTENSION_ORIGIN),
            (200, target, body, "127.0.0.1:9999", TEST_EXTENSION_ORIGIN),
            (200, target, body, host, "moz-extension://different-synthetic-origin"),
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotEqual(
                    server._response_proof(
                        TEST_CHALLENGE,
                        variant[0],
                        variant[1],
                        variant[2],
                        variant[3],
                        variant[4],
                    ),
                    proof,
                )


class HandlerRouteTests(unittest.TestCase):
    def setUp(self):
        with server._AUTH_CHALLENGE_LOCK:
            server._AUTH_CHALLENGES.clear()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.accounts_file = Path(self.temporary_directory.name) / "accounts.json"

    def assert_json_response(self, handler, status, body):
        self.assertIsNone(handler.error)
        self.assertEqual(handler.response_status, status)
        self.assertEqual(handler.json_body(), body)
        response_auth = getattr(handler, "_response_auth", None)
        if response_auth:
            self.assertEqual(
                handler.header_values()[server._RESPONSE_PROOF_HEADER],
                server._response_proof(
                    response_auth["challenge"],
                    status,
                    response_auth["target"],
                    handler.wfile.getvalue(),
                    response_auth["host"],
                    response_auth["origin"],
                ),
            )

    def test_every_supported_get_route_rejects_a_foreign_origin_first(self):
        for path in (
            "/accounts",
            "/sso-identity",
            f"/roles?account={TEST_ACCOUNT_ID}",
            f"/generate-url?account={TEST_ACCOUNT_ID}",
        ):
            with self.subTest(path=path):
                accounts_file = Mock()
                handler = RecordingHandler(path=path, origin="https://example.invalid")
                with (
                    patch.object(server, "ACCOUNTS_FILE", accounts_file),
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                    ) as get_account_meta,
                ):
                    handler.do_GET()

                self.assertEqual(
                    handler.error,
                    (403, "Forbidden: cross-origin request"),
                )
                self.assertEqual(handler.response_status, 403)
                accounts_file.read_text.assert_not_called()
                get_account_meta.assert_not_called()

    def test_every_supported_get_route_rejects_auth_before_side_effects(self):
        for auth_case in ("missing", "malformed", "wrong"):
            for path in (
                "/accounts",
                "/sso-identity",
                f"/roles?account={TEST_ACCOUNT_ID}",
                f"/generate-url?account={TEST_ACCOUNT_ID}",
            ):
                with self.subTest(auth_case=auth_case, path=path):
                    accounts_file = Mock()
                    handler = RecordingHandler(
                        path=path,
                        origin=TEST_EXTENSION_ORIGIN,
                    )
                    if auth_case == "missing":
                        del handler.headers[server._CHALLENGE_HEADER]
                        del handler.headers[server._REQUEST_PROOF_HEADER]
                    elif auth_case == "malformed":
                        handler.headers.replace_header(
                            server._REQUEST_PROOF_HEADER,
                            "not-a-proof",
                        )
                    else:
                        proof = handler.headers[server._REQUEST_PROOF_HEADER]
                        handler.headers.replace_header(
                            server._REQUEST_PROOF_HEADER,
                            ("1" if proof[0] != "1" else "2") + proof[1:],
                        )
                    with (
                        patch.object(server, "ACCOUNTS_FILE", accounts_file),
                        patch.object(
                            server.ContainoodleHandler,
                            "_get_account_meta",
                        ) as get_account_meta,
                        patch.object(
                            server,
                            "_select_sso_identity",
                        ) as select_identity,
                        patch.object(server, "generate_signin_url") as generate_url,
                    ):
                        handler.do_GET()

                    self.assert_json_response(
                        handler,
                        401,
                        {"error": "Authentication required"},
                    )
                    accounts_file.read_text.assert_not_called()
                    get_account_meta.assert_not_called()
                    select_identity.assert_not_called()
                    generate_url.assert_not_called()
                    self.assertNotIn(
                        server._RESPONSE_PROOF_HEADER,
                        handler.header_values(),
                    )

    def test_supported_routes_reject_a_rebound_host_before_auth_or_filesystem(self):
        accounts_file = Mock()
        handler = RecordingHandler(
            path="/accounts",
            host="synthetic-rebind.invalid:8421",
            authorization=None,
        )

        with patch.object(server, "ACCOUNTS_FILE", accounts_file):
            handler.do_GET()

        self.assertEqual(handler.response_status, 403)
        self.assertEqual(
            handler.error,
            (403, "Forbidden: invalid Host header"),
        )
        accounts_file.read_text.assert_not_called()

    def test_accounts_route_returns_the_stored_document(self):
        accounts = [
            {
                "accountId": TEST_ACCOUNT_ID,
                "accountName": "synthetic-shared",
                "region": "eu-west-1",
            },
        ]
        self.accounts_file.write_text(json.dumps(accounts))
        handler = RecordingHandler(
            path="/accounts",
            origin="moz-extension://synthetic-extension-id",
        )

        with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
            handler.do_GET()

        self.assert_json_response(handler, 200, accounts)
        self.assertEqual(
            handler.header_values()["Access-Control-Allow-Origin"],
            "moz-extension://synthetic-extension-id",
        )

    def test_accounts_route_allows_authenticated_no_origin_clients(self):
        accounts = [{
            "accountId": TEST_ACCOUNT_ID,
            "accountName": "synthetic-command-line-account",
        }]
        self.accounts_file.write_text(json.dumps(accounts))
        handler = RecordingHandler(path="/accounts", origin=None)

        with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
            handler.do_GET()

        self.assert_json_response(handler, 200, accounts)
        self.assertNotIn(
            "Access-Control-Allow-Origin",
            handler.header_values(),
        )

    def test_accounts_route_reports_missing_and_invalid_json(self):
        with self.subTest(case="missing"):
            handler = RecordingHandler(path="/accounts")
            with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
                handler.do_GET()
            self.assert_json_response(
                handler,
                404,
                {"error": "accounts.json not found"},
            )

        with self.subTest(case="invalid"):
            self.accounts_file.write_text("{")
            handler = RecordingHandler(path="/accounts")
            with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
                handler.do_GET()
            self.assert_json_response(
                handler,
                500,
                {"error": "accounts.json is invalid"},
            )

    def test_sso_identity_route_returns_only_the_opaque_identity_key(self):
        identity_key = "a" * 64
        target = "/sso-identity?" + urllib.parse.urlencode({
            "profile": TEST_PROFILE_ALPHA,
        })
        handler = RecordingHandler(path=target)
        selection = {
            "accessToken": TEST_ACCESS_TOKEN_ALPHA,
            "identityKey": identity_key,
            "cache": {
                "startUrl": TEST_START_URL_ALPHA,
                "region": "eu-west-1",
            },
        }

        with patch.object(
            server,
            "_select_sso_identity",
            return_value=selection,
        ) as select_identity:
            handler.do_GET()

        self.assert_json_response(handler, 200, {
            "ok": True,
            "identityKey": identity_key,
        })
        select_identity.assert_called_once_with(TEST_PROFILE_ALPHA)
        rendered = handler.wfile.getvalue().decode()
        self.assertNotIn(TEST_PROFILE_ALPHA, rendered)
        self.assertNotIn(TEST_ACCESS_TOKEN_ALPHA, rendered)
        self.assertNotIn(TEST_START_URL_ALPHA, rendered)

    def test_sso_identity_route_rejects_bad_profile_values_before_selection(self):
        cases = (
            ("profile=", "Invalid AWS CLI profile selection"),
            ("profile=alpha&profile=beta", "Invalid request parameters"),
            ("profile=%0A", "Invalid AWS CLI profile selection"),
        )
        for query, public_message in cases:
            with self.subTest(query=query):
                handler = RecordingHandler(path=f"/sso-identity?{query}")
                with patch.object(
                    server,
                    "_select_sso_identity",
                ) as select_identity:
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    400,
                    {"error": public_message},
                )
                select_identity.assert_not_called()

    def test_routes_reject_unknown_or_duplicate_parameters_before_route_work(self):
        cases = (
            "/accounts?profile=__CONTAINOODLE_TEST_PROFILE__",
            "/sso-identity?unknown=__CONTAINOODLE_TEST_VALUE__",
            (
                f"/roles?account={TEST_ACCOUNT_ID}"
                f"&account={TEST_OTHER_ACCOUNT_ID}"
            ),
            (
                f"/generate-url?account={TEST_ACCOUNT_ID}"
                f"&role={TEST_ROLE_ALPHA}&role={TEST_ROLE_BETA}"
            ),
        )
        for path in cases:
            with self.subTest(path=path):
                handler = RecordingHandler(path=path)
                with (
                    patch.object(server, "ACCOUNTS_FILE") as accounts_file,
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                    ) as get_account_meta,
                    patch.object(
                        server,
                        "_select_sso_identity",
                    ) as select_identity,
                    patch.object(server, "generate_signin_url") as generate_url,
                ):
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    400,
                    {"error": "Invalid request parameters"},
                )
                accounts_file.read_text.assert_not_called()
                get_account_meta.assert_not_called()
                select_identity.assert_not_called()
                generate_url.assert_not_called()

    def test_sso_identity_route_returns_sanitized_selection_failures(self):
        cases = (
            (
                server.SsoSelectionError(
                    "Multiple AWS SSO logins were found. Choose an AWS CLI profile."
                ),
                409,
                "Multiple AWS SSO logins were found. Choose an AWS CLI profile.",
            ),
            (
                TypeError("__CONTAINOODLE_TEST_PRIVATE_FAILURE__"),
                500,
                "Unexpected error selecting AWS SSO login",
            ),
        )
        for error, status, public_message in cases:
            with self.subTest(error=type(error).__name__):
                handler = RecordingHandler(path="/sso-identity")
                with patch.object(
                    server,
                    "_select_sso_identity",
                    side_effect=error,
                ):
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    status,
                    {"error": public_message},
                )
                self.assertNotIn(
                    "__CONTAINOODLE_TEST_PRIVATE_FAILURE__",
                    handler.wfile.getvalue().decode(),
                )

    def test_roles_route_rejects_missing_or_invalid_account_ids(self):
        for path in (
            "/roles",
            "/roles?account=123",
            "/roles?account=not-an-account",
        ):
            with self.subTest(path=path):
                handler = RecordingHandler(path=path)
                with patch.object(
                    server.ContainoodleHandler,
                    "_get_account_meta",
                ) as get_account_meta:
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    400,
                    {"error": "Invalid or missing account ID (expected 12-digit number)"},
                )
                get_account_meta.assert_not_called()

    def test_roles_route_rejects_unknown_accounts_and_invalid_regions(self):
        with self.subTest(case="unknown account"):
            handler = RecordingHandler(path=f"/roles?account={TEST_ACCOUNT_ID}")
            with patch.object(
                server.ContainoodleHandler,
                "_get_account_meta",
                return_value=None,
            ):
                handler.do_GET()
            self.assert_json_response(
                handler,
                404,
                {"error": "Account not found in accounts.json"},
            )

        with self.subTest(case="invalid region"):
            handler = RecordingHandler(path=f"/roles?account={TEST_ACCOUNT_ID}")
            with (
                patch.object(
                    server.ContainoodleHandler,
                    "_get_account_meta",
                    return_value={
                        "accountId": TEST_ACCOUNT_ID,
                        "region": "invalid-region",
                    },
                ),
                patch.object(server, "_select_sso_identity") as select_identity,
            ):
                handler.do_GET()
            self.assert_json_response(
                handler,
                400,
                {"error": "Invalid region in account config"},
            )
            select_identity.assert_not_called()

    def test_roles_route_lists_roles_with_account_or_default_region(self):
        selection = {
            "accessToken": TEST_ACCESS_TOKEN_ALPHA,
            "identityKey": "a" * 64,
        }
        cases = (
            (
                {"accountId": TEST_ACCOUNT_ID, "region": "eu-central-1"},
                "eu-central-1",
            ),
            ({"accountId": TEST_ACCOUNT_ID}, "ap-southeast-2"),
        )

        for account_meta, expected_region in cases:
            with self.subTest(expected_region=expected_region):
                handler = RecordingHandler(path=f"/roles?account={TEST_ACCOUNT_ID}")
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                        return_value=account_meta,
                    ),
                    patch.object(server, "DEFAULT_REGION", "ap-southeast-2"),
                    patch.object(
                        server,
                        "_select_sso_identity",
                        return_value=selection,
                    ) as select_identity,
                    patch.object(
                        server,
                        "_verify_sso_identity",
                    ) as verify_identity,
                    patch.object(
                        server,
                        "_list_account_roles",
                        return_value=[TEST_ROLE_ALPHA, TEST_ROLE_BETA],
                    ) as list_roles,
                ):
                    handler.do_GET()

                self.assert_json_response(handler, 200, {
                    "ok": True,
                    "roles": [TEST_ROLE_ALPHA, TEST_ROLE_BETA],
                })
                select_identity.assert_called_once_with(None)
                verify_identity.assert_called_once_with(selection, None)
                list_roles.assert_called_once_with(
                    TEST_ACCESS_TOKEN_ALPHA,
                    TEST_ACCOUNT_ID,
                    expected_region,
                )

    def test_roles_route_binds_profile_and_expected_identity_before_aws_work(self):
        identity_key = "a" * 64
        target = "/roles?" + urllib.parse.urlencode({
            "account": TEST_ACCOUNT_ID,
            "profile": TEST_PROFILE_ALPHA,
            "identity": identity_key,
        })
        selection = {
            "accessToken": TEST_ACCESS_TOKEN_ALPHA,
            "identityKey": identity_key,
        }
        handler = RecordingHandler(path=target)
        with (
            patch.object(
                server.ContainoodleHandler,
                "_get_account_meta",
                return_value={"accountId": TEST_ACCOUNT_ID},
            ),
            patch.object(
                server,
                "_select_sso_identity",
                return_value=selection,
            ) as select_identity,
            patch.object(
                server,
                "_verify_sso_identity",
                wraps=server._verify_sso_identity,
            ) as verify_identity,
            patch.object(
                server,
                "_list_account_roles",
                return_value=[TEST_ROLE_ALPHA],
            ) as list_roles,
        ):
            handler.do_GET()

        self.assert_json_response(handler, 200, {
            "ok": True,
            "roles": [TEST_ROLE_ALPHA],
        })
        select_identity.assert_called_once_with(TEST_PROFILE_ALPHA)
        verify_identity.assert_called_once_with(selection, identity_key)
        list_roles.assert_called_once_with(
            TEST_ACCESS_TOKEN_ALPHA,
            TEST_ACCOUNT_ID,
            server.DEFAULT_REGION,
        )

    def test_roles_route_stops_before_aws_work_when_identity_changed(self):
        expected_identity = "a" * 64
        selection = {
            "accessToken": TEST_ACCESS_TOKEN_ALPHA,
            "identityKey": "b" * 64,
        }
        target = "/roles?" + urllib.parse.urlencode({
            "account": TEST_ACCOUNT_ID,
            "identity": expected_identity,
        })
        handler = RecordingHandler(path=target)
        with (
            patch.object(
                server.ContainoodleHandler,
                "_get_account_meta",
                return_value={"accountId": TEST_ACCOUNT_ID},
            ),
            patch.object(
                server,
                "_select_sso_identity",
                return_value=selection,
            ),
            patch.object(server, "_list_account_roles") as list_roles,
        ):
            handler.do_GET()

        self.assert_json_response(handler, 409, {
            "error": (
                "The AWS SSO login changed. Refresh the selected identity "
                "and try again."
            ),
        })
        list_roles.assert_not_called()

    def test_roles_route_rejects_malformed_selectors_before_account_or_aws_work(self):
        cases = (
            (
                f"/roles?account={TEST_ACCOUNT_ID}&profile=",
                "Invalid AWS SSO selection",
            ),
            (
                f"/roles?account={TEST_ACCOUNT_ID}&identity=not-an-identity",
                "Invalid AWS SSO selection",
            ),
            ((
                f"/roles?account={TEST_ACCOUNT_ID}"
                f"&profile={TEST_PROFILE_ALPHA}&profile={TEST_PROFILE_BETA}"
            ), "Invalid request parameters"),
        )
        for path, public_message in cases:
            with self.subTest(path=path):
                handler = RecordingHandler(path=path)
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                    ) as get_account_meta,
                    patch.object(
                        server,
                        "_select_sso_identity",
                    ) as select_identity,
                ):
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    400,
                    {"error": public_message},
                )
                get_account_meta.assert_not_called()
                select_identity.assert_not_called()

    def test_roles_route_sanitizes_expected_and_unexpected_failures(self):
        cases = (
            (
                RuntimeError("synthetic token failure"),
                "Failed to list roles. Is your SSO token valid?",
            ),
            (
                ValueError("synthetic unexpected failure"),
                "Unexpected error listing roles",
            ),
        )
        for error, public_message in cases:
            with self.subTest(error=type(error).__name__):
                handler = RecordingHandler(path=f"/roles?account={TEST_ACCOUNT_ID}")
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                        return_value={"accountId": TEST_ACCOUNT_ID},
                    ),
                    patch.object(server, "_select_sso_identity", side_effect=error),
                ):
                    handler.do_GET()

                self.assert_json_response(handler, 500, {"error": public_message})

    def test_generate_url_route_rejects_missing_or_invalid_account_ids(self):
        for path in (
            "/generate-url",
            "/generate-url?account=123",
            "/generate-url?account=not-an-account",
        ):
            with self.subTest(path=path):
                handler = RecordingHandler(path=path)
                with patch.object(
                    server.ContainoodleHandler,
                    "_get_account_meta",
                ) as get_account_meta:
                    handler.do_GET()

                self.assert_json_response(
                    handler,
                    400,
                    {"error": "Invalid or missing account ID (expected 12-digit number)"},
                )
                get_account_meta.assert_not_called()

    def test_generate_url_route_rejects_unknown_accounts(self):
        handler = RecordingHandler(path=f"/generate-url?account={TEST_ACCOUNT_ID}")
        with patch.object(
            server.ContainoodleHandler,
            "_get_account_meta",
            return_value=None,
        ):
            handler.do_GET()

        self.assert_json_response(
            handler,
            404,
            {"error": "Account not found in accounts.json"},
        )

    def test_generate_url_route_rejects_invalid_role_or_region(self):
        cases = (
            (
                f"/generate-url?account={TEST_ACCOUNT_ID}&role=invalid%20role",
                {"accountId": TEST_ACCOUNT_ID, "region": "eu-west-1"},
                "Invalid role name in account config",
            ),
            (
                f"/generate-url?account={TEST_ACCOUNT_ID}",
                {
                    "accountId": TEST_ACCOUNT_ID,
                    "role": TEST_ROLE_ALPHA,
                    "region": "invalid-region",
                },
                "Invalid region in account config",
            ),
        )
        for path, metadata, public_message in cases:
            with self.subTest(public_message=public_message):
                handler = RecordingHandler(path=path)
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                        return_value=metadata,
                    ),
                    patch.object(server, "generate_signin_url") as generate_url,
                ):
                    handler.do_GET()

                self.assert_json_response(handler, 400, {"error": public_message})
                generate_url.assert_not_called()

    def test_generate_url_route_applies_role_and_metadata_precedence(self):
        cases = (
            {
                "name": "query role wins",
                "path": (
                    f"/generate-url?account={TEST_ACCOUNT_ID}"
                    f"&role={TEST_ROLE_QUERY}"
                ),
                "metadata": {
                    "accountId": TEST_ACCOUNT_ID,
                    "accountName": "synthetic-shared",
                    "role": TEST_ROLE_ALPHA,
                    "region": "eu-central-1",
                },
                "expected_role": TEST_ROLE_QUERY,
                "expected_region": "eu-central-1",
                "expected_name": "synthetic-shared",
            },
            {
                "name": "account role wins over default",
                "path": f"/generate-url?account={TEST_ACCOUNT_ID}",
                "metadata": {
                    "accountId": TEST_ACCOUNT_ID,
                    "accountName": "synthetic-shared",
                    "role": TEST_ROLE_ALPHA,
                    "region": "eu-central-1",
                },
                "expected_role": TEST_ROLE_ALPHA,
                "expected_region": "eu-central-1",
                "expected_name": "synthetic-shared",
            },
            {
                "name": "module defaults fill missing metadata",
                "path": f"/generate-url?account={TEST_ACCOUNT_ID}",
                "metadata": {"accountId": TEST_ACCOUNT_ID},
                "expected_role": TEST_ROLE_DEFAULT,
                "expected_region": "ap-southeast-2",
                "expected_name": TEST_ACCOUNT_ID,
            },
        )

        for case in cases:
            with self.subTest(case=case["name"]):
                handler = RecordingHandler(path=case["path"])
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                        return_value=case["metadata"],
                    ),
                    patch.object(server, "DEFAULT_ROLE", TEST_ROLE_DEFAULT),
                    patch.object(server, "DEFAULT_REGION", "ap-southeast-2"),
                    patch.object(
                        server,
                        "generate_signin_url",
                        return_value="https://signin.aws.amazon.com/synthetic-login",
                    ) as generate_url,
                    patch.object(
                        server,
                        "_build_container_url",
                        return_value="ext+container:synthetic",
                    ) as build_container,
                ):
                    handler.do_GET()

                generate_url.assert_called_once_with(
                    TEST_ACCOUNT_ID,
                    case["expected_role"],
                    case["expected_region"],
                    None,
                    None,
                )
                build_container.assert_called_once_with(
                    case["expected_name"],
                    "https://signin.aws.amazon.com/synthetic-login",
                )
                self.assert_json_response(handler, 200, {
                    "ok": True,
                    "containerUrl": "ext+container:synthetic",
                    "account": case["expected_name"],
                })

    def test_generate_url_route_forwards_profile_and_expected_identity(self):
        identity_key = "a" * 64
        target = "/generate-url?" + urllib.parse.urlencode({
            "account": TEST_ACCOUNT_ID,
            "role": TEST_ROLE_QUERY,
            "profile": TEST_PROFILE_ALPHA,
            "identity": identity_key,
        })
        handler = RecordingHandler(path=target)
        with (
            patch.object(
                server.ContainoodleHandler,
                "_get_account_meta",
                return_value={
                    "accountId": TEST_ACCOUNT_ID,
                    "accountName": "__CONTAINOODLE_TEST_ACCOUNT_NAME__",
                    "region": "eu-west-1",
                },
            ),
            patch.object(
                server,
                "generate_signin_url",
                return_value="https://signin.aws.amazon.com/synthetic-login",
            ) as generate_url,
            patch.object(
                server,
                "_build_container_url",
                return_value="ext+container:synthetic",
            ),
        ):
            handler.do_GET()

        generate_url.assert_called_once_with(
            TEST_ACCOUNT_ID,
            TEST_ROLE_QUERY,
            "eu-west-1",
            TEST_PROFILE_ALPHA,
            identity_key,
        )
        self.assert_json_response(handler, 200, {
            "ok": True,
            "containerUrl": "ext+container:synthetic",
            "account": "__CONTAINOODLE_TEST_ACCOUNT_NAME__",
        })

    def test_generate_url_route_returns_actionable_selection_failure(self):
        handler = RecordingHandler(
            path=f"/generate-url?account={TEST_ACCOUNT_ID}",
        )
        public_message = (
            "Multiple AWS SSO logins were found. Choose an AWS CLI profile."
        )
        with (
            patch.object(
                server.ContainoodleHandler,
                "_get_account_meta",
                return_value={
                    "accountId": TEST_ACCOUNT_ID,
                    "role": TEST_ROLE_ALPHA,
                    "region": "eu-west-1",
                },
            ),
            patch.object(
                server,
                "generate_signin_url",
                side_effect=server.SsoSelectionError(public_message),
            ),
        ):
            handler.do_GET()

        self.assert_json_response(
            handler,
            409,
            {"error": public_message},
        )

    def test_generate_url_route_sanitizes_expected_and_unexpected_failures(self):
        cases = (
            (
                RuntimeError("synthetic SSO failure"),
                "Failed to generate session. Is your SSO token valid?",
            ),
            (
                ValueError("synthetic unexpected failure"),
                "Unexpected error generating session",
            ),
        )
        for error, public_message in cases:
            with self.subTest(error=type(error).__name__):
                handler = RecordingHandler(
                    path=f"/generate-url?account={TEST_ACCOUNT_ID}",
                )
                with (
                    patch.object(
                        server.ContainoodleHandler,
                        "_get_account_meta",
                        return_value={
                            "accountId": TEST_ACCOUNT_ID,
                            "role": TEST_ROLE_ALPHA,
                            "region": "eu-west-1",
                        },
                    ),
                    patch.object(server, "generate_signin_url", side_effect=error),
                ):
                    handler.do_GET()

                self.assert_json_response(handler, 500, {"error": public_message})

    def test_unknown_and_removed_legacy_routes_remain_unavailable(self):
        for path in ("/", "/open", "/static/app.js", "/missing"):
            with self.subTest(path=path):
                handler = RecordingHandler(path=path)
                handler.do_GET()
                self.assertEqual(handler.response_status, 404)
                self.assertEqual(handler.error, (404, None))

if __name__ == "__main__":
    unittest.main()
