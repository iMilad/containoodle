import io
import json
import os
import tempfile
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


_GUARD_DIRECTORY = None
_GUARD_PATCHERS = []


def setUpModule():
    """Fail closed if a test reaches the user's AWS state or external I/O."""
    global _GUARD_DIRECTORY
    _GUARD_DIRECTORY = tempfile.TemporaryDirectory()
    safe_root = Path(_GUARD_DIRECTORY.name)
    _GUARD_PATCHERS.extend([
        patch.object(server, "ACCOUNTS_FILE", safe_root / "accounts.json"),
        patch.object(server, "SSO_CACHE_DIR", safe_root / "sso-cache"),
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

    def __init__(self, path="/", origin=None, command="GET"):
        self.path = path
        self.command = command
        self.headers = Message()
        if origin is not None:
            self.headers["Origin"] = origin
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

    def test_accepts_an_expiry_with_an_explicit_utc_offset(self):
        expires_at = FixedDateTime.current + timedelta(minutes=6)
        with patch.object(server, "datetime", FixedDateTime):
            server._check_token_expiry({"expiresAt": expires_at.isoformat()})

    def test_rejects_a_cache_entry_without_an_expiry(self):
        with self.assertRaisesRegex(RuntimeError, "no expiresAt"):
            with patch.object(server, "datetime", FixedDateTime):
                server._check_token_expiry({"accessToken": "synthetic-token"})


class SsoCacheSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.cache_directory = Path(self.temporary_directory.name)

    def write_json(self, name, data, modified_at):
        path = self.cache_directory / name
        path.write_text(json.dumps(data))
        os.utime(path, (modified_at, modified_at))
        return path

    def test_selects_the_most_recent_token_file_and_skips_other_json(self):
        self.write_json(
            "older-token.json",
            {"accessToken": "synthetic-older", "expiresAt": "2030-01-01T00:00:00Z"},
            100,
        )
        expected = {
            "accessToken": "synthetic-newer",
            "expiresAt": "2030-01-02T00:00:00Z",
        }
        self.write_json("newer-token.json", expected, 200)
        self.write_json("newest-without-token.json", {"clientId": "synthetic"}, 400)
        invalid = self.cache_directory / "invalid.json"
        invalid.write_text("{")
        os.utime(invalid, (500, 500))

        with patch.object(server, "SSO_CACHE_DIR", self.cache_directory):
            self.assertEqual(server._find_sso_cache_file(), expected)

    def test_skips_an_unreadable_candidate(self):
        unreadable = self.write_json(
            "unreadable.json",
            {"accessToken": "must-not-be-returned"},
            300,
        )
        expected = {"accessToken": "synthetic-readable"}
        self.write_json("readable.json", expected, 200)
        original_read_text = Path.read_text

        def controlled_read_text(path, *args, **kwargs):
            if path == unreadable:
                raise OSError("synthetic read failure")
            return original_read_text(path, *args, **kwargs)

        with (
            patch.object(server, "SSO_CACHE_DIR", self.cache_directory),
            patch.object(Path, "read_text", controlled_read_text),
        ):
            self.assertEqual(server._find_sso_cache_file(), expected)

    def test_raises_when_no_token_candidate_exists(self):
        self.write_json("client-registration.json", {"clientId": "synthetic"}, 100)

        with (
            patch.object(server, "SSO_CACHE_DIR", self.cache_directory),
            self.assertRaisesRegex(RuntimeError, "aws sso login"),
        ):
            server._find_sso_cache_file()


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
        cache = {
            "accessToken": "synthetic-access-token",
            "expiresAt": "2030-01-01T00:00:00Z",
        }
        credentials = {
            "sessionId": "SYNTHETIC-ID",
            "sessionKey": "SYNTHETIC-KEY",
            "sessionToken": "SYNTHETIC-TOKEN",
        }

        with (
            patch.object(server, "_find_sso_cache_file", return_value=cache) as find_cache,
            patch.object(server, "_check_token_expiry") as check_expiry,
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
            )

        self.assertEqual(result, "https://signin.aws.amazon.com/synthetic-login")
        find_cache.assert_called_once_with()
        check_expiry.assert_called_once_with(cache)
        get_credentials.assert_called_once_with(
            "synthetic-access-token",
            TEST_ACCOUNT_ID,
            TEST_ROLE_ALPHA,
            "eu-west-1",
        )
        build_url.assert_called_once_with(credentials, "eu-west-1")

    def test_generate_signin_url_stops_when_expiry_validation_fails(self):
        cache = {
            "accessToken": "synthetic-access-token",
            "expiresAt": "2020-01-01T00:00:00Z",
        }

        with (
            patch.object(server, "_find_sso_cache_file", return_value=cache),
            patch.object(
                server,
                "_check_token_expiry",
                side_effect=RuntimeError("synthetic expired token"),
            ),
            patch.object(server, "_get_role_credentials") as get_credentials,
            patch.object(server, "_build_signin_url") as build_url,
            self.assertRaisesRegex(RuntimeError, "synthetic expired token"),
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
    def test_origin_policy_allows_extension_or_no_origin_and_rejects_web_origins(self):
        self.assertTrue(RecordingHandler()._check_origin())
        self.assertTrue(
            RecordingHandler(origin="moz-extension://synthetic-extension-id")._check_origin(),
        )

        rejected = RecordingHandler(origin="https://example.invalid")
        self.assertFalse(rejected._check_origin())
        self.assertEqual(rejected.response_status, 403)
        self.assertEqual(rejected.error, (403, "Forbidden: cross-origin request"))

    def test_send_json_sets_transport_security_and_extension_cors_headers(self):
        handler = RecordingHandler(origin="moz-extension://synthetic-extension-id")
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
            "moz-extension://synthetic-extension-id",
        )
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, OPTIONS")
        self.assertEqual(headers["Access-Control-Allow-Headers"], "Content-Type")

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
            origin="moz-extension://synthetic-extension-id",
            command="OPTIONS",
        )
        allowed.do_OPTIONS()

        self.assertEqual(allowed.response_status, 204)
        self.assertTrue(allowed.response_ended)
        self.assertEqual(allowed.wfile.getvalue(), b"")
        self.assertEqual(allowed.header_values(), {
            "Access-Control-Allow-Origin": "moz-extension://synthetic-extension-id",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "86400",
        })

        for origin in (None, "https://example.invalid"):
            with self.subTest(origin=origin):
                rejected = RecordingHandler(origin=origin, command="OPTIONS")
                rejected.do_OPTIONS()
                self.assertEqual(rejected.response_status, 403)
                self.assertEqual(rejected.error, (403, None))

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


class HandlerRouteTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.accounts_file = Path(self.temporary_directory.name) / "accounts.json"

    def assert_json_response(self, handler, status, body):
        self.assertIsNone(handler.error)
        self.assertEqual(handler.response_status, status)
        self.assertEqual(handler.json_body(), body)

    def test_every_supported_get_route_rejects_a_foreign_origin_first(self):
        for path in (
            "/accounts",
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
            path="/accounts?ignored=1",
            origin="moz-extension://synthetic-extension-id",
        )

        with patch.object(server, "ACCOUNTS_FILE", self.accounts_file):
            handler.do_GET()

        self.assert_json_response(handler, 200, accounts)
        self.assertEqual(
            handler.header_values()["Access-Control-Allow-Origin"],
            "moz-extension://synthetic-extension-id",
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
                patch.object(server, "_find_sso_cache_file") as find_cache,
            ):
                handler.do_GET()
            self.assert_json_response(
                handler,
                400,
                {"error": "Invalid region in account config"},
            )
            find_cache.assert_not_called()

    def test_roles_route_lists_roles_with_account_or_default_region(self):
        cache = {
            "accessToken": "synthetic-access-token",
            "expiresAt": "2030-01-01T00:00:00Z",
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
                    patch.object(server, "_find_sso_cache_file", return_value=cache),
                    patch.object(server, "_check_token_expiry") as check_expiry,
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
                check_expiry.assert_called_once_with(cache)
                list_roles.assert_called_once_with(
                    "synthetic-access-token",
                    TEST_ACCOUNT_ID,
                    expected_region,
                )

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
                    patch.object(server, "_find_sso_cache_file", side_effect=error),
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
