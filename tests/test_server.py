import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import server


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


if __name__ == "__main__":
    unittest.main()
