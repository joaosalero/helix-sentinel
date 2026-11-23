"""Regression coverage for synthetic seeder output without a running API."""

from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

SEEDER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "seed-demo-events.py"
SPEC = importlib.util.spec_from_file_location("helix_demo_seeder", SEEDER_PATH)
assert SPEC is not None and SPEC.loader is not None
SEEDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEEDER)


class DemoSeederOutputTests(unittest.TestCase):
    """Keep the printed event identity aligned with the ingestion response."""

    def test_reports_normalized_ids_that_alert_matches_reference(self) -> None:
        responses = [
            {
                "raw_event_id": str(UUID(int=index + 100)),
                "normalized_event_id": str(UUID(int=index + 1)),
            }
            for index in range(len(SEEDER.EVENTS))
        ]
        output = io.StringIO()
        with (
            patch.dict("os.environ", HELIX_API_TOKEN="synthetic-test-token"),
            patch.object(SEEDER, "API_BASE_URL", "http://localhost:8000/api/v1"),
            patch.object(SEEDER, "_post_event", side_effect=responses) as post_event,
            redirect_stdout(output),
        ):
            result = SEEDER.main()

        self.assertEqual(result, 0)
        self.assertEqual(post_event.call_count, len(SEEDER.EVENTS))
        rendered = output.getvalue()
        for response in responses:
            self.assertIn(f"accepted as {response['normalized_event_id']}", rendered)
            self.assertNotIn(response["raw_event_id"], rendered)
        self.assertNotIn("accepted as unknown", rendered)

    def test_missing_normalized_id_uses_explicit_unknown_fallback(self) -> None:
        output = io.StringIO()
        with (
            patch.dict("os.environ", HELIX_API_TOKEN="synthetic-test-token"),
            patch.object(SEEDER, "API_BASE_URL", "http://localhost:8000/api/v1"),
            patch.object(SEEDER, "_post_event", return_value={"raw_event_id": "raw-only"}),
            redirect_stdout(output),
        ):
            self.assertEqual(SEEDER.main(), 0)

        self.assertEqual(output.getvalue().count("accepted as unknown"), len(SEEDER.EVENTS))
        self.assertNotIn("accepted as raw-only", output.getvalue())


    def test_missing_token_stops_before_post(self) -> None:
        with (
            patch.dict("os.environ", HELIX_API_TOKEN=""),
            patch.object(SEEDER, "_post_event") as post,
        ):
            self.assertEqual(SEEDER.main(), 1)
            post.assert_not_called()

    def test_refuses_nonlocal_destinations(self) -> None:
        with self.assertRaises(SystemExit):
            SEEDER._validated_endpoint("https://example.test/api/v1/events/ingest")

    def test_authenticated_post_stops_on_redirect_without_forwarding_token(self) -> None:
        endpoint = SEEDER._validated_endpoint("http://127.0.0.1:8000/api/v1/events/ingest")
        with patch.object(SEEDER.http.client, "HTTPConnection") as connect:
            connection = connect.return_value
            connection.getresponse.return_value.status = 307
            with self.assertRaises(SystemExit):
                SEEDER._post_event(endpoint, SEEDER.EVENTS[0], "synthetic-test-token")
            connect.assert_called_once_with("127.0.0.1", port=8000, timeout=10)
            connection.request.assert_called_once()
            headers = connection.request.call_args.kwargs["headers"]
            self.assertEqual(headers["Authorization"], "Bearer synthetic-test-token")
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
