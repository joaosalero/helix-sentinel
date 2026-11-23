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
            patch.object(SEEDER, "API_BASE_URL", "http://localhost:8000/api/v1"),
            patch.object(SEEDER, "_post_event", return_value={"raw_event_id": "raw-only"}),
            redirect_stdout(output),
        ):
            self.assertEqual(SEEDER.main(), 0)

        self.assertEqual(output.getvalue().count("accepted as unknown"), len(SEEDER.EVENTS))
        self.assertNotIn("accepted as raw-only", output.getvalue())


if __name__ == "__main__":
    unittest.main()
