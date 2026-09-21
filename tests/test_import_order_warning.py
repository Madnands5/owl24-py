"""Launch backlog item 7 (2026-09-20): a transitive import of fastapi/flask
before Owl24.init() runs leaves auto-instrumentation silently inactive - no
error, no broken-looking behavior, just no traces. This is the
loud-detection half of that fix: warn at init() time rather than build a
bootstrap launcher.

Why this checks a captured snapshot rather than live sys.modules: this
SDK's own module-level setup (_AUTO_INSTRUMENTORS in telemetry.py) already
imports fastapi/flask as a side effect of importing their OTel instrumentor
packages, regardless of what the customer's code does - verified live, a
process that does nothing but `from owl24_py import Owl24` already has both
in sys.modules by the time that import finishes. A naive `name in
sys.modules` check would therefore fire on every single init() call. These
tests exist specifically to pin that distinction down, not just the happy
path - see test_true_positive_and_true_negative_against_a_real_subprocess
for the actual end-to-end proof, not just a monkeypatched unit.

Run directly: `python tests/test_import_order_warning.py`.
"""
import contextlib
import io
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from owl24_py import telemetry  # noqa: E402


class TestImportOrderWarningUnit(unittest.TestCase):
    """Fast unit tests against the pure decision function, with
    _MODULES_PRESENT_BEFORE_OWL24_IMPORT monkeypatched directly - no
    subprocess needed to check the warning's own text/logic."""

    def setUp(self):
        self._saved_snapshot = telemetry._MODULES_PRESENT_BEFORE_OWL24_IMPORT

    def tearDown(self):
        telemetry._MODULES_PRESENT_BEFORE_OWL24_IMPORT = self._saved_snapshot

    def _capture(self, pre_existing_modules):
        telemetry._MODULES_PRESENT_BEFORE_OWL24_IMPORT = frozenset(pre_existing_modules)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            telemetry._warn_if_framework_already_imported()
        return buf.getvalue()

    def test_silent_when_snapshot_is_empty(self):
        self.assertEqual(self._capture(set()), "")

    def test_silent_when_snapshot_has_unrelated_modules(self):
        self.assertEqual(self._capture({"os", "sys", "json"}), "")

    def test_warns_when_fastapi_is_in_the_pre_import_snapshot(self):
        output = self._capture({"fastapi"})
        self.assertIn("fastapi", output)
        self.assertIn("WARNING", output)
        self.assertIn("Owl24.init()", output)

    def test_names_both_frameworks_when_both_are_present(self):
        output = self._capture({"fastapi", "flask"})
        self.assertIn("fastapi", output)
        self.assertIn("flask", output)

    def test_does_not_warn_about_django_or_requests(self):
        # Scoped to fastapi/flask only - see telemetry.py's own comment on
        # why django/requests/DB drivers don't share this specific footgun
        # (they patch free functions, not a singleton app instance).
        output = self._capture({"django", "requests", "psycopg2"})
        self.assertEqual(output, "")


class TestImportOrderWarningRealSubprocess(unittest.TestCase):
    """The unit tests above prove the decision function is correct in
    isolation, but the bug this whole feature exists to catch is a REAL
    false-positive risk from this SDK's own import machinery (see module
    docstring) - a monkeypatched unit test could not have caught that, since
    it never actually imports fastapi through the real _AUTO_INSTRUMENTORS
    path. These run actual subprocesses to prove both directions against
    the genuine import mechanics, not a mock of them."""

    def _run(self, code):
        src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONPATH": src_dir},
        )
        return result.stderr

    def test_well_ordered_import_stays_silent_despite_owl24s_own_side_effect_import(self):
        # This is the exact false-positive scenario that made the first
        # version of this feature wrong: owl24_py's own import already pulls
        # fastapi into sys.modules, but no app has been constructed and the
        # customer did nothing wrong - must stay silent.
        stderr = self._run(
            "from owl24_py import Owl24\n"
            "Owl24.init('fake-key', 'smoke-test')\n"
        )
        self.assertNotIn("already imported before Owl24.init()", stderr)

    def test_transitive_import_before_owl24_triggers_the_warning(self):
        # Simulates the real documented footgun: some other import (a stand-
        # in for an auth helper) pulls in fastapi before owl24_py is ever
        # imported.
        stderr = self._run(
            "import fastapi\n"  # stand-in for a transitive import\n"
            "from owl24_py import Owl24\n"
            "Owl24.init('fake-key', 'smoke-test')\n"
        )
        self.assertIn("WARNING: fastapi already imported before Owl24.init()", stderr)


if __name__ == "__main__":
    unittest.main()
