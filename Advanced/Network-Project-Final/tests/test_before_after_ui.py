import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class BeforeAfterComparisonUITests(unittest.TestCase):
    def test_comparison_panel_and_controls_exist(self):
        html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        for element_id in (
            "beforeAfterComparison", "comparisonDomain", "captureBefore",
            "runAfterComparison", "clearComparison", "beforeDetails",
            "afterDetails", "comparisonDelta",
        ):
            self.assertIn(f'id="{element_id}"', html)

    def test_comparison_uses_live_resolver_and_persists_baseline(self):
        html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("api('/api/resolve',{domain})", html)
        self.assertIn("COMPARISON_STORAGE_KEY", html)
        self.assertIn("localStorage.setItem", html)
        self.assertIn("localStorage.getItem", html)
        self.assertIn("restoreComparisonBaseline();refresh()", html)

    def test_comparison_distinguishes_policy_decision_from_cache_source(self):
        html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("function comparisonDecision(event)", html)
        self.assertIn("source==='UPSTREAM'||source==='CACHE'", html)
        self.assertIn("TTL نیز", html)

if __name__ == "__main__":
    unittest.main()
