"""
tests/test_agents.py — Unit tests for TruthLens AI agents

Run with:  python manage.py test tests.test_agents
"""
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")


from django.test import TestCase


class TestContentAgent(TestCase):
    def setUp(self):
        from agents.content_agent import ContentAnalysisAgent
        self.agent = ContentAnalysisAgent(provider="mock")

    def test_clean_content_scores_low(self):
        result = self.agent._timed_analyze(
            text="The Tanzanian government has announced new infrastructure investment plans."
        )
        self.assertTrue(result.success)
        self.assertLessEqual(result.score, 40)

    def test_scam_content_scores_high(self):
        result = self.agent._timed_analyze(
            text="Congratulations! You have won a prize. Send money via M-Pesa now. Act now — limited time offer!"
        )
        self.assertTrue(result.success)
        self.assertGreater(result.score, 50)

    def test_no_content_fails(self):
        result = self.agent._timed_analyze(text="", url="")
        self.assertFalse(result.success)


class TestURLAgent(TestCase):
    def setUp(self):
        from agents.url_agent import URLAnalysisAgent
        self.agent = URLAnalysisAgent(provider="mock")

    def test_https_legitimate_domain_scores_low(self):
        result = self.agent._timed_analyze(url="https://www.google.com")
        self.assertTrue(result.success)
        self.assertLessEqual(result.score, 30)

    def test_http_suspicious_domain(self):
        result = self.agent._timed_analyze(url="http://paypal-secure-login.xyz/verify")
        self.assertTrue(result.success)
        self.assertGreater(result.score, 40)

    def test_no_url_fails(self):
        result = self.agent._timed_analyze(url="")
        self.assertFalse(result.success)

    def test_ip_address_url_scores_high(self):
        result = self.agent._timed_analyze(url="http://192.168.1.100/login")
        self.assertTrue(result.success)
        self.assertGreater(result.score, 30)

    def test_brand_impersonation_detected(self):
        result = self.agent._timed_analyze(url="https://paypal-support.clickme.top/verify")
        self.assertTrue(result.success)
        self.assertIn("is_brand_impersonation_suspected", result.data)


class TestScamAgent(TestCase):
    def setUp(self):
        from agents.scam_agent import ScamDetectionAgent
        self.agent = ScamDetectionAgent(provider="mock")

    def test_fake_scholarship_detected(self):
        text = "APPLY NOW! Fully funded scholarship, no requirements, no exam. Contact us on WhatsApp immediately."
        result = self.agent._timed_analyze(text=text)
        self.assertTrue(result.success)
        self.assertIn("fake_scholarship", result.data.get("detected_categories", {}))
        self.assertGreater(result.score, 50)

    def test_investment_scam_detected(self):
        text = "Invest $100 and earn $1000 weekly. Guaranteed profit. Double your money today!"
        result = self.agent._timed_analyze(text=text)
        self.assertTrue(result.success)
        self.assertIn("investment_scam", result.data.get("detected_categories", {}))

    def test_phishing_detected(self):
        text = "Click here to verify your account. Your account will be suspended if you don't confirm."
        result = self.agent._timed_analyze(text=text)
        self.assertTrue(result.success)
        self.assertIn("phishing", result.data.get("detected_categories", {}))

    def test_clean_content_no_matches(self):
        text = "The National Bureau of Statistics has published the 2024 economic report."
        result = self.agent._timed_analyze(text=text)
        self.assertTrue(result.success)
        self.assertEqual(result.score, 0)


class TestRiskAgent(TestCase):
    def setUp(self):
        from agents.risk_agent import RiskAssessmentAgent
        self.agent = RiskAssessmentAgent(provider="mock")

    def test_high_scores_give_high_risk(self):
        result = self.agent._timed_analyze(
            content_score=85,
            url_score=80,
            scam_score=90,
            community_score=0,
            scam_category="investment_scam",
            content_findings=["Urgency language detected"],
        )
        self.assertTrue(result.success)
        self.assertGreater(result.score, 65)

    def test_low_scores_give_low_risk(self):
        result = self.agent._timed_analyze(
            content_score=5,
            url_score=0,
            scam_score=0,
            community_score=0,
        )
        self.assertTrue(result.success)
        self.assertLessEqual(result.score, 30)

    def test_result_has_recommendation(self):
        result = self.agent._timed_analyze(content_score=70, url_score=60, scam_score=75)
        self.assertIn("recommendation", result.data)
        self.assertTrue(len(result.data["recommendation"]) > 0)


class TestOrchestrator(TestCase):
    def test_full_pipeline_text(self):
        from agents.orchestrator import AnalysisOrchestrator
        orch = AnalysisOrchestrator(provider="mock")
        result = orch.run(text="Congratulations! You won TZS 1,000,000. Send registration fee first.")
        self.assertTrue(result["success"])
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)
        self.assertIn("threat_category", result)
        self.assertIn("explanation", result)
        self.assertIn("recommendation", result)
        self.assertIsInstance(result["risk_score"], int)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_full_pipeline_url(self):
        from agents.orchestrator import AnalysisOrchestrator
        orch = AnalysisOrchestrator(provider="mock")
        result = orch.run(url="http://paypal-login.xyz/verify-account")
        self.assertTrue(result["success"])
        self.assertIn("url_analysis_data", result)
        self.assertIsNotNone(result["url_analysis_data"])

    def test_full_pipeline_text_and_url(self):
        from agents.orchestrator import AnalysisOrchestrator
        orch = AnalysisOrchestrator(provider="mock")
        result = orch.run(
            text="Click the link to claim your scholarship",
            url="http://scholarship-apply-now.top/claim",
        )
        self.assertTrue(result["success"])
        self.assertIn("key_findings", result)


# ---------------------------------------------------------------------------
# Provider injection tests
# ---------------------------------------------------------------------------

class TestContentAgentProviderInjection(TestCase):
    """Verify that ContentAnalysisAgent accepts and uses an injected provider."""

    def _make_mock_provider(self):
        from services.ai_provider import MockAIProvider, ProviderConfig
        cfg = ProviderConfig(provider_name="mock", api_key="", url="", project_id="")
        return MockAIProvider(cfg)

    def test_injected_provider_is_used(self):
        from agents.content_agent import ContentAnalysisAgent
        mock_p = self._make_mock_provider()
        agent = ContentAnalysisAgent(ai_provider=mock_p)
        result = agent._timed_analyze(text="Send money now! Act immediately!")
        self.assertTrue(result.success)
        self.assertEqual(result.provider, "mock")

    def test_blend_weight_override(self):
        """Setting CONTENT_AI_WEIGHT=0.0 means pattern score drives result."""
        from agents.content_agent import ContentAnalysisAgent
        from django.test import override_settings
        with override_settings(CONTENT_AI_WEIGHT=0.0):
            agent = ContentAnalysisAgent(ai_provider=self._make_mock_provider())
            result = agent._timed_analyze(
                text="Pay registration fee via M-Pesa immediately. Act now!"
            )
            self.assertTrue(result.success)
            # With AI weight=0, only pattern_score drives combined_score
            self.assertGreater(result.score, 0)

    def test_confidence_within_bounds(self):
        from agents.content_agent import ContentAnalysisAgent
        agent = ContentAnalysisAgent(ai_provider=self._make_mock_provider())
        for text in [
            "Hello world",
            "Click here to verify your bank account now!",
            "Official government notice — send your NIDA details.",
        ]:
            result = agent._timed_analyze(text=text)
            self.assertGreaterEqual(result.confidence, 25, msg=f"Confidence too low for: {text}")
            self.assertLessEqual(result.confidence, 95, msg=f"Confidence too high for: {text}")


class TestOrchestratorProviderInjection(TestCase):
    """Verify that AnalysisOrchestrator accepts and propagates an injected provider."""

    def _make_mock_provider(self):
        from services.ai_provider import MockAIProvider, ProviderConfig
        cfg = ProviderConfig(provider_name="mock", api_key="", url="", project_id="")
        return MockAIProvider(cfg)

    def test_orchestrator_accepts_injected_provider(self):
        from agents.orchestrator import AnalysisOrchestrator
        orch = AnalysisOrchestrator(ai_provider=self._make_mock_provider())
        result = orch.run(text="Fake scholarship — no exam needed. Apply on WhatsApp.")
        self.assertTrue(result["success"])
        self.assertIn("risk_score", result)
        self.assertIsInstance(result["risk_score"], int)

    def test_orchestrator_url_with_injected_provider(self):
        from agents.orchestrator import AnalysisOrchestrator
        orch = AnalysisOrchestrator(ai_provider=self._make_mock_provider())
        result = orch.run(
            text="Click to claim your free iPhone",
            url="http://free-iphone-claim.xyz/win",
        )
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["url_analysis_data"])


# ---------------------------------------------------------------------------
# Extended URL agent tests (14-signal upgrade)
# ---------------------------------------------------------------------------

class TestURLAgentExtended(TestCase):
    def setUp(self):
        from agents.url_agent import URLAnalysisAgent
        self.agent = URLAnalysisAgent(provider="internal")

    # --- Happy-path low-risk URLs ---

    def test_legitimate_gov_domain_scores_low(self):
        result = self.agent._timed_analyze(url="https://tra.go.tz/vat-registration")
        self.assertTrue(result.success)
        self.assertLessEqual(result.score, 25)

    def test_https_clean_domain_scores_low(self):
        result = self.agent._timed_analyze(url="https://news.bbc.com/world/africa")
        self.assertTrue(result.success)
        self.assertLessEqual(result.score, 25)

    # --- Signal 1: No HTTPS ---

    def test_http_scheme_raises_score(self):
        result = self.agent._timed_analyze(url="http://example.com/page")
        self.assertTrue(result.success)
        self.assertIn("no_https", result.data["suspicious_patterns"])
        self.assertGreaterEqual(result.score, 20)

    # --- Signal 2: IP address host ---

    def test_ip_host_detected(self):
        result = self.agent._timed_analyze(url="http://203.0.113.5/admin")
        self.assertTrue(result.success)
        self.assertIn("ip_address_as_host", result.data["suspicious_patterns"])
        self.assertGreaterEqual(result.score, 30)

    # --- Signal 3: Suspicious TLD ---

    def test_xyz_tld_penalised(self):
        result = self.agent._timed_analyze(url="https://grantaward.xyz/apply")
        self.assertTrue(result.success)
        self.assertTrue(
            any("suspicious_tld" in p for p in result.data["suspicious_patterns"])
        )
        self.assertGreaterEqual(result.data["tld_risk"], 20)

    def test_tk_tld_penalised(self):
        result = self.agent._timed_analyze(url="https://mpesa-update.tk/verify")
        self.assertTrue(result.success)
        self.assertGreaterEqual(result.score, 25)

    # --- Signal 5: Brand impersonation ---

    def test_brand_impersonation_paypal(self):
        result = self.agent._timed_analyze(url="https://paypal-login.xyz/confirm")
        self.assertTrue(result.success)
        self.assertIn("brand_impersonation", result.data["suspicious_patterns"])
        self.assertTrue(result.data["is_brand_impersonation_suspected"])

    def test_official_paypal_not_flagged(self):
        result = self.agent._timed_analyze(url="https://paypal.com/signin")
        self.assertTrue(result.success)
        self.assertFalse(result.data["is_brand_impersonation_suspected"])

    # --- Signal 9: Punycode / IDN ---

    def test_punycode_domain_flagged(self):
        result = self.agent._timed_analyze(url="https://xn--pple-43d.com/verify")
        self.assertTrue(result.success)
        self.assertIn("punycode_idn", result.data["suspicious_patterns"])

    # --- Signal 10: Dangerous scheme ---

    def test_javascript_scheme_scores_100(self):
        result = self.agent._timed_analyze(url="javascript:alert(1)")
        self.assertTrue(result.success)
        self.assertEqual(result.score, 100)
        self.assertIn("dangerous_scheme", result.data["suspicious_patterns"])

    # --- Signal 12: Encoding abuse ---

    def test_encoding_abuse_flagged(self):
        encoded = "https://example.com/" + "%41" * 8  # 8 encoded chars > threshold of 5
        result = self.agent._timed_analyze(url=encoded)
        self.assertTrue(result.success)
        self.assertIn("encoding_abuse", result.data["suspicious_patterns"])

    # --- Signal 13: Typosquatting ---

    def test_typosquatting_paypal_detected(self):
        result = self.agent._timed_analyze(url="https://paypa1.com/login")
        self.assertTrue(result.success)
        self.assertTrue(result.data["is_typosquatting_suspected"])

    def test_exact_brand_not_typosquatting(self):
        result = self.agent._timed_analyze(url="https://paypal.com/login")
        self.assertTrue(result.success)
        # Official domain — neither typosquatting nor brand impersonation
        self.assertFalse(result.data["is_typosquatting_suspected"])

    # --- Signal 14: Non-standard port ---

    def test_non_standard_port_flagged(self):
        result = self.agent._timed_analyze(url="https://example.com:8888/admin")
        self.assertTrue(result.success)
        self.assertIn("non_standard_port", result.data["suspicious_patterns"])

    # --- Data completeness ---

    def test_result_contains_new_fields(self):
        result = self.agent._timed_analyze(url="https://suspicious-prize.xyz/claim")
        self.assertTrue(result.success)
        for field in ("tld_risk", "path_depth", "encoding_issues",
                      "signal_detail", "is_typosquatting_suspected",
                      "is_brand_impersonation_suspected", "redirect_count",
                      "final_url"):
            self.assertIn(field, result.data, msg=f"Missing data field: {field}")

    # --- Confidence calibration ---

    def test_confidence_increases_with_signals(self):
        low_result = self.agent._timed_analyze(url="https://google.com")
        high_result = self.agent._timed_analyze(
            url="http://paypal-secure-login.xyz/confirm-account"
        )
        self.assertLess(low_result.confidence, high_result.confidence)
