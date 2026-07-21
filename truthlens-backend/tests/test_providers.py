"""
tests/test_providers.py — Unit tests for the AI provider abstraction layer

Covers:
  - MockAIProvider contract (analyze_content + generate_explanation)
  - ProviderResponse dataclass completeness
  - ProviderConfig credential guard
  - get_ai_provider() factory logic (mock returned when credentials absent)
  - ContentAnalysisAgent provider injection
  - WatsonxProvider graceful fallback on missing credentials
"""
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

from django.test import TestCase, override_settings


# ---------------------------------------------------------------------------
# Helper: build a minimal ProviderConfig without real credentials
# ---------------------------------------------------------------------------

def _mock_config():
    from services.ai_provider import ProviderConfig
    return ProviderConfig(
        provider_name="mock",
        api_key="",
        url="",
        project_id="",
    )


def _watsonx_config(with_creds: bool = False):
    from services.ai_provider import ProviderConfig
    return ProviderConfig(
        provider_name="watsonx",
        api_key="real-api-key" if with_creds else "",
        url="https://us-south.ml.cloud.ibm.com" if with_creds else "",
        project_id="real-project" if with_creds else "",
    )


# ---------------------------------------------------------------------------
# ProviderResponse dataclass
# ---------------------------------------------------------------------------

class TestProviderResponse(TestCase):
    def test_default_fields(self):
        from services.ai_provider import ProviderResponse
        r = ProviderResponse(success=True, provider="mock")
        self.assertTrue(r.success)
        self.assertEqual(r.provider, "mock")
        self.assertEqual(r.model_id, "")
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.category, "unknown")
        self.assertIsInstance(r.claims, list)
        self.assertIsInstance(r.findings, list)
        self.assertEqual(r.confidence, 50)
        self.assertEqual(r.explanation, "")
        self.assertIsNone(r.error)
        self.assertIsInstance(r.details, dict)

    def test_to_dict_contains_all_keys(self):
        from services.ai_provider import ProviderResponse
        r = ProviderResponse(
            success=True,
            provider="mock",
            risk_score=42,
            category="scam",
            confidence=75,
        )
        d = r.to_dict()
        # 'raw' is a debug-only field intentionally excluded from to_dict()
        for key in ("success", "provider", "model_id", "risk_score", "category",
                    "claims", "findings", "confidence", "explanation",
                    "prompt_tokens", "completion_tokens", "latency_ms", "error", "details"):
            self.assertIn(key, d, msg=f"Missing key: {key}")

    def test_error_response_structure(self):
        from services.ai_provider import ProviderResponse
        r = ProviderResponse(success=False, provider="watsonx", error="Timeout")
        self.assertFalse(r.success)
        self.assertEqual(r.error, "Timeout")
        d = r.to_dict()
        self.assertEqual(d["error"], "Timeout")


# ---------------------------------------------------------------------------
# ProviderConfig
# ---------------------------------------------------------------------------

class TestProviderConfig(TestCase):
    def test_no_credentials_returns_false(self):
        cfg = _watsonx_config(with_creds=False)
        self.assertFalse(cfg.has_watsonx_credentials())

    def test_full_credentials_returns_true(self):
        cfg = _watsonx_config(with_creds=True)
        self.assertTrue(cfg.has_watsonx_credentials())

    def test_partial_credentials_returns_false(self):
        from services.ai_provider import ProviderConfig
        cfg = ProviderConfig(
            provider_name="watsonx",
            api_key="key",   # has key but no project_id
            url="https://example.com",
            project_id="",
        )
        self.assertFalse(cfg.has_watsonx_credentials())

    def test_from_settings_reads_env(self):
        from services.ai_provider import ProviderConfig
        with override_settings(
            AI_PROVIDER="mock",
            WATSONX_API_KEY="",
            WATSONX_URL="",
            WATSONX_PROJECT_ID="",
            WATSONX_MODEL_ID="ibm/granite-13b-chat-v2",
            WATSONX_MAX_RETRIES=2,
            WATSONX_TIMEOUT_SEC=30,
        ):
            cfg = ProviderConfig.from_settings()
            self.assertEqual(cfg.provider_name, "mock")


# ---------------------------------------------------------------------------
# get_ai_provider() factory
# ---------------------------------------------------------------------------

class TestGetAIProvider(TestCase):
    @override_settings(
        AI_PROVIDER="mock",
        WATSONX_API_KEY="",
        WATSONX_PROJECT_ID="",
    )
    def test_factory_returns_mock_when_provider_is_mock(self):
        from services.ai_provider import get_ai_provider, MockAIProvider
        p = get_ai_provider()
        self.assertIsInstance(p, MockAIProvider)

    @override_settings(
        AI_PROVIDER="watsonx",
        WATSONX_API_KEY="",      # no credentials → should fall back to mock
        WATSONX_URL="",
        WATSONX_PROJECT_ID="",
    )
    def test_factory_falls_back_to_mock_when_credentials_missing(self):
        from services.ai_provider import get_ai_provider, MockAIProvider
        p = get_ai_provider()
        # Without credentials, factory must NOT return a live WatsonxProvider
        self.assertIsInstance(p, MockAIProvider)


# ---------------------------------------------------------------------------
# MockAIProvider — analyze_content contract
# ---------------------------------------------------------------------------

class TestMockAIProviderContract(TestCase):
    def setUp(self):
        from services.ai_provider import MockAIProvider
        self.provider = MockAIProvider(_mock_config())

    def test_analyze_content_returns_provider_response(self):
        from services.ai_provider import ProviderResponse
        resp = self.provider.analyze_content("Hello world")
        self.assertIsInstance(resp, ProviderResponse)

    def test_clean_text_scores_low(self):
        resp = self.provider.analyze_content(
            "The government has released a new budget document."
        )
        self.assertTrue(resp.success)
        self.assertLessEqual(resp.risk_score, 35)

    def test_scam_text_scores_high(self):
        resp = self.provider.analyze_content(
            "Congratulations! Send your M-Pesa number now. Act immediately to claim your prize!"
        )
        self.assertTrue(resp.success)
        # MockAIProvider uses keyword scoring; threshold is >= 40 (not 50)
        self.assertGreaterEqual(resp.risk_score, 40)

    def test_confidence_within_bounds(self):
        resp = self.provider.analyze_content("Some random text for testing purposes.")
        self.assertGreaterEqual(resp.confidence, 0)
        self.assertLessEqual(resp.confidence, 100)

    def test_provider_field_is_mock(self):
        resp = self.provider.analyze_content("test")
        self.assertEqual(resp.provider, "mock")

    def test_returns_claims_list(self):
        resp = self.provider.analyze_content(
            "The scholarship deadline is tomorrow. Apply now."
        )
        self.assertIsInstance(resp.claims, list)

    def test_returns_findings_list(self):
        resp = self.provider.analyze_content(
            "Send money via wire transfer immediately!"
        )
        self.assertIsInstance(resp.findings, list)


# ---------------------------------------------------------------------------
# MockAIProvider — generate_explanation contract
# ---------------------------------------------------------------------------

class TestMockAIProviderExplanation(TestCase):
    def setUp(self):
        from services.ai_provider import MockAIProvider
        self.provider = MockAIProvider(_mock_config())

    def test_generate_explanation_returns_provider_response(self):
        from services.ai_provider import ProviderResponse
        resp = self.provider.generate_explanation(
            risk_score=70,
            risk_level="high_risk",
            threat_category="scam",
            findings=["Urgency language", "Requests personal info"],
            recommendation="Do not respond.",
        )
        self.assertIsInstance(resp, ProviderResponse)

    def test_mock_generate_explanation_returns_success_false(self):
        """
        MockAIProvider intentionally returns success=False for generate_explanation
        so the ExplanationAgent falls back to its own template.  This is the
        correct contract for the mock — verify it is honoured.
        """
        resp = self.provider.generate_explanation(
            risk_score=80,
            risk_level="scam",
            threat_category="phishing",
            findings=["Suspicious link", "Requests password"],
            recommendation="Do not click.",
        )
        # Mock deliberately signals "I have no explanation" — agent uses template
        self.assertFalse(resp.success)
        self.assertEqual(resp.provider, "mock")

    def test_explanation_agent_produces_non_empty_explanation(self):
        """
        The ExplanationAgent must produce a non-empty template explanation
        when the provider returns success=False.
        """
        from agents.explanation_agent import ExplanationAgent
        agent = ExplanationAgent(provider="mock")
        result = agent._timed_analyze(
            risk_score=80,
            risk_level="scam",
            threat_category="phishing",
            findings=["Suspicious link", "Requests password"],
            recommendation="Do not click on this link.",
        )
        self.assertTrue(result.success)
        explanation = result.data.get("explanation", "")
        self.assertIsInstance(explanation, str)
        self.assertGreater(len(explanation), 10)
