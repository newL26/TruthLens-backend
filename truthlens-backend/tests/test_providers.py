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
import json
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


# ---------------------------------------------------------------------------
# OpenRouter provider tests
# ---------------------------------------------------------------------------

def _openrouter_config(with_key: bool = False):
    from services.ai_provider import ProviderConfig
    return ProviderConfig(
        provider_name="openrouter",
        openrouter_api_key="sk-or-test-key" if with_key else "",
        openrouter_api_url="https://openrouter.ai/api/v1/chat/completions",
        openrouter_model="deepseek/deepseek-v4-flash:free",
    )


class TestOpenRouterProviderConfig(TestCase):
    def test_no_key_returns_false(self):
        cfg = _openrouter_config(with_key=False)
        self.assertFalse(cfg.has_openrouter_credentials())

    def test_with_key_returns_true(self):
        cfg = _openrouter_config(with_key=True)
        self.assertTrue(cfg.has_openrouter_credentials())

    def test_from_settings_reads_env(self):
        from services.ai_provider import ProviderConfig
        from django.test import override_settings
        with override_settings(
            AI_PROVIDER="openrouter",
            OPENROUTER_API_KEY="test-key",
            OPENROUTER_API_URL="https://openrouter.ai/api/v1/chat/completions",
            OPENROUTER_MODEL="deepseek/deepseek-v4-flash:free",
        ):
            cfg = ProviderConfig.from_settings()
            self.assertEqual(cfg.provider_name, "openrouter")
            self.assertEqual(cfg.openrouter_api_key, "test-key")
            self.assertEqual(cfg.openrouter_model, "deepseek/deepseek-v4-flash:free")


class TestOpenRouterFactory(TestCase):
    @override_settings(
        AI_PROVIDER="openrouter",
        OPENROUTER_API_KEY="",   # no key → falls back to mock
    )
    def test_factory_falls_back_when_no_key(self):
        from services.ai_provider import get_ai_provider, MockAIProvider
        p = get_ai_provider()
        self.assertIsInstance(p, MockAIProvider)

    @override_settings(
        AI_PROVIDER="openrouter",
        OPENROUTER_API_KEY="sk-or-test-key",
    )
    def test_factory_returns_openrouter_when_key_present(self):
        from services.ai_provider import get_ai_provider, OpenRouterProvider
        p = get_ai_provider()
        self.assertIsInstance(p, OpenRouterProvider)


class TestOpenRouterProviderContract(TestCase):
    """
    Tests that run against OpenRouterProvider with a mocked HTTP layer.
    We monkey-patch _chat() to return a controlled fixture, keeping tests
    fast and offline.
    """

    def setUp(self):
        from services.ai_provider import OpenRouterProvider
        self.provider = OpenRouterProvider(_openrouter_config(with_key=True))

    def _patch_chat_ok(self, risk_score=70, category="scam"):
        """Make _chat return a valid JSON analysis response."""
        fixture = json.dumps({
            "risk_score": risk_score,
            "category": category,
            "findings": ["Contains urgency language", "Requests payment"],
            "claims": [{"text": "Send money now", "requires_verification": True}],
            "confidence": 80,
        })
        self.provider._chat = lambda **kw: (fixture, 100, 50)

    def _patch_chat_explanation(self, text="This content looks suspicious."):
        self.provider._chat = lambda **kw: (text, 80, 30)

    def _patch_chat_empty(self):
        self.provider._chat = lambda **kw: ("", 0, 0)

    # --- analyze_content ---

    def test_empty_input_returns_failure(self):
        from services.ai_provider import ProviderResponse
        resp = self.provider.analyze_content("")
        self.assertIsInstance(resp, ProviderResponse)
        self.assertFalse(resp.success)

    def test_valid_json_response_parsed_correctly(self):
        self._patch_chat_ok(risk_score=75, category="investment_scam")
        resp = self.provider.analyze_content("Invest $100 earn $1000 weekly!")
        self.assertTrue(resp.success)
        self.assertEqual(resp.risk_score, 75)
        self.assertEqual(resp.category, "investment_scam")
        self.assertIsInstance(resp.findings, list)
        self.assertIsInstance(resp.claims, list)
        self.assertEqual(resp.provider, "openrouter")

    def test_empty_chat_response_falls_back_to_mock(self):
        self._patch_chat_empty()
        resp = self.provider.analyze_content("Send money now!")
        # Falls back to mock but still returns a valid ProviderResponse
        self.assertIsInstance(resp.risk_score, int)
        self.assertIn("fallback:mock", resp.provider)

    def test_confidence_within_bounds(self):
        self._patch_chat_ok(risk_score=50)
        resp = self.provider.analyze_content("Some text to analyze")
        self.assertGreaterEqual(resp.confidence, 0)
        self.assertLessEqual(resp.confidence, 100)

    def test_risk_score_clamped(self):
        # Even if model returns out-of-range value, it should be clamped
        fixture = json.dumps({"risk_score": 150, "category": "scam",
                              "findings": [], "claims": [], "confidence": 90})
        self.provider._chat = lambda **kw: (fixture, 10, 20)
        resp = self.provider.analyze_content("test")
        self.assertLessEqual(resp.risk_score, 100)

    # --- generate_explanation ---

    def test_generate_explanation_returns_provider_response(self):
        from services.ai_provider import ProviderResponse
        self._patch_chat_explanation("This message is suspicious.")
        resp = self.provider.generate_explanation(
            risk_score=80, risk_level="high_risk",
            threat_category="scam", findings=["Urgency language"],
            recommendation="Do not respond.",
        )
        self.assertIsInstance(resp, ProviderResponse)
        self.assertTrue(resp.success)
        self.assertEqual(resp.explanation, "This message is suspicious.")
        self.assertEqual(resp.provider, "openrouter")

    def test_empty_explanation_response_returns_failure(self):
        self._patch_chat_empty()
        resp = self.provider.generate_explanation(risk_score=50)
        self.assertFalse(resp.success)
