"""
services/ai_provider.py — AI provider abstraction layer for TruthLens AI

Architecture
------------
  BaseAIProvider          — abstract contract every provider must satisfy
    MockAIProvider        — deterministic synthetic responses (dev / CI)
    WatsonxProvider       — IBM watsonx.ai + IBM Granite (production)

Factory
-------
  get_ai_provider()  resolves the provider from settings at call-time.

  Resolution order:
    1. settings.AI_PROVIDER == "watsonx"  AND  credentials present  → WatsonxProvider
    2. settings.AI_PROVIDER == "watsonx"  AND  credentials missing   → MockAIProvider
       (logged as WARNING so the operator knows)
    3. anything else                                                  → MockAIProvider

Environment variables (all read via settings)
---------------------------------------------
  AI_PROVIDER           = mock | watsonx          (default: mock)
  WATSONX_API_KEY       = <IAM key>
  WATSONX_URL           = https://us-south.ml.cloud.ibm.com
  WATSONX_PROJECT_ID    = <project uuid>
  WATSONX_MODEL_ID      = ibm/granite-13b-chat-v2 (default)
  WATSONX_MAX_RETRIES   = 2                        (default)
  WATSONX_TIMEOUT_SEC   = 30                       (default)

Provider contract
-----------------
Every provider must implement:
  analyze_content(text: str)  → ProviderResponse
  generate_explanation(**kw)  → ProviderResponse

Both return a ProviderResponse dataclass — never a bare dict — so callers
get type-checked fields instead of fragile dict key access.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from django.conf import settings

logger = logging.getLogger("services.ai_provider")


# ---------------------------------------------------------------------------
# Data transfer object returned by every provider method
# ---------------------------------------------------------------------------

@dataclass
class ProviderResponse:
    """
    Standardised return value from any AI provider call.

    Fields
    ------
    success         True when the provider returned usable data.
    provider        "mock" | "watsonx"
    model_id        Model identifier string (empty for mock).
    risk_score      0–100 integer (content analysis only; 0 for explanation calls).
    category        Threat category string or "unknown".
    claims          List of {"text": str, "requires_verification": bool} dicts.
    findings        Human-readable strings explaining why content is suspicious.
    confidence      0–100 provider confidence in the analysis.
    explanation     Plain-language explanation (explanation calls only).
    prompt_tokens   Tokens consumed by the prompt (0 when unavailable).
    completion_tokens Tokens generated (0 when unavailable).
    latency_ms      Wall-clock time of the provider call in milliseconds.
    error           Error description when success=False, else None.
    raw             Raw provider response string for audit logging.
    details         Arbitrary extra data (e.g. keyword hits for mock).
    """
    success: bool
    provider: str
    model_id: str = ""
    risk_score: int = 0
    category: str = "unknown"
    claims: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    confidence: int = 50
    explanation: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    error: Optional[str] = None
    raw: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "provider": self.provider,
            "model_id": self.model_id,
            "risk_score": self.risk_score,
            "category": self.category,
            "claims": self.claims,
            "findings": self.findings,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------

@dataclass
class ProviderConfig:
    """Resolved provider configuration from Django settings."""
    provider_name: str
    api_key: str = ""
    url: str = ""
    project_id: str = ""
    model_id: str = "ibm/granite-13b-chat-v2"
    max_retries: int = 2
    timeout_sec: int = 30

    @classmethod
    def from_settings(cls) -> "ProviderConfig":
        return cls(
            provider_name=getattr(settings, "AI_PROVIDER", "mock"),
            api_key=getattr(settings, "WATSONX_API_KEY", ""),
            url=getattr(settings, "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"),
            project_id=getattr(settings, "WATSONX_PROJECT_ID", ""),
            model_id=getattr(settings, "WATSONX_MODEL_ID", "ibm/granite-13b-chat-v2"),
            max_retries=int(getattr(settings, "WATSONX_MAX_RETRIES", 2)),
            timeout_sec=int(getattr(settings, "WATSONX_TIMEOUT_SEC", 30)),
        )

    def has_watsonx_credentials(self) -> bool:
        return bool(self.api_key and self.url and self.project_id)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_ai_provider(config: Optional[ProviderConfig] = None) -> "BaseAIProvider":
    """
    Return the appropriate AI provider.

    Falls back to MockAIProvider with a WARNING log if:
    - AI_PROVIDER=watsonx but credentials are incomplete.
    """
    cfg = config or ProviderConfig.from_settings()

    if cfg.provider_name == "watsonx":
        if cfg.has_watsonx_credentials():
            return WatsonxProvider(cfg)
        logger.warning(
            "AI_PROVIDER=watsonx but WATSONX_API_KEY / WATSONX_PROJECT_ID are not set. "
            "Falling back to MockAIProvider. Set credentials in .env to use IBM watsonx.ai."
        )
    return MockAIProvider(cfg)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseAIProvider:
    """
    Contract every AI provider must satisfy.
    Subclasses override analyze_content() and generate_explanation().
    """
    provider_name: str = "base"

    def __init__(self, config: ProviderConfig):
        self.config = config

    def analyze_content(self, text: str) -> ProviderResponse:  # pragma: no cover
        raise NotImplementedError

    def generate_explanation(
        self,
        risk_score: int = 0,
        risk_level: str = "needs_verification",
        threat_category: str = "unknown",
        findings: Optional[list] = None,
        recommendation: str = "",
    ) -> ProviderResponse:  # pragma: no cover
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers shared by all providers
    # ------------------------------------------------------------------

    @staticmethod
    def _timed(fn, *args, **kwargs):
        """Run fn(*args, **kwargs) and attach latency_ms to the returned ProviderResponse."""
        t0 = time.monotonic()
        result: ProviderResponse = fn(*args, **kwargs)
        result.latency_ms = int((time.monotonic() - t0) * 1000)
        return result


# ---------------------------------------------------------------------------
# Mock provider — deterministic, keyword-based, clearly labelled
# ---------------------------------------------------------------------------

# High-risk keywords and their per-category weight
_HIGH_RISK = {
    "send money": ("payment_scam", 22),
    "transfer": ("payment_scam", 15),
    "registration fee": ("fake_scholarship", 25),
    "processing fee": ("payment_scam", 20),
    "deposit fee": ("payment_scam", 20),
    "guaranteed profit": ("investment_scam", 28),
    "double your money": ("investment_scam", 28),
    "act now": ("urgency", 12),
    "click here": ("phishing", 18),
    "verify your account": ("phishing", 22),
    "account suspended": ("phishing", 22),
    "winner": ("prize_scam", 20),
    "prize": ("prize_scam", 18),
    "congratulations": ("prize_scam", 15),
    "scholarship": ("fake_scholarship", 14),
    "job offer": ("fake_job", 16),
    "earn daily": ("fake_job", 20),
    "no experience": ("fake_job", 16),
    "investment": ("investment_scam", 10),
    "whatsapp": ("fake_job", 10),
    "limited time": ("urgency", 12),
    "free money": ("scam", 25),
    "government grant": ("impersonation", 18),
    "official notice": ("impersonation", 16),
    "m-pesa": ("payment_scam", 10),
    "airtel money": ("payment_scam", 10),
    "tigo pesa": ("payment_scam", 10),
    "bitcoin": ("investment_scam", 12),
    "crypto": ("investment_scam", 10),
}

_MEDIUM_RISK = {
    "urgent": 8,
    "exclusive": 6,
    "opportunity": 5,
    "apply now": 7,
    "free": 5,
    "reward": 6,
    "special offer": 7,
    "limited slots": 9,
    "don't miss": 8,
}

# Category priority when multiple categories match (higher = takes priority)
_CATEGORY_PRIORITY = {
    "phishing": 10,
    "fake_scholarship": 9,
    "fake_job": 9,
    "investment_scam": 9,
    "prize_scam": 8,
    "payment_scam": 8,
    "impersonation": 7,
    "urgency": 4,
    "scam": 3,
    "unknown": 0,
}


class MockAIProvider(BaseAIProvider):
    """
    [MOCK] Deterministic AI provider for local development and CI.

    Behaviour
    ---------
    - Scans text for a curated keyword list.
    - Accumulates a weighted risk score per keyword hit (capped at 100).
    - Picks the highest-priority category from matched keywords.
    - Extracts sentence fragments as mock "claims".
    - Returns clearly labelled responses (provider="mock", model_id="mock-v1").

    This is NOT a machine-learning model.  It will not catch all scams
    and will produce false positives.  Use WatsonxProvider for production.
    """
    provider_name = "mock"

    def analyze_content(self, text: str) -> ProviderResponse:
        if not text or not text.strip():
            return ProviderResponse(
                success=False,
                provider=self.provider_name,
                error="Empty input",
            )

        text_lower = text.lower()

        # --- score and category accumulation ---
        accumulated_score = 0
        category_scores: dict[str, int] = {}
        high_hits: list[str] = []
        medium_hits: list[str] = []

        for keyword, (cat, weight) in _HIGH_RISK.items():
            if keyword in text_lower:
                accumulated_score += weight
                high_hits.append(keyword)
                category_scores[cat] = category_scores.get(cat, 0) + weight

        for keyword, weight in _MEDIUM_RISK.items():
            if keyword in text_lower:
                accumulated_score += weight
                medium_hits.append(keyword)

        risk_score = min(100, accumulated_score)

        # --- category resolution ---
        category = "unknown"
        if category_scores:
            # Prefer highest-priority category; break ties by weight sum
            category = max(
                category_scores,
                key=lambda c: (_CATEGORY_PRIORITY.get(c, 0), category_scores[c]),
            )

        # --- claim extraction (sentence fragments > 20 chars) ---
        raw_sentences = re.split(r"[.!?\n]+", text)
        claims = []
        for s in raw_sentences[:5]:
            s = s.strip()
            if len(s) > 20:
                claims.append({
                    "text": s,
                    "requires_verification": risk_score > 30,
                    "is_suspicious": risk_score > 50,
                })

        # --- findings ---
        findings: list[str] = []
        if high_hits:
            findings.append(
                f"Contains high-risk language: {', '.join(high_hits[:4])}"
            )
        if medium_hits:
            findings.append(
                f"Contains potentially suspicious phrasing: {', '.join(medium_hits[:3])}"
            )
        if not findings and risk_score == 0:
            findings.append("No suspicious language patterns detected")

        # --- confidence: more keyword hits → higher confidence ---
        total_hits = len(high_hits) + len(medium_hits)
        if total_hits == 0:
            confidence = 45
        elif total_hits <= 2:
            confidence = 58
        elif total_hits <= 5:
            confidence = 70
        else:
            confidence = 82

        return ProviderResponse(
            success=True,
            provider=self.provider_name,
            model_id="mock-v1",
            risk_score=risk_score,
            category=category,
            claims=claims,
            findings=findings,
            confidence=confidence,
            details={
                "high_risk_keywords": high_hits,
                "medium_risk_keywords": medium_hits,
                "category_scores": category_scores,
                "note": (
                    "[MOCK] Keyword-based simulation for development. "
                    "Not a real AI model — switch to AI_PROVIDER=watsonx for production."
                ),
            },
        )

    def generate_explanation(
        self,
        risk_score: int = 0,
        risk_level: str = "needs_verification",
        threat_category: str = "unknown",
        findings: Optional[list] = None,
        recommendation: str = "",
    ) -> ProviderResponse:
        # Mock provider intentionally returns success=False so ExplanationAgent
        # falls back to its own template-based explanation.  This keeps mock
        # explanations consistent and avoids duplicating template logic here.
        return ProviderResponse(
            success=False,
            provider=self.provider_name,
            model_id="mock-v1",
            details={"note": "[MOCK] Template explanation used."},
        )


# ---------------------------------------------------------------------------
# IBM watsonx.ai provider
# ---------------------------------------------------------------------------

_ANALYSIS_PROMPT_TEMPLATE = """\
You are TruthLens AI, a cybersecurity and misinformation detection system \
helping users in Tanzania and East Africa stay safe online.

Analyse the following content carefully and respond with ONLY valid JSON. \
Do not include any text outside the JSON object.

Content:
\"\"\"
{text}
\"\"\"

Respond with exactly this JSON schema — no markdown, no extra keys:
{{
  "risk_score": <integer 0-100>,
  "category": "<one of: fake_news|scam|phishing|fake_job|fake_scholarship|investment_scam|impersonation|fraud|health_misinfo|political_misinfo|suspicious_url|other|unknown>",
  "findings": ["<concise finding 1>", "<concise finding 2>"],
  "claims": [{{"text": "<sentence>", "requires_verification": true}}],
  "confidence": <integer 0-100>
}}

Scoring guide:
- 0–15:  No suspicious signals.
- 16–35: Minor concerns; verify before acting.
- 36–60: Notable suspicious elements present.
- 61–80: Strong risk signals; likely harmful.
- 81–100: Very high confidence this is a scam/misinformation.

JSON:"""

_EXPLANATION_PROMPT_TEMPLATE = """\
You are TruthLens AI, a digital safety assistant helping non-technical users \
in Tanzania and East Africa understand online risks.

Analysis summary:
- Risk Score: {risk_score}/100
- Risk Level: {risk_level}
- Threat Category: {threat_category}
- Key Findings:
{findings_text}

Write a clear explanation (3–5 sentences) for a non-technical user explaining \
why this content was flagged. Use simple, direct language. \
Do not repeat the recommendation verbatim; instead explain the reasoning. \
End with exactly this sentence: "{recommendation}"

Explanation:"""


class WatsonxProvider(BaseAIProvider):
    """
    IBM watsonx.ai provider using IBM Granite foundation models.

    Features
    --------
    - Lazy-initialised ModelInference (one instance reused per provider object).
    - Configurable retry with exponential back-off.
    - Automatic fallback to MockAIProvider on any error.
    - Structured JSON parsing with regex extraction fallback.
    - Token usage tracking returned in ProviderResponse.

    Required settings
    -----------------
      WATSONX_API_KEY, WATSONX_URL, WATSONX_PROJECT_ID
    Optional
      WATSONX_MODEL_ID      (default ibm/granite-13b-chat-v2)
      WATSONX_MAX_RETRIES   (default 2)
      WATSONX_TIMEOUT_SEC   (default 30)
    """
    provider_name = "watsonx"

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self._model = None          # lazily created
        self._mock_fallback = MockAIProvider(config)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze_content(self, text: str) -> ProviderResponse:
        if not text or not text.strip():
            return ProviderResponse(
                success=False,
                provider=self.provider_name,
                model_id=self.config.model_id,
                error="Empty input",
            )
        prompt = _ANALYSIS_PROMPT_TEMPLATE.format(text=text[:2000])
        raw, tokens_in, tokens_out = self._generate_with_retry(prompt, max_tokens=700)
        if not raw:
            logger.warning("watsonx analyze_content returned empty — using mock fallback")
            r = self._mock_fallback.analyze_content(text)
            r.provider = f"{self.provider_name}(fallback:mock)"
            return r
        return self._parse_analysis(raw, tokens_in, tokens_out)

    def generate_explanation(
        self,
        risk_score: int = 0,
        risk_level: str = "needs_verification",
        threat_category: str = "unknown",
        findings: Optional[list] = None,
        recommendation: str = "",
    ) -> ProviderResponse:
        findings = findings or []
        findings_text = "\n".join(f"  - {f}" for f in findings[:6]) or "  - No specific findings."
        prompt = _EXPLANATION_PROMPT_TEMPLATE.format(
            risk_score=risk_score,
            risk_level=risk_level,
            threat_category=threat_category,
            findings_text=findings_text,
            recommendation=recommendation,
        )
        raw, tokens_in, tokens_out = self._generate_with_retry(prompt, max_tokens=350)
        if not raw:
            return ProviderResponse(
                success=False,
                provider=self.provider_name,
                model_id=self.config.model_id,
                error="Empty explanation response from watsonx",
            )
        return ProviderResponse(
            success=True,
            provider=self.provider_name,
            model_id=self.config.model_id,
            explanation=raw.strip(),
            prompt_tokens=tokens_in,
            completion_tokens=tokens_out,
        )

    # ------------------------------------------------------------------
    # Internal: model lifecycle
    # ------------------------------------------------------------------

    def _get_model(self):
        """Return a lazily-created, reusable ModelInference instance."""
        if self._model is not None:
            return self._model
        try:
            from ibm_watsonx_ai.foundation_models import ModelInference
            from ibm_watsonx_ai import Credentials
            from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams

            credentials = Credentials(
                url=self.config.url,
                api_key=self.config.api_key,
            )
            self._model = ModelInference(
                model_id=self.config.model_id,
                credentials=credentials,
                project_id=self.config.project_id,
                params={
                    GenParams.MAX_NEW_TOKENS: 700,
                    GenParams.MIN_NEW_TOKENS: 10,
                    GenParams.TEMPERATURE: 0.05,      # near-deterministic
                    GenParams.REPETITION_PENALTY: 1.1,
                    GenParams.STOP_SEQUENCES: ["```"],
                },
            )
            logger.info(
                "WatsonxProvider: ModelInference created — model=%s project=%s",
                self.config.model_id,
                self.config.project_id,
            )
        except ImportError:
            logger.error(
                "ibm_watsonx_ai package not installed. "
                "Run: pip install ibm-watsonx-ai"
            )
            raise
        return self._model

    # ------------------------------------------------------------------
    # Internal: generation with retry
    # ------------------------------------------------------------------

    def _generate_with_retry(
        self, prompt: str, max_tokens: int = 512
    ) -> tuple[str, int, int]:
        """
        Call the IBM watsonx.ai API with exponential back-off retry.

        Returns (text, prompt_tokens, completion_tokens).
        Returns ("", 0, 0) after all retries are exhausted.
        """
        last_exc = None
        for attempt in range(self.config.max_retries + 1):
            try:
                model = self._get_model()

                # Override max tokens per call
                from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams
                result = model.generate(
                    prompt=prompt,
                    params={GenParams.MAX_NEW_TOKENS: max_tokens},
                )

                # Extract text and token counts from the response object
                generated_text = ""
                tokens_in = 0
                tokens_out = 0

                if isinstance(result, dict):
                    results_list = result.get("results", [{}])
                    if results_list:
                        first = results_list[0]
                        generated_text = first.get("generated_text", "")
                        tokens_in = result.get("usage", {}).get("prompt_tokens", 0)
                        tokens_out = first.get("generated_token_count", 0)
                elif hasattr(result, "generated_text"):
                    generated_text = result.generated_text
                else:
                    generated_text = str(result)

                if generated_text:
                    return generated_text.strip(), tokens_in, tokens_out

                logger.debug("watsonx attempt %d: empty generated_text", attempt + 1)

            except Exception as exc:
                last_exc = exc
                wait = 2 ** attempt          # 1 s, 2 s, 4 s …
                logger.warning(
                    "watsonx attempt %d/%d failed: %s — retrying in %ds",
                    attempt + 1,
                    self.config.max_retries + 1,
                    exc,
                    wait,
                )
                if attempt < self.config.max_retries:
                    time.sleep(wait)

        logger.error(
            "watsonx: all %d attempts exhausted. Last error: %s",
            self.config.max_retries + 1,
            last_exc,
        )
        return "", 0, 0

    # ------------------------------------------------------------------
    # Internal: response parsing
    # ------------------------------------------------------------------

    def _parse_analysis(
        self, raw: str, tokens_in: int, tokens_out: int
    ) -> ProviderResponse:
        """Parse the JSON analysis response from Granite."""
        parsed = self._extract_json(raw)
        if parsed is None:
            logger.warning(
                "watsonx: could not parse JSON from response (len=%d). "
                "Using mock fallback scores.", len(raw)
            )
            return ProviderResponse(
                success=False,
                provider=self.provider_name,
                model_id=self.config.model_id,
                error="JSON parse failed",
                raw=raw[:500],
                prompt_tokens=tokens_in,
                completion_tokens=tokens_out,
            )

        # Validate and clamp numeric fields
        risk_score = int(max(0, min(100, parsed.get("risk_score", 0))))
        confidence = int(max(0, min(100, parsed.get("confidence", 50))))

        # Sanitise claims list
        claims_raw = parsed.get("claims", [])
        claims = []
        for c in claims_raw[:10]:
            if isinstance(c, dict) and "text" in c:
                claims.append({
                    "text": str(c["text"])[:500],
                    "requires_verification": bool(c.get("requires_verification", False)),
                    "is_suspicious": risk_score > 50,
                })

        # Sanitise findings list
        findings = [str(f)[:300] for f in parsed.get("findings", [])[:8] if f]

        return ProviderResponse(
            success=True,
            provider=self.provider_name,
            model_id=self.config.model_id,
            risk_score=risk_score,
            category=str(parsed.get("category", "unknown")),
            claims=claims,
            findings=findings,
            confidence=confidence,
            prompt_tokens=tokens_in,
            completion_tokens=tokens_out,
            raw=raw[:500],
        )

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """
        Extract and parse the first valid JSON object from text.
        Handles cases where the model wraps JSON in markdown code fences.
        """
        # Strip markdown fences
        cleaned = re.sub(r"```(?:json)?", "", text).strip()

        # Try direct parse first
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Try to find embedded JSON object
        match = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        # Greedy match for nested JSON
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None
