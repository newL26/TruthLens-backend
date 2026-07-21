"""
agents/content_agent.py — Agent 1: Content Analysis Agent

Responsibilities
----------------
- Accept text or URL as input
- Run fast rule-based pattern matching (7 signal groups, always executed)
- Call the AI provider for deeper semantic analysis and claim extraction
- Merge pattern scores with AI scores using a configurable blend ratio
- Return a standardised AgentResult

Provider injection
------------------
The agent accepts an optional `provider` argument at construction time.
When omitted the agent resolves the provider from settings via
`get_ai_provider()`.  This design allows tests to inject a MockAIProvider
without touching settings or environment variables.

Scoring blend
-------------
  combined_score = AI_score * AI_WEIGHT + pattern_score * PATTERN_WEIGHT

  AI_WEIGHT      = 0.60  (configurable via settings.CONTENT_AI_WEIGHT)
  PATTERN_WEIGHT = 0.40
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from django.conf import settings
from .base import BaseAgent, AgentResult
from services.ai_provider import BaseAIProvider, get_ai_provider

logger = logging.getLogger("agents.content_agent")

# ---------------------------------------------------------------------------
# AI/pattern blend weights (overridable in settings)
# ---------------------------------------------------------------------------
_DEFAULT_AI_WEIGHT = 0.60
_DEFAULT_PATTERN_WEIGHT = 0.40

# ---------------------------------------------------------------------------
# Pattern libraries — compiled once at import time
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\bact now\b",
    r"\blimited time\b",
    r"\bexpires? (today|soon|in \d+ hours?)\b",
    r"\burgen(t|cy)\b",
    r"\bimmediately\b",
    r"\blast chance\b",
    r"\bdon'?t (miss|wait|delay)\b",
    r"\bonly \d+ (spots?|slots?|seats?)\b",
    r"\bfinal notice\b",
    r"\bexpires? (tonight|tomorrow|this week)\b",
]

_FEAR_PATTERNS = [
    r"\byour account (has been|will be) (suspended|blocked|closed|locked)\b",
    r"\bunauthorized access\b",
    r"\bsuspicious activity\b",
    r"\byou (owe|have been charged|will be arrested|face (charges|penalties))\b",
    r"\bwarning\b.{0,30}\bbank\b",
    r"\bpenalt(y|ies)\b",
    r"\bthreat(en|ened)?\b",
    r"\blegal action\b",
]

_MONEY_REQUEST_PATTERNS = [
    r"\bsend (money|cash|payment|funds)\b",
    r"\bpay (now|immediately|first|upfront|registration fee)\b",
    r"\btransfer.{0,30}\b(account|wallet)\b",
    r"\bwire transfer\b",
    r"\bmobile money\b",
    r"\bm-pesa\b",
    r"\bairtel money\b",
    r"\btigo pesa\b",
    r"\bhalopesa\b",
    r"\bbitcoin\b",
    r"\bcrypto\b",
    r"\bgift card\b",
    r"\bdeposit (fee|first|now|required)\b",
    r"\bprocessing fee\b",
]

_PII_REQUEST_PATTERNS = [
    r"\bpassword\b",
    r"\bpin\b",
    r"\bsocial security\b",
    r"\bnational id\b",
    r"\bnida\b",
    r"\bnhif\b",
    r"\bnssf\b",
    r"\bbank account (number|details)\b",
    r"\bcredit card\b",
    r"\bconfirm your (details|information|account)\b",
    r"\bverify your (account|identity|email|phone|number)\b",
    r"\benter your (otp|pin|password|code)\b",
]

_UNUSUAL_PROMISE_PATTERNS = [
    r"\bguarante(e|d) (profit|return|income|money)\b",
    r"\bearn \$?\d[\d,]* (per day|daily|weekly|monthly)\b",
    r"\bdouble your (money|investment|income)\b",
    r"\b(free|win|won|winner)\b.{0,40}\b(iphone|laptop|car|cash|prize)\b",
    r"\b(selected|chosen|congratulations)\b.{0,40}\b(prize|winner|reward)\b",
    r"\bno (experience|qualification|skill) (needed|required)\b",
    r"\bwork from home.{0,40}(daily|weekly).{0,20}pay\b",
    r"\bscholarship.{0,30}no (requirement|qualification|exam)\b",
    r"\b\d+% (return|profit|ROI)\b",
]

_FAKE_JOB_PATTERNS = [
    r"\b(hiring|recruit(ing)?|vacancy|job offer)\b.{0,40}\b(whatsapp|telegram|chat)\b",
    r"\bno (experience|qualification|degree|cv) (required|needed)\b",
    r"\bapply (via|through|on) whatsapp\b",
    r"\bwork from home.{0,30}(daily|weekly).{0,15}pay\b",
    r"\bdata entry.{0,30}(daily|weekly) (pay|salary|income)\b",
]

_PHISHING_PATTERNS = [
    r"\bclick (here|the link|below) (to|and) (verify|confirm|update|activate)\b",
    r"\bverify your account\b",
    r"\bupdate your (payment|billing|card) (information|details)\b",
    r"\byour (account|profile) (has been|will be) (suspended|terminated)\b",
    r"\bsign in to (avoid|prevent|stop)\b",
    r"\bconfirm (your identity|your details|to proceed)\b",
]

_IMPERSONATION_PATTERNS = [
    r"\bofficial (notice|message|announcement) from\b",
    r"\bthis is (the|your) (bank|government|police|ministry)\b",
    r"\b(government|ministry|authority|nida|tra|nhif|nssf).{0,40}(contact|send|apply|click)\b",
    r"\bverified official\b",
    r"\bofficial government\b",
]

_ALL_PATTERN_GROUPS: list[tuple[str, list[str]]] = [
    ("urgency", _URGENCY_PATTERNS),
    ("fear", _FEAR_PATTERNS),
    ("money_request", _MONEY_REQUEST_PATTERNS),
    ("pii_request", _PII_REQUEST_PATTERNS),
    ("unusual_promise", _UNUSUAL_PROMISE_PATTERNS),
    ("fake_job", _FAKE_JOB_PATTERNS),
    ("phishing", _PHISHING_PATTERNS),
    ("impersonation", _IMPERSONATION_PATTERNS),
]

_COMPILED_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    (name, [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns])
    for name, patterns in _ALL_PATTERN_GROUPS
]

# How each pattern group maps to a threat category
_CATEGORY_SIGNAL_MAP: dict[str, str] = {
    "phishing": "phishing",
    "fake_job": "fake_job",
    "impersonation": "impersonation",
    "urgency": "scam",
    "fear": "scam",
    "money_request": "payment_scam",
    "pii_request": "phishing",
    "unusual_promise": "investment_scam",
}

# Maximum contribution of each group to pattern_score
_GROUP_WEIGHTS: dict[str, int] = {
    "phishing": 30,
    "impersonation": 28,
    "pii_request": 30,
    "money_request": 25,
    "fake_job": 25,
    "unusual_promise": 20,
    "urgency": 15,
    "fear": 15,
}

# Source credibility heuristics (used when a URL is also provided)
_CREDIBLE_DOMAIN_SUFFIXES = (".go.tz", ".gov", ".go.ke", ".go.ug", ".org", ".edu")
_SUSPICIOUS_DOMAIN_SUFFIXES = (".xyz", ".top", ".click", ".tk", ".ml", ".gq", ".ga")


class ContentAnalysisAgent(BaseAgent):
    """
    Agent 1 — Analyses text content for suspicious patterns and claims.

    Parameters
    ----------
    provider : BaseAIProvider, optional
        Pre-built AI provider instance.  When None, the factory
        ``get_ai_provider()`` is called using current settings.
    """
    agent_name = "content_analysis"

    def __init__(
        self,
        provider: str = "mock",           # kept for backward-compat; ignored when ai_provider given
        ai_provider: Optional[BaseAIProvider] = None,
    ):
        super().__init__(provider=provider)
        # Prefer explicitly injected provider over the settings-based factory
        self._ai_provider: Optional[BaseAIProvider] = ai_provider

    def _get_provider(self) -> BaseAIProvider:
        if self._ai_provider is not None:
            return self._ai_provider
        return get_ai_provider()

    def analyze(self, text: str = "", url: str = "", **kwargs) -> AgentResult:
        content = text or url
        if not content.strip():
            return AgentResult(
                success=False,
                agent_name=self.agent_name,
                error="No content provided for analysis.",
            )

        ai_provider = self._get_provider()

        # ----------------------------------------------------------------
        # Step 1: Rule-based pattern matching (fast, always runs)
        # ----------------------------------------------------------------
        matched_groups, pattern_score = self._run_pattern_matching(content)

        # ----------------------------------------------------------------
        # Step 2: Source credibility heuristic (URL-based, if available)
        # ----------------------------------------------------------------
        source_credibility_boost = self._assess_source(url)

        # ----------------------------------------------------------------
        # Step 3: AI semantic analysis
        # ----------------------------------------------------------------
        ai_response = ai_provider.analyze_content(content)

        if ai_response.success:
            ai_score = ai_response.risk_score
            ai_findings = ai_response.findings
            claims = ai_response.claims
            ai_category = ai_response.category
            confidence = ai_response.confidence
            used_provider = ai_response.provider
            used_model = ai_response.model_id
        else:
            # Provider returned an error — trust only pattern matching
            ai_score = 0
            ai_findings = []
            claims = self._extract_claims_from_text(content)
            ai_category = "unknown"
            confidence = 40
            used_provider = ai_response.provider
            used_model = ""
            if ai_response.error:
                logger.warning(
                    "ContentAnalysisAgent: AI provider error — %s", ai_response.error
                )

        # ----------------------------------------------------------------
        # Step 4: Determine dominant category
        # ----------------------------------------------------------------
        category = ai_category
        if category == "unknown" and matched_groups:
            # Fall back to highest-weight matched pattern group
            dominant = max(
                matched_groups,
                key=lambda g: _GROUP_WEIGHTS.get(g, 5) * len(matched_groups[g]),
            )
            category = _CATEGORY_SIGNAL_MAP.get(dominant, "scam")

        # ----------------------------------------------------------------
        # Step 5: Blend scores
        # ----------------------------------------------------------------
        ai_weight = float(getattr(settings, "CONTENT_AI_WEIGHT", _DEFAULT_AI_WEIGHT))
        pattern_weight = 1.0 - ai_weight
        combined_score = int(min(100, ai_score * ai_weight + pattern_score * pattern_weight))

        # Apply source credibility adjustment (−10 for known good domains)
        combined_score = max(0, combined_score + source_credibility_boost)

        # ----------------------------------------------------------------
        # Step 6: Build findings list
        # ----------------------------------------------------------------
        pattern_findings = [
            f"Detected {gname.replace('_', ' ')} language pattern ({len(hits)} signal{'s' if len(hits) > 1 else ''})"
            for gname, hits in matched_groups.items()
        ]
        all_findings = ai_findings + pattern_findings

        # ----------------------------------------------------------------
        # Step 7: Calibrate confidence
        # ----------------------------------------------------------------
        confidence = self._calibrate_confidence(
            base_confidence=confidence,
            ai_succeeded=ai_response.success,
            pattern_hit_count=sum(len(v) for v in matched_groups.values()),
            combined_score=combined_score,
        )

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            score=combined_score,
            confidence=confidence,
            provider=used_provider,
            model_id=used_model,
            findings=all_findings,
            data={
                "category": category,
                "claims": claims,
                "matched_pattern_groups": {k: len(v) for k, v in matched_groups.items()},
                "pattern_score": pattern_score,
                "ai_score": ai_score,
                "blend": {"ai_weight": ai_weight, "pattern_weight": pattern_weight},
                "source_credibility_boost": source_credibility_boost,
                "ai_details": ai_response.details,
                "ai_provider": used_provider,
                "ai_model": used_model,
            },
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_pattern_matching(text: str) -> tuple[dict[str, list[str]], int]:
        """
        Scan text against all compiled pattern groups.

        Returns
        -------
        matched_groups : dict[group_name, list[matched_pattern_strings]]
        pattern_score  : 0–100 weighted aggregate
        """
        matched: dict[str, list[str]] = {}
        for group_name, patterns in _COMPILED_PATTERNS:
            hits = [p.pattern for p in patterns if p.search(text)]
            if hits:
                matched[group_name] = hits

        if not matched:
            return {}, 0

        score = min(100, sum(_GROUP_WEIGHTS.get(g, 10) for g in matched))
        return matched, score

    @staticmethod
    def _assess_source(url: str) -> int:
        """
        Return a credibility score adjustment based on domain heuristics.

        - Known credible TLD suffix → −10 (lowers risk)
        - Known suspicious TLD suffix → +5 (raises risk)
        - Unknown → 0
        """
        if not url:
            return 0
        url_lower = url.lower()
        for suffix in _CREDIBLE_DOMAIN_SUFFIXES:
            if suffix in url_lower:
                return -10
        for suffix in _SUSPICIOUS_DOMAIN_SUFFIXES:
            if url_lower.endswith(suffix) or f"{suffix}/" in url_lower:
                return 5
        return 0

    @staticmethod
    def _extract_claims_from_text(text: str) -> list[dict]:
        """
        Fallback claim extractor used when the AI provider fails.
        Splits text into sentence fragments and marks each for verification.
        """
        fragments = re.split(r"[.!?\n]+", text)
        claims = []
        for s in fragments[:5]:
            s = s.strip()
            if len(s) > 20:
                claims.append({"text": s, "requires_verification": True, "is_suspicious": False})
        return claims

    @staticmethod
    def _calibrate_confidence(
        base_confidence: int,
        ai_succeeded: bool,
        pattern_hit_count: int,
        combined_score: int,
    ) -> int:
        """
        Adjust confidence based on the quality of available evidence.

        Rules
        -----
        - AI succeeded → base stays
        - AI failed     → reduce by 15 (less certain without semantic analysis)
        - Many pattern hits → small boost
        - Very high or very low score → higher confidence in the classification
        """
        conf = base_confidence
        if not ai_succeeded:
            conf -= 15
        if pattern_hit_count >= 5:
            conf += 8
        elif pattern_hit_count >= 2:
            conf += 4
        if combined_score >= 75 or combined_score <= 10:
            conf += 5
        return max(25, min(95, conf))
