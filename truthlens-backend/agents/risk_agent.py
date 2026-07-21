"""
agents/risk_agent.py — Agent 6: Risk Assessment Agent

Combines signals from all other agents to produce a final risk score,
threat category, confidence level, and recommended action.
"""
import logging
from django.conf import settings
from .base import BaseAgent, AgentResult

logger = logging.getLogger("agents.risk_agent")

RISK_LEVELS = [
    (0, 15, "trustworthy", "Likely Trustworthy"),
    (16, 30, "mostly_trustworthy", "Mostly Trustworthy"),
    (31, 50, "needs_verification", "Needs Verification"),
    (51, 65, "suspicious", "Suspicious"),
    (66, 79, "high_risk", "High Risk"),
    (80, 89, "scam", "Potential Scam"),
    (90, 100, "misinformation", "Potential Misinformation / High Risk"),
]

RECOMMENDATIONS = {
    "trustworthy": "This content appears to be legitimate based on available signals. Always apply your own judgment.",
    "mostly_trustworthy": "This content appears mostly trustworthy, but independent verification is advisable.",
    "needs_verification": "This content requires further verification before acting on it. Do not share sensitive information.",
    "suspicious": "This content contains suspicious signals. Do not provide personal information, send money, or click links until independently verified.",
    "high_risk": "HIGH RISK: Do not engage with this content. Avoid clicking links, providing personal information, or making payments. Report if received.",
    "scam": "POTENTIAL SCAM: This content exhibits strong scam indicators. Do not respond, click links, or send money. Report to authorities.",
    "misinformation": "POTENTIAL MISINFORMATION: This content may be false or misleading. Verify through official sources before sharing.",
}


class RiskAssessmentAgent(BaseAgent):
    """Agent 6 — Aggregates all agent scores into a final risk assessment."""
    agent_name = "risk_assessment"

    def analyze(
        self,
        content_score: int = 0,
        url_score: int = 0,
        scam_score: int = 0,
        community_score: int = 0,
        content_category: str = "unknown",
        scam_category: str = "none",
        content_findings: list = None,
        url_findings: list = None,
        scam_findings: list = None,
        **kwargs,
    ) -> AgentResult:
        content_findings = content_findings or []
        url_findings = url_findings or []
        scam_findings = scam_findings or []

        weights = getattr(settings, "RISK_SCORE_WEIGHTS", {
            "content_analysis": 0.20,
            "source_reliability": 0.20,
            "evidence_verification": 0.25,
            "url_risk": 0.15,
            "community_reports": 0.10,
            "scam_pattern_detection": 0.10,
        })

        # For Phase 1, source_reliability and evidence_verification use content_score
        # as a proxy (no external evidence retrieval yet)
        source_score = min(content_score + 10, 100)
        evidence_score = content_score

        total = (
            content_score * weights["content_analysis"]
            + source_score * weights["source_reliability"]
            + evidence_score * weights["evidence_verification"]
            + url_score * weights["url_risk"]
            + community_score * weights["community_reports"]
            + scam_score * weights["scam_pattern_detection"]
        )
        total = int(min(100, total))

        # Boost if scam patterns are dominant
        if scam_score >= 70 and scam_category != "none":
            total = min(100, total + 10)

        risk_key, risk_label = self._get_risk_level(total)
        recommendation = RECOMMENDATIONS[risk_key]

        # Determine final category
        category = self._resolve_category(content_category, scam_category, total)

        all_findings = content_findings + url_findings + scam_findings
        unique_findings = list(dict.fromkeys(all_findings))  # deduplicate preserving order

        confidence = self._compute_confidence(
            content_score, url_score, scam_score, all_findings
        )

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            score=total,
            confidence=confidence,
            provider="internal",
            findings=unique_findings,
            data={
                "risk_level": risk_key,
                "risk_label": risk_label,
                "threat_category": category,
                "recommendation": recommendation,
                "sub_scores": {
                    "content_analysis": content_score,
                    "source_reliability": source_score,
                    "evidence_verification": evidence_score,
                    "url_risk": url_score,
                    "community_reports": community_score,
                    "scam_pattern_detection": scam_score,
                },
                "weights_used": weights,
            },
        )

    @staticmethod
    def _get_risk_level(score: int) -> tuple[str, str]:
        for low, high, key, label in RISK_LEVELS:
            if low <= score <= high:
                return key, label
        return "high_risk", "High Risk"

    @staticmethod
    def _resolve_category(content_cat: str, scam_cat: str, score: int) -> str:
        if scam_cat and scam_cat != "none":
            return scam_cat
        if content_cat and content_cat != "unknown":
            return content_cat
        if score >= 66:
            return "scam"
        if score >= 31:
            return "unknown"
        return "other"

    @staticmethod
    def _compute_confidence(
        content_score: int, url_score: int, scam_score: int, findings: list
    ) -> int:
        base = 40
        if content_score > 0:
            base += 15
        if url_score > 0:
            base += 15
        if scam_score > 0:
            base += 20
        if len(findings) >= 3:
            base += 10
        return min(95, base)
