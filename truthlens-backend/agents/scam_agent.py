"""
agents/scam_agent.py — Agent 4: Scam Detection Agent

Detects patterns associated with:
- Phishing, fake jobs, fake scholarships
- Investment scams, payment scams
- Impersonation, prize scams, urgency-based fraud
"""
import logging
import re
from .base import BaseAgent, AgentResult

logger = logging.getLogger("agents.scam_agent")

SCAM_PROFILES = {
    "fake_scholarship": {
        "patterns": [
            r"\bscholarship\b.*\b(apply|application|free|no requirement)\b",
            r"\b(fully funded|full scholarship)\b.*\b(whatsapp|telegram|click|link)\b",
            r"\bscholarship.*\bregistration fee\b",
            r"\bapply.*\bscholarship\b.*\btoday\b",
            r"\bgovernment.*\bscholarship\b.*\bfree\b",
            r"\bUN\b.*\bscholarship\b",
        ],
        "base_score": 60,
    },
    "fake_job": {
        "patterns": [
            r"\b(urgent|immediate) (hiring|vacancy|job)\b",
            r"\bwork (from home|online)\b.*\b(earn|income|salary)\b.*\b(daily|weekly)\b",
            r"\bno (experience|degree|qualification) (needed|required)\b",
            r"\bsalary\b.*\bper (day|week)\b.*\bwhatsapp\b",
            r"\bjob offer\b.*\bsend (cv|resume) (to|via) whatsapp\b",
            r"\bdata entry.*\b(daily|weekly) pay\b",
        ],
        "base_score": 55,
    },
    "investment_scam": {
        "patterns": [
            r"\binvest (only )?\$?\d+.*\b(return|earn|get back)\b",
            r"\b\d+%.*\b(profit|return|ROI)\b.*\b(guaranteed|daily|weekly)\b",
            r"\bpyramid\b|\bponzi\b|\bmlm\b",
            r"\bdouble (your )?(money|investment)\b",
            r"\bcrypto.*\bguaranteed\b",
            r"\bforex.*\bguaranteed (profit|return)\b",
        ],
        "base_score": 70,
    },
    "phishing": {
        "patterns": [
            r"\bclick (here|the link)\b.*\bverify\b",
            r"\b(your|the) (account|password) (will be|has been) (suspended|locked|closed)\b",
            r"\bupdate (your )?(billing|payment|card) (info|information|details)\b",
            r"\benter (your )?(otp|pin|password)\b",
            r"\bconfirm (your )?(account|identity|email)\b.*\blink\b",
        ],
        "base_score": 75,
    },
    "prize_scam": {
        "patterns": [
            r"\byou (have won|won|are a winner)\b",
            r"\bcongratulations.*\b(selected|chosen|winner|prize)\b",
            r"\bclaim (your )?(prize|reward|winnings)\b",
            r"\blottery.*\b(winner|won|prize)\b",
            r"\bsweepstake\b",
        ],
        "base_score": 80,
    },
    "impersonation": {
        "patterns": [
            r"\bthis is (the|your) bank\b",
            r"\bthis (message is from|is) (the government|police|ministry|president)\b",
            r"\bofficial (notice|message|announcement) from\b",
            r"\bTanzania (Revenue Authority|Government|Police|NIDA)\b.*\bcontact\b",
        ],
        "base_score": 65,
    },
    "payment_scam": {
        "patterns": [
            r"\bpay (now|first|before|upfront)\b.*\b(delivery|job|course|form)\b",
            r"\bregistration fee.*\b(before|to|in order)\b",
            r"\bprocessing fee\b",
            r"\bsend.*\b(m-pesa|mpesa|airtel money|tigo pesa|halopesa)\b.*\bto receive\b",
        ],
        "base_score": 70,
    },
}

COMPILED_SCAM_PROFILES = {
    category: {
        "patterns": [re.compile(p, re.IGNORECASE) for p in profile["patterns"]],
        "base_score": profile["base_score"],
    }
    for category, profile in SCAM_PROFILES.items()
}


class ScamDetectionAgent(BaseAgent):
    """Agent 4 — Detects known scam patterns in content."""
    agent_name = "scam_detection"

    def analyze(self, text: str = "", url: str = "", **kwargs) -> AgentResult:
        content = text or url
        if not content.strip():
            return AgentResult(
                success=False, agent_name=self.agent_name, error="No content provided."
            )

        findings = []
        detected_categories = {}
        max_score = 0

        for category, profile in COMPILED_SCAM_PROFILES.items():
            hits = [p.pattern for p in profile["patterns"] if p.search(content)]
            if hits:
                cat_score = min(100, profile["base_score"] + len(hits) * 5)
                detected_categories[category] = {
                    "score": cat_score,
                    "matched_patterns": len(hits),
                }
                max_score = max(max_score, cat_score)
                findings.append(f"Matches {category.replace('_', ' ')} scam pattern ({len(hits)} signal(s))")

        dominant_category = (
            max(detected_categories, key=lambda c: detected_categories[c]["score"])
            if detected_categories
            else "none"
        )

        confidence = min(95, 50 + len(detected_categories) * 10) if detected_categories else 30

        return AgentResult(
            success=True,
            agent_name=self.agent_name,
            score=max_score,
            confidence=confidence,
            provider="internal",
            findings=findings,
            data={
                "detected_categories": detected_categories,
                "dominant_category": dominant_category,
                "total_categories_matched": len(detected_categories),
            },
        )
