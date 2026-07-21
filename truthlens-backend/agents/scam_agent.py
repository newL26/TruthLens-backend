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
            r"\bscholarship.*\b(no requirement|no qualification|anyone can apply)\b",
            r"\bfree.*\bscholarship\b.*\b(apply|whatsapp|telegram|link)\b",
        ],
        "base_score": 62,
    },
    "fake_job": {
        "patterns": [
            r"\b(urgent|immediate) (hiring|vacancy|job)\b",
            r"\bwork (from home|online)\b.*\b(earn|income|salary)\b.*\b(daily|weekly)\b",
            r"\bno (experience|degree|qualification) (needed|required)\b",
            r"\bsalary\b.*\bper (day|week)\b.*\bwhatsapp\b",
            r"\bjob offer\b.*\bsend (cv|resume) (to|via) whatsapp\b",
            r"\bdata entry.*\b(daily|weekly) pay\b",
            r"\b(typing|copy.?paste) job\b",
            r"\b(earn|make)\b.{0,20}\b(daily|per day)\b.{0,30}\b(no experience|from home|online)\b",
            r"\bpart[- ]?time.*\b(daily|weekly).*\bpay\b",
            r"\bonline job.*\b(apply|whatsapp|telegram)\b",
            r"\bwork online.*\b(earn|income|\$|pay)\b",
        ],
        "base_score": 58,
    },
    "investment_scam": {
        "patterns": [
            r"\binvest (only )?\$?\d+.*\b(return|earn|get back)\b",
            r"\b\d+%.*\b(profit|return|ROI)\b.*\b(guaranteed|daily|weekly)\b",
            r"\bpyramid\b|\bponzi\b|\bmlm\b",
            r"\bdouble (your )?(money|investment)\b",
            r"\bcrypto.*\bguaranteed\b",
            r"\bforex.*\bguaranteed (profit|return)\b",
            r"\b(100|200|300|500)%\b.*\b(return|profit|ROI)\b",
            r"\bguaranteed (profit|return|income|earnings)\b",
            r"\bbinary options?\b",
            r"\bforex (signal|robot|trading)\b.*\b(profit|earn|daily)\b",
            r"\b(referral|recruit).*\b(bonus|commission|earn)\b",
            r"\bpassive income\b.*\b(daily|weekly|guaranteed)\b",
            r"\bmultiply (your )?(money|investment|funds)\b",
            r"\b(withdraw|cashout)\b.{0,30}\b(daily|anytime|immediately)\b",
        ],
        "base_score": 72,
    },
    "phishing": {
        "patterns": [
            r"\bclick (here|the link)\b.*\bverify\b",
            r"\b(your|the) (account|password) (will be|has been) (suspended|locked|closed|blocked|terminated)\b",
            r"\bupdate (your )?(billing|payment|card) (info|information|details)\b",
            r"\benter (your )?(otp|pin|password|code)\b",
            r"\bconfirm (your )?(account|identity|email)\b.*\blink\b",
            r"\b(your )?(sim|sim card) (will be|has been|is) (blocked|suspended|deactivated)\b",
            r"\bkyc (verification|update|required)\b",
            r"\bverify (your )?(otp|identity|account|sim|number)\b",
            r"\b(share|send|provide) (your )?(otp|one.?time.?password|verification code)\b",
            r"\bdo not share (your )?(otp|pin|password)\b.*\b(except|but|however)\b",
            r"\bparcel.{0,30}\b(delivery|waiting|held|customs)\b.*\b(fee|pay|click)\b",
            r"\bpackage.{0,30}\b(waiting|customs|delivery)\b.*\b(fee|pay|click)\b",
        ],
        "base_score": 76,
    },
    "prize_scam": {
        "patterns": [
            r"\byou (have won|won|are a winner|are the winner)\b",
            r"\bcongratulations.*\b(selected|chosen|winner|prize|lucky)\b",
            r"\bclaim (your )?(prize|reward|winnings|gift|cash)\b",
            r"\blottery.*\b(winner|won|prize)\b",
            r"\bsweepstake\b",
            r"\byou (have been|are) (selected|chosen) (as |to receive )?\b(a prize|a winner|a reward|a gift)\b",
            r"\b(lucky|random) (winner|draw|selection)\b.*\b(you|your number)\b",
            r"\bprize.*\b(claim|collect|receive)\b.*\b(today|now|immediately|within)\b",
            r"\b(iphone|laptop|car|cash prize|gift card)\b.*\b(won|winner|free|claim)\b",
        ],
        "base_score": 80,
    },
    "impersonation": {
        "patterns": [
            r"\bthis is (the|your) bank\b",
            r"\bthis (message is from|is) (the government|police|ministry|president)\b",
            r"\bofficial (notice|message|announcement) from\b",
            r"\bTanzania (Revenue Authority|Government|Police|NIDA)\b.*\bcontact\b",
            r"\b(nida|nhif|nssf|tra|tarura|tanesco)\b.*\b(contact|send|apply|click|verify|update)\b",
            r"\b(verified|official) (representative|agent|officer)\b.*\b(bank|government|ministry)\b",
            r"\bthis message (is from|comes from|sent by) (the )?(government|bank|police|ministry)\b",
        ],
        "base_score": 68,
    },
    "payment_scam": {
        "patterns": [
            r"\bpay (now|first|before|upfront)\b.*\b(delivery|job|course|form|start|training)\b",
            r"\bregistration fee.*\b(before|to|in order|required)\b",
            r"\bprocessing fee\b",
            r"\bsend.*\b(m-pesa|mpesa|airtel money|tigo pesa|halopesa)\b.*\bto receive\b",
            r"\b(small|little|only)\b.{0,20}\b(fee|payment|deposit)\b.{0,30}\b(to receive|to get|before)\b",
            r"\brefundable.*\bfee\b",
            r"\bactivation fee\b",
            r"\b(pay|send|deposit)\b.{0,20}\b(\$|usd|tshs|ksh|naira)\b.{0,20}\b(to receive|to get|to start|to unlock)\b",
        ],
        "base_score": 72,
    },
    "advance_fee": {
        "patterns": [
            r"\b(inheritance|unclaimed) (funds?|money|assets?)\b",
            r"\bnext of kin\b",
            r"\b(fund|money) transfer\b.*\b(your assistance|help|account)\b",
            r"\b\$?\d+\s*(million|billion)\b.*\b(transfer|release|claim|share)\b",
            r"\bdeceased (customer|client|account holder|person)\b.*\b(funds?|money|inheritance)\b",
            r"\bconfidential (business|transfer|proposal|deal)\b",
            r"\byour (bank )?account.*\b(receive|transfer|deposit)\b.*\bmillion\b",
            r"\b(share|split|percentage)\b.{0,30}\b(funds?|money|profit)\b.{0,30}\b(assistance|cooperation|help)\b",
        ],
        "base_score": 75,
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
