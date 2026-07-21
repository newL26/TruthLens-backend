"""
agents/orchestrator.py — Agent Orchestrator

Coordinates all AI agents into a single analysis pipeline.

Phase 1 pipeline:
  ContentAnalysisAgent → URLAnalysisAgent → ScamDetectionAgent
       → RiskAssessmentAgent → ExplanationAgent
"""
import logging
from typing import Optional
from .content_agent import ContentAnalysisAgent
from .url_agent import URLAnalysisAgent
from .scam_agent import ScamDetectionAgent
from .risk_agent import RiskAssessmentAgent
from .explanation_agent import ExplanationAgent
from services.ai_provider import BaseAIProvider, get_ai_provider

logger = logging.getLogger("agents.orchestrator")


class AnalysisOrchestrator:
    """
    Runs the full Phase 1 analysis pipeline.

    Parameters
    ----------
    provider : str
        Legacy string hint ("mock" | "watsonx").  Ignored when
        ``ai_provider`` is supplied explicitly.
    ai_provider : BaseAIProvider, optional
        Pre-built provider instance to inject into agents.  When None,
        the factory ``get_ai_provider()`` is called once and the same
        instance is shared across all agents that accept one.
    """

    def __init__(
        self,
        provider: str = "mock",
        ai_provider: Optional[BaseAIProvider] = None,
    ):
        self.provider = provider
        # Resolve a single shared provider instance; inject into agents
        # that need semantic analysis (content + explanation).
        # URL, scam, and risk agents are purely rule-based — no provider needed.
        shared_provider: BaseAIProvider = ai_provider or get_ai_provider()

        self.content_agent = ContentAnalysisAgent(
            provider=provider, ai_provider=shared_provider
        )
        self.url_agent = URLAnalysisAgent(provider=provider)
        self.scam_agent = ScamDetectionAgent(provider=provider)
        self.risk_agent = RiskAssessmentAgent(provider=provider)
        self.explanation_agent = ExplanationAgent(provider=provider)

    def run(self, text: str = "", url: str = "") -> dict:
        """
        Execute the full pipeline and return a structured result dict.
        """
        logger.info("Starting analysis pipeline — text_len=%d url=%s", len(text), url or "(none)")

        # --- Agent 1: Content Analysis ---
        content_result = self.content_agent._timed_analyze(text=text, url=url)
        logger.debug("Content agent score=%d", content_result.score)

        # --- URL Analysis (if URL provided) ---
        url_result = None
        if url:
            url_result = self.url_agent._timed_analyze(url=url)
            logger.debug("URL agent score=%d", url_result.score)

        # --- Agent 4: Scam Detection ---
        scam_result = self.scam_agent._timed_analyze(text=text, url=url)
        logger.debug("Scam agent score=%d", scam_result.score)

        # --- Agent 6: Risk Assessment ---
        risk_result = self.risk_agent._timed_analyze(
            content_score=content_result.score,
            url_score=url_result.score if url_result else 0,
            scam_score=scam_result.score,
            community_score=0,  # Phase 3 will populate this
            content_category=content_result.data.get("category", "unknown"),
            scam_category=scam_result.data.get("dominant_category", "none"),
            content_findings=content_result.findings,
            url_findings=url_result.findings if url_result else [],
            scam_findings=scam_result.findings,
        )
        logger.debug("Risk agent final_score=%d level=%s", risk_result.score, risk_result.data.get("risk_level"))

        # --- Agent 7: Explanation ---
        explanation_result = self.explanation_agent._timed_analyze(
            risk_score=risk_result.score,
            risk_level=risk_result.data.get("risk_level", "needs_verification"),
            threat_category=risk_result.data.get("threat_category", "unknown"),
            confidence=risk_result.confidence,
            findings=risk_result.findings,
            recommendation=risk_result.data.get("recommendation", ""),
            content_text=text,
        )

        # Compile agent_logs for AIAnalysisLog records
        agent_logs = [content_result.to_dict()]
        if url_result:
            agent_logs.append(url_result.to_dict())
        agent_logs += [scam_result.to_dict(), risk_result.to_dict(), explanation_result.to_dict()]

        return {
            "success": True,
            "risk_score": risk_result.score,
            "risk_level": risk_result.data.get("risk_level"),
            "risk_label": risk_result.data.get("risk_label"),
            "threat_category": risk_result.data.get("threat_category"),
            "confidence_score": risk_result.confidence,
            "summary": explanation_result.data.get("summary", ""),
            "explanation": explanation_result.data.get("explanation", ""),
            "recommendation": risk_result.data.get("recommendation", ""),
            "disclaimer": explanation_result.data.get("disclaimer", ""),
            "key_findings": risk_result.findings[:8],
            "agent_scores": {
                "content_analysis": content_result.score,
                "url_analysis": url_result.score if url_result else 0,
                "scam_detection": scam_result.score,
                "risk_assessment": risk_result.score,
            },
            "agent_outputs": {
                "content": content_result.to_dict(),
                "url": url_result.to_dict() if url_result else None,
                "scam": scam_result.to_dict(),
                "risk": risk_result.to_dict(),
                "explanation": explanation_result.to_dict(),
            },
            "url_analysis_data": url_result.data if url_result else None,
            "sub_scores": risk_result.data.get("sub_scores", {}),
            "agent_logs": agent_logs,
            "claims": content_result.data.get("claims", []),
        }
