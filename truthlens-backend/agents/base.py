"""
agents/base.py — Base AI agent interface for TruthLens AI

All agents return a standardized AgentResult object.
The AI provider (watsonx | mock) is resolved at runtime via settings.AI_PROVIDER.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("agents")


@dataclass
class AgentResult:
    """Standardized result returned by every agent."""
    success: bool
    agent_name: str
    score: int = 0              # 0–100
    confidence: int = 50        # 0–100
    data: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    provider: str = "mock"
    model_id: str = ""
    latency_ms: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "agent": self.agent_name,
            "score": self.score,
            "confidence": self.confidence,
            "findings": self.findings,
            "data": self.data,
            "provider": self.provider,
            "model_id": self.model_id,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


class BaseAgent:
    """Abstract base class for all TruthLens AI agents."""
    agent_name: str = "base"

    def __init__(self, provider: str = "mock"):
        self.provider = provider
        self.logger = logging.getLogger(f"agents.{self.agent_name}")

    def analyze(self, **kwargs) -> AgentResult:
        """Run analysis. Must be overridden by subclasses."""
        raise NotImplementedError

    def _timed_analyze(self, **kwargs) -> AgentResult:
        """Wrap analyze() with latency tracking."""
        start = time.monotonic()
        result = self.analyze(**kwargs)
        result.latency_ms = int((time.monotonic() - start) * 1000)
        return result
