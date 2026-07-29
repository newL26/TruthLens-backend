"""
analysis/views.py — Analysis API views for TruthLens AI

Phase 1 endpoints:
  POST /api/v1/analysis/analyze/      — submit text/URL for analysis
  GET  /api/v1/analysis/{id}/         — retrieve analysis result
  GET  /api/v1/analysis/              — list user's analyses
  POST /api/v1/analysis/url-info/     — deep URL-only analysis (no DB write)
"""
import logging
from django.conf import settings
from django.utils import timezone
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Analysis,
    SubmittedContent,
    ContentType,
    ExtractedClaim,
    URLAnalysis,
    RiskAssessment,
    Evidence,
    AIAnalysisLog,
    AnalysisStatus,
)
from .serializers import (
    AnalysisSerializer,
    AnalysisListSerializer,
    AnalyzeTextRequestSerializer,
    URLInfoRequestSerializer,
)
from agents.orchestrator import AnalysisOrchestrator
from agents.url_agent import URLAnalysisAgent
from utils.audit import log_audit

logger = logging.getLogger("apps.analysis")


class AnalyzeView(APIView):
    """
    POST /api/v1/analysis/analyze/

    Submit text and/or URL for AI-powered risk analysis.
    Returns a complete analysis result synchronously (Phase 1).

    authentication_classes is intentionally empty: DRF's JWTAuthentication raises
    401 when it encounters an expired/malformed Bearer token even on AllowAny views,
    because authentication runs before permission checks. Removing the authenticator
    from public views lets the request through regardless of any Authorization header
    the client may (or may not) send.
    """
    authentication_classes = []          # Skip JWT validation — public endpoint
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = AnalyzeTextRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        text = serializer.validated_data.get("text", "").strip()
        url = serializer.validated_data.get("url", "").strip()

        # 1. Determine content type
        if url and not text:
            content_type = ContentType.URL
        elif text:
            content_type = ContentType.TEXT
        else:
            content_type = ContentType.TEXT

        # 2. Store submitted content
        content = SubmittedContent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            content_type=content_type,
            raw_text=text,
            url=url,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:512],
        )

        # 3. Create analysis record
        analysis = Analysis.objects.create(
            content=content,
            status=AnalysisStatus.PROCESSING,
        )

        try:
            # 4. Run AI agent orchestrator
            provider = getattr(settings, "AI_PROVIDER", "mock")
            orchestrator = AnalysisOrchestrator(provider=provider)
            result = orchestrator.run(text=text, url=url)

            # 5. Persist agent results
            _persist_analysis_results(analysis, result)

            # 6. Log agent invocations
            for agent_log in result.get("agent_logs", []):
                AIAnalysisLog.objects.create(
                    analysis=analysis,
                    agent_name=agent_log.get("agent", "unknown"),
                    provider=agent_log.get("provider", "mock"),
                    model_id=agent_log.get("model_id", ""),
                    latency_ms=agent_log.get("latency_ms", 0),
                    success=agent_log.get("success", True),
                    error_message=agent_log.get("error") or "",
                )

            log_audit(
                actor=request.user if request.user.is_authenticated else None,
                action="CONTENT_ANALYZED",
                target=str(analysis.id),
                ip=_get_client_ip(request),
            )

            return Response(AnalysisSerializer(analysis).data, status=status.HTTP_201_CREATED)

        except Exception as exc:
            logger.exception("Analysis pipeline failed for analysis %s: %s", analysis.id, exc)
            analysis.status = AnalysisStatus.FAILED
            analysis.error_message = str(exc)[:1000]
            analysis.save(update_fields=["status", "error_message"])
            return Response(
                {"error": "Analysis failed. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class URLInfoView(APIView):
    """
    POST /api/v1/analysis/url-info/

    Lightweight URL-only deep analysis — runs the URL agent standalone and
    returns the full signal breakdown without storing anything to the DB.
    Useful for quick URL checks from the frontend without a full pipeline run.
    """
    authentication_classes = []          # Skip JWT validation — public endpoint
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = URLInfoRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        url = serializer.validated_data["url"]
        agent = URLAnalysisAgent(provider="internal")
        result = agent._timed_analyze(url=url)

        if not result.success:
            return Response(
                {"error": result.error or "URL analysis failed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "url": result.data.get("url"),
                "domain": result.data.get("domain"),
                "risk_score": result.score,
                "risk_label": result.data.get("risk_label"),
                "confidence": result.confidence,
                "uses_https": result.data.get("uses_https"),
                "is_brand_impersonation_suspected": result.data.get("is_brand_impersonation_suspected"),
                "is_typosquatting_suspected": result.data.get("is_typosquatting_suspected"),
                "suspicious_patterns": result.data.get("suspicious_patterns", []),
                "signal_detail": result.data.get("signal_detail", {}),
                "findings": result.findings,
                "tld_risk": result.data.get("tld_risk", 0),
                "path_depth": result.data.get("path_depth", 0),
                "encoding_issues": result.data.get("encoding_issues", False),
                "latency_ms": result.latency_ms,
            },
            status=status.HTTP_200_OK,
        )


class AnalysisDetailView(generics.RetrieveAPIView):
    """GET /api/v1/analysis/{id}/ — retrieve a specific analysis result"""
    serializer_class = AnalysisSerializer
    authentication_classes = []          # Skip JWT validation — public endpoint (share links)
    permission_classes = [permissions.AllowAny]
    lookup_field = "id"

    def get_queryset(self):
        qs = Analysis.objects.select_related(
            "content", "url_analysis", "risk_assessment"
        ).prefetch_related("claims", "evidence")
        # Authenticated users can see their own analyses
        # Unauthenticated can still retrieve by ID (for share links)
        return qs


class AnalysisListView(generics.ListAPIView):
    """GET /api/v1/analysis/ — list analyses for the authenticated user"""
    serializer_class = AnalysisListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Analysis.objects.filter(
            content__user=self.request.user
        ).select_related("content").order_by("-created_at")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _persist_analysis_results(analysis: Analysis, result: dict):
    """Save orchestrator result into DB models."""
    # Update Analysis
    analysis.status = AnalysisStatus.COMPLETED
    analysis.risk_score = result["risk_score"]
    analysis.risk_level = result["risk_level"]
    analysis.threat_category = result["threat_category"]
    analysis.confidence_score = result["confidence_score"]
    analysis.summary = result["summary"]
    analysis.explanation = result["explanation"]
    analysis.recommendation = result["recommendation"]
    analysis.agent_scores = result["agent_scores"]
    analysis.agent_outputs = {
        k: v for k, v in (result.get("agent_outputs") or {}).items()
        if v is not None
    }
    analysis.completed_at = timezone.now()
    analysis.save()

    # Save extracted claims
    for claim in result.get("claims", [])[:10]:
        ExtractedClaim.objects.create(
            analysis=analysis,
            claim_text=claim.get("text", "")[:1000],
            requires_verification=claim.get("requires_verification", False),
            is_suspicious=claim.get("is_suspicious", False),
        )

    # Save URL analysis
    url_data = result.get("url_analysis_data")
    if url_data and analysis.content.url:
        URLAnalysis.objects.create(
            analysis=analysis,
            url=url_data.get("url") or analysis.content.url,
            domain=url_data.get("domain", ""),
            uses_https=url_data.get("uses_https"),
            is_typosquatting_suspected=url_data.get("is_typosquatting_suspected", False),
            is_brand_impersonation_suspected=url_data.get("is_brand_impersonation_suspected", False),
            # New extended fields
            redirect_count=url_data.get("redirect_count", 0),
            final_url=url_data.get("final_url", "") or "",
            tld_risk=url_data.get("tld_risk", 0),
            path_depth=url_data.get("path_depth", 0),
            encoding_issues=url_data.get("encoding_issues", False),
            signal_detail=url_data.get("signal_detail", {}),
            suspicious_patterns=url_data.get("suspicious_patterns", []),
            reputation_signals={
                "online_check": url_data.get("online_check", {}),
                "crosscheck_links": url_data.get("crosscheck_links", {}),
            },
            url_risk_score=result["agent_scores"].get("url_analysis", 0),
            url_risk_details="\n".join(url_data.get("suspicious_patterns", [])),
        )

    # Save RiskAssessment
    sub_scores = result.get("sub_scores", {})
    key_findings = result.get("key_findings", [])
    RiskAssessment.objects.create(
        analysis=analysis,
        content_analysis_score=sub_scores.get("content_analysis", 0),
        source_reliability_score=sub_scores.get("source_reliability", 0),
        evidence_score=sub_scores.get("evidence_verification", 0),
        url_risk_score=sub_scores.get("url_risk", 0),
        community_score=sub_scores.get("community_reports", 0),
        scam_pattern_score=sub_scores.get("scam_pattern_detection", 0),
        total_risk_score=result["risk_score"],
        weights_used=result.get("agent_outputs", {}).get("risk", {}).get("data", {}).get("weights_used", {}),
        key_findings=key_findings,
    )


def _get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
