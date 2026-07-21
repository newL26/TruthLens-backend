"""
community/views.py — Community intelligence API views
"""
import hashlib
import logging
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ScamReport, ThreatCampaign
from .serializers import ScamReportCreateSerializer, ScamReportSerializer, ThreatCampaignSerializer
from utils.audit import log_audit

logger = logging.getLogger("apps.community")


def _content_hash(text: str, url: str) -> str:
    """Create a simple fingerprint to detect duplicate reports."""
    normalized = (text + url).lower().strip()
    return hashlib.sha256(normalized.encode()).hexdigest()[:32]


class SubmitReportView(APIView):
    """POST /api/v1/community/report/ — submit a suspicious content report"""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = ScamReportCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        text = serializer.validated_data.get("raw_text", "")
        url = serializer.validated_data.get("url", "")
        fingerprint = _content_hash(text, url)

        # Check for near-duplicate
        existing = ScamReport.objects.filter(content_hash=fingerprint).first()
        if existing:
            return Response(
                {
                    "message": "Similar report already exists. Your report has been noted.",
                    "report_id": str(existing.id),
                    "duplicate": True,
                },
                status=status.HTTP_200_OK,
            )

        report = serializer.save(
            reporter=request.user if request.user.is_authenticated else None,
            content_hash=fingerprint,
        )

        log_audit(
            actor=request.user if request.user.is_authenticated else None,
            action="SCAM_REPORT_SUBMITTED",
            target=str(report.id),
        )

        logger.info("New scam report: %s category=%s", report.id, report.report_category)

        return Response(
            {
                "message": "Thank you for your report. Our team will review it.",
                "report_id": str(report.id),
            },
            status=status.HTTP_201_CREATED,
        )


class ThreatCampaignListView(generics.ListAPIView):
    """GET /api/v1/community/campaigns/ — list active threat campaigns"""
    serializer_class = ThreatCampaignSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        return ThreatCampaign.objects.filter(
            status__in=["emerging", "active", "confirmed"]
        ).order_by("-last_activity_at")[:20]


class ThreatCampaignDetailView(generics.RetrieveAPIView):
    """GET /api/v1/community/campaigns/{id}/ — campaign detail"""
    serializer_class = ThreatCampaignSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = "id"
    queryset = ThreatCampaign.objects.all()
