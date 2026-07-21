"""
analysis/serializers.py — Serializers for analysis API
"""
from rest_framework import serializers
from .models import (
    Analysis,
    SubmittedContent,
    ExtractedClaim,
    URLAnalysis,
    RiskAssessment,
    Evidence,
)


class SubmittedContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubmittedContent
        fields = ("id", "content_type", "raw_text", "url", "created_at")
        read_only_fields = ("id", "created_at")


class ExtractedClaimSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExtractedClaim
        fields = ("id", "claim_text", "claim_type", "requires_verification", "is_suspicious", "suspicion_reason")


class URLAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLAnalysis
        fields = (
            "url", "domain", "uses_https", "domain_age_days",
            "is_typosquatting_suspected", "is_brand_impersonation_suspected",
            "redirects_detected", "redirect_chain",
            "redirect_count", "final_url",
            "tld_risk", "path_depth", "encoding_issues", "signal_detail",
            "suspicious_patterns", "reputation_signals",
            "url_risk_score", "url_risk_details",
        )


class RiskAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskAssessment
        fields = (
            "content_analysis_score", "source_reliability_score", "evidence_score",
            "url_risk_score", "community_score", "scam_pattern_score",
            "total_risk_score", "weights_used", "key_findings",
        )


class EvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = ("id", "evidence_type", "title", "description", "source_url", "source_name", "reliability_score", "is_mock")


class AnalysisSerializer(serializers.ModelSerializer):
    content = SubmittedContentSerializer(read_only=True)
    claims = ExtractedClaimSerializer(many=True, read_only=True)
    url_analysis = URLAnalysisSerializer(read_only=True)
    risk_assessment = RiskAssessmentSerializer(read_only=True)
    evidence = EvidenceSerializer(many=True, read_only=True)

    class Meta:
        model = Analysis
        fields = (
            "id", "status", "risk_score", "risk_level", "threat_category",
            "confidence_score", "summary", "explanation", "recommendation",
            "agent_scores", "content", "claims", "url_analysis",
            "risk_assessment", "evidence", "created_at", "completed_at",
        )
        read_only_fields = fields


class AnalysisListSerializer(serializers.ModelSerializer):
    """Compact serializer for list views."""
    class Meta:
        model = Analysis
        fields = (
            "id", "status", "risk_score", "risk_level", "threat_category",
            "confidence_score", "summary", "created_at",
        )


class AnalyzeTextRequestSerializer(serializers.Serializer):
    """Request body for text analysis."""
    text = serializers.CharField(
        max_length=10000,
        required=False,
        allow_blank=True,
        help_text="Plain text content to analyze.",
    )
    url = serializers.CharField(
        max_length=2048,
        required=False,
        allow_blank=True,
        help_text="URL to analyze.",
    )

    def validate_url(self, value):
        value = value.strip()
        if not value:
            return value
        if not value.startswith(("http://", "https://")):
            value = "https://" + value
        # Validate the normalised URL
        field = serializers.URLField()
        return field.run_validation(value)

    def validate(self, attrs):
        if not attrs.get("text") and not attrs.get("url"):
            raise serializers.ValidationError(
                "Provide either 'text' or 'url' (or both)."
            )
        return attrs


class URLInfoRequestSerializer(serializers.Serializer):
    """Request body for the lightweight URL-info endpoint."""
    url = serializers.CharField(
        max_length=2048,
        required=True,
        help_text="URL to analyze. Scheme may be omitted (https:// assumed).",
    )

    def validate_url(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("URL must not be blank.")
        return value
