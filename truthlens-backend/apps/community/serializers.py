"""
community/serializers.py — Community report serializers
"""
from rest_framework import serializers
from .models import ScamReport, ThreatCampaign


class ScamReportCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScamReport
        fields = (
            "report_category", "raw_text", "url", "description",
            "phone_number", "country",
        )

    def validate(self, attrs):
        if not attrs.get("raw_text") and not attrs.get("url"):
            raise serializers.ValidationError(
                "Provide either 'raw_text' or 'url' for the report."
            )
        return attrs


class ScamReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScamReport
        fields = (
            "id", "report_category", "status", "country",
            "created_at",
            # NOTE: raw_text and description are intentionally excluded
            # from public responses to protect reporter privacy
        )
        read_only_fields = fields


class ThreatCampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatCampaign
        fields = (
            "id", "title", "description", "threat_category", "status",
            "risk_level", "report_count", "affected_countries",
            "related_urls", "recommendation", "first_detected_at", "last_activity_at",
        )
        read_only_fields = fields
