"""analysis/admin.py"""
from django.contrib import admin
from .models import Analysis, SubmittedContent, ExtractedClaim, URLAnalysis, RiskAssessment, Evidence, AIAnalysisLog


@admin.register(SubmittedContent)
class SubmittedContentAdmin(admin.ModelAdmin):
    list_display = ("id", "content_type", "user", "created_at")
    list_filter = ("content_type",)
    ordering = ("-created_at",)


@admin.register(Analysis)
class AnalysisAdmin(admin.ModelAdmin):
    list_display = ("id", "status", "risk_level", "threat_category", "risk_score", "confidence_score", "created_at")
    list_filter = ("status", "risk_level", "threat_category")
    search_fields = ("id",)
    ordering = ("-created_at",)


@admin.register(ExtractedClaim)
class ExtractedClaimAdmin(admin.ModelAdmin):
    list_display = ("claim_text", "is_suspicious", "requires_verification")
    list_filter = ("is_suspicious", "requires_verification")


@admin.register(URLAnalysis)
class URLAnalysisAdmin(admin.ModelAdmin):
    list_display = ("url", "domain", "uses_https", "url_risk_score", "created_at")
    ordering = ("-created_at",)


@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    list_display = ("analysis", "total_risk_score", "created_at")
    ordering = ("-created_at",)


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ("title", "evidence_type", "source_name", "is_mock", "created_at")
    list_filter = ("evidence_type", "is_mock")


@admin.register(AIAnalysisLog)
class AIAnalysisLogAdmin(admin.ModelAdmin):
    list_display = ("agent_name", "provider", "model_id", "success", "latency_ms", "created_at")
    list_filter = ("agent_name", "provider", "success")
    ordering = ("-created_at",)
