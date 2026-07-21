"""community/admin.py"""
from django.contrib import admin
from .models import ScamReport, ThreatCampaign, AuditLog


@admin.register(ScamReport)
class ScamReportAdmin(admin.ModelAdmin):
    list_display = ("id", "report_category", "status", "country", "created_at")
    list_filter = ("status", "report_category", "country")
    search_fields = ("raw_text", "url", "description")
    ordering = ("-created_at",)


@admin.register(ThreatCampaign)
class ThreatCampaignAdmin(admin.ModelAdmin):
    list_display = ("title", "threat_category", "status", "risk_level", "report_count", "first_detected_at")
    list_filter = ("status", "threat_category", "risk_level")
    search_fields = ("title", "description")
    ordering = ("-last_activity_at",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "actor_email", "target", "ip_address", "created_at")
    list_filter = ("action",)
    search_fields = ("actor_email", "action", "target")
    ordering = ("-created_at",)
    readonly_fields = ("id", "created_at")
