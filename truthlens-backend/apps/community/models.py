"""
community/models.py — Community intelligence models for TruthLens AI
"""
import uuid
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class ScamReport(models.Model):
    """User-submitted report of suspicious content."""

    class ReportStatus(models.TextChoices):
        PENDING = "pending", "Pending Review"
        CONFIRMED = "confirmed", "Confirmed Threat"
        REJECTED = "rejected", "Rejected (False Positive)"
        DUPLICATE = "duplicate", "Duplicate"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reporter = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="reports"
    )
    report_category = models.CharField(max_length=30, blank=True)
    raw_text = models.TextField(blank=True)
    url = models.URLField(max_length=2048, blank=True)
    description = models.TextField(blank=True)
    phone_number = models.CharField(max_length=30, blank=True)
    country = models.CharField(max_length=100, blank=True)
    status = models.CharField(
        max_length=20, choices=ReportStatus.choices, default=ReportStatus.PENDING
    )
    # Similarity fingerprint — used to detect duplicates/campaigns
    content_hash = models.CharField(max_length=64, blank=True, db_index=True)
    campaign = models.ForeignKey(
        "ThreatCampaign",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reports",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "scam_report"
        ordering = ["-created_at"]

    def __str__(self):
        return f"Report {self.id} — {self.report_category}"


class ThreatCampaign(models.Model):
    """Aggregated emerging threat campaign detected from similar reports."""

    class CampaignStatus(models.TextChoices):
        EMERGING = "emerging", "Emerging"
        ACTIVE = "active", "Active"
        CONFIRMED = "confirmed", "Confirmed"
        RESOLVED = "resolved", "Resolved"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    threat_category = models.CharField(max_length=30, blank=True)
    status = models.CharField(
        max_length=20, choices=CampaignStatus.choices, default=CampaignStatus.EMERGING
    )
    risk_level = models.CharField(max_length=30, blank=True)
    report_count = models.IntegerField(default=0)
    affected_countries = models.JSONField(default=list)
    related_urls = models.JSONField(default=list)
    related_keywords = models.JSONField(default=list)
    recommendation = models.TextField(blank=True)
    first_detected_at = models.DateTimeField(auto_now_add=True)
    last_activity_at = models.DateTimeField(auto_now=True)
    confirmed_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name="confirmed_campaigns"
    )

    class Meta:
        db_table = "threat_campaign"
        ordering = ["-last_activity_at"]

    def __str__(self):
        return self.title


class AuditLog(models.Model):
    """System-wide audit trail for security and compliance."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor_id = models.CharField(max_length=100, blank=True)
    actor_email = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=100)
    target = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    extra_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_log"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["action"]),
            models.Index(fields=["actor_id"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"{self.action} by {self.actor_email} at {self.created_at}"
