"""
analysis/models.py — Core analysis models for TruthLens AI
"""
import uuid
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class ContentType(models.TextChoices):
    TEXT = "text", "Text"
    URL = "url", "URL"
    IMAGE = "image", "Image"
    DOCUMENT = "document", "Document"


class ThreatCategory(models.TextChoices):
    FAKE_NEWS = "fake_news", "Fake News"
    SCAM = "scam", "Scam"
    PHISHING = "phishing", "Phishing"
    FAKE_JOB = "fake_job", "Fake Job"
    FAKE_SCHOLARSHIP = "fake_scholarship", "Fake Scholarship"
    INVESTMENT_SCAM = "investment_scam", "Investment Scam"
    IMPERSONATION = "impersonation", "Impersonation"
    FRAUD = "fraud", "Fraud"
    HEALTH_MISINFO = "health_misinfo", "Health Misinformation"
    POLITICAL_MISINFO = "political_misinfo", "Political Misinformation"
    SUSPICIOUS_URL = "suspicious_url", "Suspicious URL"
    OTHER = "other", "Other"
    UNKNOWN = "unknown", "Unknown"


class RiskLevel(models.TextChoices):
    TRUSTWORTHY = "trustworthy", "Likely Trustworthy"
    MOSTLY_TRUSTWORTHY = "mostly_trustworthy", "Mostly Trustworthy"
    NEEDS_VERIFICATION = "needs_verification", "Needs Verification"
    SUSPICIOUS = "suspicious", "Suspicious"
    HIGH_RISK = "high_risk", "High Risk"
    SCAM = "scam", "Potential Scam"
    MISINFORMATION = "misinformation", "Potential Misinformation"


class AnalysisStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    PROCESSING = "processing", "Processing"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"


class SubmittedContent(models.Model):
    """Raw content submitted by a user for analysis."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="submissions")
    content_type = models.CharField(max_length=20, choices=ContentType.choices)
    raw_text = models.TextField(blank=True)
    url = models.URLField(max_length=2048, blank=True)
    file = models.FileField(upload_to="uploads/%Y/%m/", null=True, blank=True)
    extracted_text = models.TextField(blank=True)  # OCR result if image/doc
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "submitted_content"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.content_type} — {self.id}"

    @property
    def analyzable_text(self):
        """Return the best available text for analysis."""
        return self.extracted_text or self.raw_text or self.url


class Analysis(models.Model):
    """Complete analysis record for a submitted content item."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    content = models.OneToOneField(
        SubmittedContent, on_delete=models.CASCADE, related_name="analysis"
    )
    status = models.CharField(
        max_length=20, choices=AnalysisStatus.choices, default=AnalysisStatus.PENDING
    )
    # Risk
    risk_score = models.SmallIntegerField(null=True, blank=True)  # 0–100
    risk_level = models.CharField(
        max_length=30, choices=RiskLevel.choices, blank=True
    )
    threat_category = models.CharField(
        max_length=30, choices=ThreatCategory.choices, default=ThreatCategory.UNKNOWN
    )
    confidence_score = models.SmallIntegerField(null=True, blank=True)  # 0–100
    # Summary
    summary = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    # Agent sub-scores (stored as JSON)
    agent_scores = models.JSONField(default=dict)
    # Raw agent outputs
    agent_outputs = models.JSONField(default=dict)
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    # Error if analysis failed
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = "analysis"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["risk_level"]),
            models.Index(fields=["threat_category"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Analysis {self.id} — {self.risk_level}"


class ExtractedClaim(models.Model):
    """Individual claims extracted from content during analysis."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="claims")
    claim_text = models.TextField()
    claim_type = models.CharField(max_length=50, blank=True)
    requires_verification = models.BooleanField(default=False)
    is_suspicious = models.BooleanField(default=False)
    suspicion_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "extracted_claim"

    def __str__(self):
        return f"Claim: {self.claim_text[:80]}"


class URLAnalysis(models.Model):
    """Detailed analysis of a URL or domain."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analysis = models.OneToOneField(
        Analysis, on_delete=models.CASCADE, related_name="url_analysis", null=True, blank=True
    )
    url = models.URLField(max_length=2048)
    domain = models.CharField(max_length=255, blank=True)
    uses_https = models.BooleanField(null=True)
    domain_age_days = models.IntegerField(null=True, blank=True)
    is_typosquatting_suspected = models.BooleanField(default=False)
    is_brand_impersonation_suspected = models.BooleanField(default=False)
    redirects_detected = models.BooleanField(default=False)
    redirect_chain = models.JSONField(default=list)
    # New fields added with URL module upgrade
    redirect_count = models.SmallIntegerField(default=0)
    final_url = models.URLField(max_length=2048, blank=True)
    tld_risk = models.SmallIntegerField(default=0)
    path_depth = models.SmallIntegerField(default=0)
    encoding_issues = models.BooleanField(default=False)
    signal_detail = models.JSONField(default=dict)
    suspicious_patterns = models.JSONField(default=list)
    reputation_signals = models.JSONField(default=dict)
    url_risk_score = models.SmallIntegerField(null=True, blank=True)
    url_risk_details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "url_analysis"
        indexes = [models.Index(fields=["domain"])]

    def __str__(self):
        return f"URL: {self.url[:80]}"


class RiskAssessment(models.Model):
    """Final aggregated risk assessment combining all agent signals."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analysis = models.OneToOneField(
        Analysis, on_delete=models.CASCADE, related_name="risk_assessment"
    )
    # Weighted sub-scores
    content_analysis_score = models.SmallIntegerField(default=0)
    source_reliability_score = models.SmallIntegerField(default=0)
    evidence_score = models.SmallIntegerField(default=0)
    url_risk_score = models.SmallIntegerField(default=0)
    community_score = models.SmallIntegerField(default=0)
    scam_pattern_score = models.SmallIntegerField(default=0)
    # Final
    total_risk_score = models.SmallIntegerField(default=0)
    weights_used = models.JSONField(default=dict)
    key_findings = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "risk_assessment"

    def __str__(self):
        return f"Risk {self.total_risk_score}/100 — analysis {self.analysis_id}"


class Evidence(models.Model):
    """Evidence items collected to support or contradict a claim."""
    class EvidenceType(models.TextChoices):
        SUPPORTING = "supporting", "Supporting"
        CONTRADICTING = "contradicting", "Contradicting"
        NEUTRAL = "neutral", "Neutral"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analysis = models.ForeignKey(Analysis, on_delete=models.CASCADE, related_name="evidence")
    evidence_type = models.CharField(max_length=20, choices=EvidenceType.choices)
    title = models.CharField(max_length=512, blank=True)
    description = models.TextField()
    source_url = models.URLField(max_length=2048, blank=True)
    source_name = models.CharField(max_length=255, blank=True)
    reliability_score = models.SmallIntegerField(null=True, blank=True)
    is_mock = models.BooleanField(default=False)  # True when from mock/internal analysis
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "evidence"

    def __str__(self):
        return f"[{self.evidence_type}] {self.title[:60]}"


class AIAnalysisLog(models.Model):
    """Log of every AI agent invocation for auditability."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    analysis = models.ForeignKey(
        Analysis, on_delete=models.CASCADE, related_name="ai_logs", null=True, blank=True
    )
    agent_name = models.CharField(max_length=100)
    provider = models.CharField(max_length=50)  # watsonx | mock
    model_id = models.CharField(max_length=100, blank=True)
    prompt_tokens = models.IntegerField(default=0)
    completion_tokens = models.IntegerField(default=0)
    latency_ms = models.IntegerField(default=0)
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ai_analysis_log"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.agent_name} — {self.provider} — {self.created_at}"
