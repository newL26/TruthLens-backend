"""
tests/test_api.py — Integration tests for TruthLens AI REST API
"""
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from apps.accounts.models import User


class TestAuthAPI(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_success(self):
        response = self.client.post("/api/v1/auth/register/", {
            "email": "testuser@truthlens.ai",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!",
            "full_name": "Test User",
            "country": "Tanzania",
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], "testuser@truthlens.ai")

    def test_register_password_mismatch(self):
        response = self.client.post("/api/v1/auth/register/", {
            "email": "test2@truthlens.ai",
            "password": "SecurePass123!",
            "password_confirm": "WrongPass!",
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success(self):
        User.objects.create_user(email="login@test.com", password="Pass1234!")
        response = self.client.post("/api/v1/auth/login/", {
            "email": "login@test.com",
            "password": "Pass1234!",
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)

    def test_login_wrong_password(self):
        User.objects.create_user(email="wrong@test.com", password="Correct123!")
        response = self.client.post("/api/v1/auth/login/", {
            "email": "wrong@test.com",
            "password": "WrongPass!",
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_requires_auth(self):
        response = self.client.get("/api/v1/auth/profile/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_authenticated(self):
        user = User.objects.create_user(email="profile@test.com", password="Pass1234!")
        self.client.force_authenticate(user=user)
        response = self.client.get("/api/v1/auth/profile/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "profile@test.com")


class TestAnalysisAPI(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_analyze_text_success(self):
        response = self.client.post("/api/v1/analysis/analyze/", {
            "text": "Apply now for a fully funded scholarship. No requirements needed. Act now!"
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("risk_score", response.data)
        self.assertIn("risk_level", response.data)
        self.assertIn("threat_category", response.data)
        self.assertIn("explanation", response.data)
        self.assertIn("recommendation", response.data)

    def test_analyze_url_success(self):
        response = self.client.post("/api/v1/analysis/analyze/", {
            "url": "http://paypal-verify.xyz/login"
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("risk_score", response.data)
        self.assertIsNotNone(response.data.get("url_analysis"))

    def test_analyze_empty_fails(self):
        response = self.client.post("/api/v1/analysis/analyze/", {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_analyze_stores_result(self):
        response = self.client.post("/api/v1/analysis/analyze/", {
            "text": "You have been selected as a winner. Claim your prize now."
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        analysis_id = response.data["id"]

        # Retrieve it
        detail = self.client.get(f"/api/v1/analysis/{analysis_id}/")
        self.assertEqual(detail.status_code, status.HTTP_200_OK)
        self.assertEqual(detail.data["id"], analysis_id)


class TestCommunityAPI(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_submit_report_success(self):
        response = self.client.post("/api/v1/community/report/", {
            "report_category": "fake_job",
            "raw_text": "Urgent hiring! Earn $500 daily. No experience. Apply on WhatsApp.",
            "description": "Suspicious job post on Facebook",
            "country": "Tanzania",
        })
        self.assertIn(response.status_code, [status.HTTP_201_CREATED, status.HTTP_200_OK])
        self.assertIn("report_id", response.data)

    def test_submit_duplicate_report(self):
        data = {
            "report_category": "scam",
            "raw_text": "Send money to receive your prize.",
            "country": "Kenya",
        }
        self.client.post("/api/v1/community/report/", data)
        response = self.client.post("/api/v1/community/report/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("duplicate"))

    def test_campaigns_list(self):
        response = self.client.get("/api/v1/community/campaigns/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_submit_report_no_content_fails(self):
        response = self.client.post("/api/v1/community/report/", {
            "report_category": "scam",
            # No text or url
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestURLInfoAPI(TestCase):
    """Tests for POST /api/v1/analysis/url-info/ (lightweight URL scanner)."""

    def setUp(self):
        self.client = APIClient()

    def test_clean_https_url_returns_low_score(self):
        response = self.client.post("/api/v1/analysis/url-info/", {
            "url": "https://www.bbc.com/news"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("risk_score", response.data)
        self.assertIn("domain", response.data)
        self.assertLessEqual(response.data["risk_score"], 30)

    def test_suspicious_url_returns_high_score(self):
        response = self.client.post("/api/v1/analysis/url-info/", {
            "url": "http://paypal-secure-verify.xyz/login"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(response.data["risk_score"], 40)

    def test_response_contains_all_signal_fields(self):
        response = self.client.post("/api/v1/analysis/url-info/", {
            "url": "https://example.com/test"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for field in ("url", "domain", "risk_score", "risk_label", "confidence",
                      "uses_https", "is_brand_impersonation_suspected",
                      "is_typosquatting_suspected", "suspicious_patterns",
                      "signal_detail", "findings", "tld_risk",
                      "path_depth", "encoding_issues", "latency_ms"):
            self.assertIn(field, response.data, msg=f"Missing response field: {field}")

    def test_brand_impersonation_flag_set(self):
        response = self.client.post("/api/v1/analysis/url-info/", {
            "url": "https://paypal-login.click/confirm"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["is_brand_impersonation_suspected"])

    def test_empty_url_returns_400(self):
        response = self.client.post("/api/v1/analysis/url-info/", {"url": ""})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_url_returns_400(self):
        response = self.client.post("/api/v1/analysis/url-info/", {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_url_without_scheme_accepted(self):
        """Scheme-less URLs should be accepted and normalised to https://."""
        response = self.client.post("/api/v1/analysis/url-info/", {
            "url": "example-scholarship.xyz/apply"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("risk_score", response.data)

    def test_full_analyze_stores_url_analysis(self):
        """End-to-end: full /analyze/ with URL should persist url_analysis record."""
        response = self.client.post("/api/v1/analysis/analyze/", {
            "url": "http://paypal-verify.xyz/login"
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        url_analysis = response.data.get("url_analysis")
        self.assertIsNotNone(url_analysis)
        # Verify new fields are present in serialized output
        self.assertIn("tld_risk", url_analysis)
        self.assertIn("path_depth", url_analysis)
        self.assertIn("encoding_issues", url_analysis)
        self.assertIn("signal_detail", url_analysis)
        self.assertIn("is_typosquatting_suspected", url_analysis)
