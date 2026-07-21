"""community/urls.py"""
from django.urls import path
from . import views

urlpatterns = [
    path("report/", views.SubmitReportView.as_view(), name="submit-report"),
    path("campaigns/", views.ThreatCampaignListView.as_view(), name="campaign-list"),
    path("campaigns/<uuid:id>/", views.ThreatCampaignDetailView.as_view(), name="campaign-detail"),
]
