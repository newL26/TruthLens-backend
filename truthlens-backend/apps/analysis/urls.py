"""analysis/urls.py"""
from django.urls import path
from . import views

urlpatterns = [
    path("analyze/", views.AnalyzeView.as_view(), name="analyze"),
    path("url-info/", views.URLInfoView.as_view(), name="url-info"),
    path("", views.AnalysisListView.as_view(), name="analysis-list"),
    path("<uuid:id>/", views.AnalysisDetailView.as_view(), name="analysis-detail"),
]
