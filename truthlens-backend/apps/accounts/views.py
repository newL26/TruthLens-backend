"""
accounts/views.py — Authentication views for TruthLens AI
"""
import logging
from django.contrib.auth import get_user_model
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    TruthLensTokenObtainPairSerializer,
)
from utils.audit import log_audit

logger = logging.getLogger("apps.accounts")
User = get_user_model()


class RegisterView(generics.CreateAPIView):
    """POST /api/v1/auth/register/ — create a new user account"""
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        log_audit(
            actor=None,
            action="USER_REGISTER",
            target=str(user.id),
            ip=_get_client_ip(request),
        )
        logger.info("New user registered: %s", user.email)
        return Response(
            {"message": "Account created successfully.", "user": UserSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )


class LoginView(TokenObtainPairView):
    """POST /api/v1/auth/login/ — obtain JWT tokens"""
    serializer_class = TruthLensTokenObtainPairSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            log_audit(
                actor=None,
                action="USER_LOGIN",
                target=request.data.get("email", ""),
                ip=_get_client_ip(request),
            )
        return response


class LogoutView(APIView):
    """POST /api/v1/auth/logout/ — blacklist refresh token"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken(refresh_token)
            token.blacklist()
            log_audit(
                actor=request.user,
                action="USER_LOGOUT",
                target=str(request.user.id),
                ip=_get_client_ip(request),
            )
            return Response({"message": "Logged out successfully."})
        except Exception as exc:
            logger.warning("Logout error: %s", exc)
            return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(generics.RetrieveUpdateAPIView):
    """GET/PATCH /api/v1/auth/profile/ — view and update user profile"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class ChangePasswordView(APIView):
    """POST /api/v1/auth/change-password/ — change user password"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        log_audit(
            actor=request.user,
            action="PASSWORD_CHANGE",
            target=str(request.user.id),
            ip=_get_client_ip(request),
        )
        return Response({"message": "Password changed successfully."})


def _get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
