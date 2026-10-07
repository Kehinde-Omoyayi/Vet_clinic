import secrets
import time

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiResponse,
    extend_schema,
)

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from django.contrib.auth import authenticate, get_user_model

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .generic import (
    AnonymousOnly,
    is_user_locked,
    locked_response,
    revoke_all_sessions,
)

from .serializers import (
    ForgotPasswordSerializer,
    LoginSerializer,
    LogoutResponseSerializer,
    MarketplaceTokenRefreshSerializer,
    RegisterSerializer,
    RequestOTPSerializer,
    ResetPasswordSerializer,
    VerifyOTPSerializer,
    VerifyResetOTPSerializer,
)

from .tasks import (
    send_otp_email,
    send_password_reset_email,
    send_verification_email,
)



User = get_user_model()


AUTH_OTP_MAX_ATTEMPTS = 5
AUTH_OTP_TTL_SECONDS = 300
RESET_TOKEN_TTL_SECONDS = 600


def _otp_attempts_key(prefix, email):
    return f"{prefix}_attempts_{email}"


def _otp_attempt_is_exhausted(prefix, email):
    key = _otp_attempts_key(prefix, email)

    try:
        return int(cache.get(key) or 0) >= AUTH_OTP_MAX_ATTEMPTS
    except (TypeError, ValueError):
        return False


def _claim_otp_cooldown(key):
    now = time.time()
    cooldown_until = now + AUTH_OTP_TTL_SECONDS

    if cache.add(
        key,
        cooldown_until,
        timeout=AUTH_OTP_TTL_SECONDS,
    ):
        return True, AUTH_OTP_TTL_SECONDS

    existing = cache.get(key)

    if existing:
        try:
            remaining = int(float(existing) - now)
        except (TypeError, ValueError):
            remaining = AUTH_OTP_TTL_SECONDS

        if remaining > 0:
            return False, remaining

    if cache.add(
        key,
        cooldown_until,
        timeout=AUTH_OTP_TTL_SECONDS,
    ):
        return True, AUTH_OTP_TTL_SECONDS

    return False, 1


def _record_failed_otp_attempt(prefix, email):
    key = _otp_attempts_key(prefix, email)

    try:
        if cache.add(
            key,
            1,
            timeout=AUTH_OTP_TTL_SECONDS,
        ):
            return 1

        return int(cache.incr(key))

    except ValueError:
        cache.add(
            key,
            1,
            timeout=AUTH_OTP_TTL_SECONDS,
        )

        return int(cache.get(key) or 1)


def _generate_otp():
    return f"{secrets.randbelow(900000) + 100000:06d}"


# ============================================================
# REGISTER
# ============================================================

class RegisterView(APIView):
    permission_classes = [AnonymousOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_register"
    parser_classes = [JSONParser]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            user = serializer.save()

            email = user.email.lower().strip()
            otp_code = _generate_otp()

            cache.set(
                f"otp_{email}",
                otp_code,
                timeout=AUTH_OTP_TTL_SECONDS,
            )

            transaction.on_commit(
                lambda: send_verification_email.delay(
                    user.first_name,
                    user.email,
                    otp_code,
                )
            )

        return Response(
            {
                "message": (
                    f"Dear esteemed {user.first_name}! "
                    "Your account has been successfully registered."
                ),
                "action": "redirect_to_otp_verification",
                "email": user.email,
                "redirect_to": "/api/v1/verify-otp/",
            },
            status=status.HTTP_201_CREATED,
        )

# ============================================================
# VERIFY REGISTRATION OTP
# ============================================================

class VerifyOTPView(APIView):
    permission_classes = [AnonymousOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_verify_otp"
    parser_classes = [JSONParser]

    @extend_schema(
        request=VerifyOTPSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP verification successful."
            ),
            400: OpenApiResponse(
                description="Invalid or expired OTP."
            ),
            403: OpenApiResponse(
                description="Account locked."
            ),
            429: OpenApiResponse(
                description="Too many OTP attempts."
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].strip().lower()
        user_otp = serializer.validated_data["otp"].strip()

        user = UserModel = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            email__iexact=email
        ).first()

        if not UserModel:
            return Response(
                {"error": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if is_user_locked(UserModel):
            cache.delete(f"otp_{email}")
            cache.delete(_otp_attempts_key("otp", email))
            return locked_response()

        cache_key = f"otp_{email}"

        if _otp_attempt_is_exhausted("otp", email):
            cache.delete(cache_key)

            return Response(
                {
                    "error": (
                        "Too many invalid OTP attempts. "
                        "Please request a new code."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        saved_otp = cache.get(cache_key)

        if saved_otp is None:
            return Response(
                {
                    "error": (
                        f"Esteemed {UserModel.first_name}. "
                        "Your OTP has expired or is invalid. "
                        "Please request a new one."
                    ),
                    "action": "request_new_otp",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not secrets.compare_digest(
            str(saved_otp),
            user_otp,
        ):
            attempts = _record_failed_otp_attempt(
                "otp",
                email,
            )

            if attempts >= AUTH_OTP_MAX_ATTEMPTS:
                cache.delete(cache_key)

                return Response(
                    {
                        "error": (
                            "Too many invalid OTP attempts. "
                            "Please request a new code."
                        )
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            return Response(
                {
                    "error": (
                        f"Esteemed {UserModel.first_name}. "
                        "The code you entered is not right. "
                        "Please try again."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        UserModel.is_active = True
        UserModel.security_status = "NORMAL"
        UserModel.save(
            update_fields=[
                "is_active",
                "security_status",
                "updated_at",
            ]
        )

        cache.delete(cache_key)
        cache.delete(_otp_attempts_key("otp", email))
        cache.delete(f"otp_cooldown_{email}")

        return Response(
            {
                "message": (
                    "OTP verification successful! "
                    "Account is fully ready."
                ),
                "action": "redirect_to_login",
                "redirect_to": "/api/v1/login/",
                "email": UserModel.email,
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# REQUEST REGISTRATION OTP
# ============================================================

class RequestOTPView(APIView):
    permission_classes = [AnonymousOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_request_otp"
    parser_classes = [JSONParser]

    @extend_schema(
        request=RequestOTPSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP request processed."
            ),
            400: OpenApiResponse(
                description="Invalid request."
            ),
            429: OpenApiResponse(
                description="OTP request rate limit reached."
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = RequestOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].strip().lower()

        user = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            email__iexact=email
        ).first()

        if not user:
            return Response(
                {
                    "message": (
                        "If the account is eligible, "
                        "a verification code will be sent."
                    ),
                    "action": "enter_otp",
                    "email": email,
                    "retry_after": AUTH_OTP_TTL_SECONDS,
                },
                status=status.HTTP_200_OK,
            )

        if is_user_locked(user):
            return Response(
                {
                    "message": (
                        "If the account is eligible, "
                        "a verification code will be sent."
                    ),
                    "action": "enter_otp",
                    "email": email,
                    "retry_after": AUTH_OTP_TTL_SECONDS,
                },
                status=status.HTTP_200_OK,
            )

        if user.is_active:
            return Response(
                {
                    "message": (
                        "If the account is eligible, "
                        "a verification code will be sent."
                    ),
                    "action": "login",
                    "email": email,
                },
                status=status.HTTP_200_OK,
            )

        cache_key = f"otp_{email}"
        cooldown_key = f"otp_cooldown_{email}"

        claimed, retry_after = _claim_otp_cooldown(
            cooldown_key
        )

        if not claimed:
            return Response(
                {
                    "error": (
                        f"Esteemed {user.first_name}, "
                        "please wait before requesting another OTP."
                    ),
                    "retry_after": retry_after,
                    "action": "wait",
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        otp_code = _generate_otp()

        cache.set(
            cache_key,
            otp_code,
            timeout=AUTH_OTP_TTL_SECONDS,
        )

        transaction.on_commit(
            lambda: send_otp_email.delay(
                user.first_name,
                user.email,
                otp_code,
            )
        )

        return Response(
            {
                "message": (
                    f"Esteemed {user.first_name}, "
                    "a new verification code has been sent "
                    "to your email."
                ),
                "action": "enter_otp",
                "email": user.email,
                "retry_after": AUTH_OTP_TTL_SECONDS,
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# LOGIN
# ============================================================

class LoginView(APIView):
    permission_classes = [AnonymousOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    @extend_schema(
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                description="Login successful."
            ),
            400: OpenApiResponse(
                description="Missing login credentials."
            ),
            401: OpenApiResponse(
                description="Invalid credentials."
            ),
            403: OpenApiResponse(
                description="Account unavailable or unverified."
            ),
            429: OpenApiResponse(
                description="Login rate limit reached."
            ),
        },
        examples=[
            OpenApiExample(
                "Login Request",
                request_only=True,
                value={
                    "email": "kehinde@example.com",
                    "password": "StrongPassword123!",
                },
            ),
            OpenApiExample(
                "Login Success",
                response_only=True,
                value={
                    "message": (
                        "Distinguished Kehinde, "
                        "Account Login successful."
                    ),
                    "access": "eyJhbGciOiJIUzI1NiIs...",
                    "refresh": "eyJhbGciOiJIUzI1NiIs...",
                    "user": {
                        "first_name": "Kehinde",
                        "last_name": "Omoyayi",
                        "email": "kehinde@example.com",
                    },
                    "redirect_to": "/home/",
                },
            ),
        ],
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].strip().lower()
        password = serializer.validated_data["password"]

        user = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            email__iexact=email
        ).first()

        if user is None or not user.check_password(password):
            return Response(
                {"error": "Invalid email or password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if is_user_locked(user):
            return locked_response()

        if not user.is_active:
            return Response(
                {
                    "error": (
                        f"Distinguished {user.first_name}. "
                        "Your account has not been verified."
                    ),
                    "action": "redirect_to_otp_verification",
                    "redirect_to": "/api/v1/verify-otp/",
                    "email": user.email,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        customer_profile = getattr(
            user,
            "customer_profile",
            None,
        )

        if customer_profile is not None:
            record_customer_network_observation(
                customer_profile,
                request,
                observation_type="LOGIN",
            )

        user.last_login = timezone.now()

        user.save(
            update_fields=[
                "last_login",
                "updated_at",
            ]
        )

        refresh = RefreshToken.for_user(user)
        refresh["token_version"] = user.token_version

        access = refresh.access_token

        return Response(
            {
                "message": (
                    f"Distinguished {user.first_name}, "
                    "Account Login successful, "
                    "see you at the other side"
                ),
                "access": str(access),
                "refresh": str(refresh),
                "user": {
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                },
                "redirect_to": "/home/",
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# LOGOUT
# ============================================================

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Authentication"],
        request=None,
        responses={
            200: LogoutResponseSerializer,
            401: OpenApiResponse(
                description="Authentication required."
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        revoke_all_sessions(request.user)

        return Response(
            {
                "message": (
                    f"Distinguished {request.user.first_name}, "
                    "you have been logged out successfully."
                ),
                "action": "redirect_to_login",
                "redirect_to": "/login/",
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# FORGOT PASSWORD
# ============================================================

class ForgotPasswordView(APIView):
    permission_classes = [AnonymousOnly]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_forgot_password"
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    @extend_schema(
        request=ForgotPasswordSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset request processed."
            ),
            400: OpenApiResponse(
                description="Invalid email."
            ),
            429: OpenApiResponse(
                description="Password reset rate limit reached."
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].strip().lower()

        user = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            email__iexact=email
        ).first()

        if not user:
            return Response(
                {
                    "message": (
                        "If the account exists, "
                        "a password reset code will be sent."
                    ),
                    "action": "enter_reset_otp",
                    "email": email,
                    "retry_after": AUTH_OTP_TTL_SECONDS,
                },
                status=status.HTTP_200_OK,
            )

        if is_user_locked(user):
            return Response(
                {
                    "message": (
                        "If the account exists, "
                        "a password reset code will be sent."
                    ),
                    "action": "enter_reset_otp",
                    "email": email,
                    "retry_after": AUTH_OTP_TTL_SECONDS,
                },
                status=status.HTTP_200_OK,
            )

        cache_key = f"password_reset_otp_{email}"
        cooldown_key = f"password_reset_cooldown_{email}"

        claimed, retry_after = _claim_otp_cooldown(
            cooldown_key
        )

        if not claimed:
            return Response(
                {
                    "error": (
                        "Please wait before requesting "
                        "another password reset code."
                    ),
                    "retry_after": retry_after,
                    "action": "wait",
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        otp_code = _generate_otp()

        cache.set(
            cache_key,
            otp_code,
            timeout=AUTH_OTP_TTL_SECONDS,
        )

        cache.delete(
            _otp_attempts_key(
                "password_reset_otp",
                email,
            )
        )

        transaction.on_commit(
            lambda: send_password_reset_email.delay(
                user.first_name,
                user.email,
                otp_code,
            )
        )

        return Response(
            {
                "message": (
                    "If the account exists, "
                    "a password reset code will be sent."
                ),
                "action": "enter_reset_otp",
                "email": user.email,
                "retry_after": AUTH_OTP_TTL_SECONDS,
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# VERIFY RESET OTP
# ============================================================

class VerifyResetOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_verify_reset"
    parser_classes = [JSONParser]

    @extend_schema(
        tags=["Authentication"],
        description=(
            "Verifies the OTP sent to the user's email "
            "and returns a short-lived password reset token."
        ),
        request=VerifyResetOTPSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP verified successfully."
            ),
            400: OpenApiResponse(
                description="Invalid or expired OTP."
            ),
            429: OpenApiResponse(
                description="Too many invalid OTP attempts."
            ),
        },
        examples=[
            OpenApiExample(
                "Verify OTP Request",
                request_only=True,
                value={
                    "email": "user@example.com",
                    "otp": "123456",
                },
            ),
            OpenApiExample(
                "OTP Verified",
                response_only=True,
                value={
                    "message": "OTP verified successfully.",
                    "action": "redirect_to_reset_password",
                    "reset_token": "temporary_secure_reset_token",
                    "expires_in": 600,
                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        serializer = VerifyResetOTPSerializer(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].strip().lower()
        otp = serializer.validated_data["otp"]

        user = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            email__iexact=email
        ).first()

        if user is None:
            return Response(
                {"error": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.is_active:
            return Response(
                {"error": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        otp_key = f"password_reset_otp_{email}"

        if _otp_attempt_is_exhausted(
            "password_reset_otp",
            email,
        ):
            cache.delete(otp_key)

            return Response(
                {
                    "error": (
                        "Too many invalid OTP attempts. "
                        "Please request a new code."
                    )
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        stored_otp = cache.get(otp_key)

        if not stored_otp or not secrets.compare_digest(
            str(stored_otp),
            otp,
        ):
            attempts = _record_failed_otp_attempt(
                "password_reset_otp",
                email,
            )

            if attempts >= AUTH_OTP_MAX_ATTEMPTS:
                cache.delete(otp_key)

                return Response(
                    {
                        "error": (
                            "Too many invalid OTP attempts. "
                            "Please request a new code."
                        )
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            return Response(
                {"error": "Invalid or expired OTP."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        reset_token = secrets.token_urlsafe(32)

        reset_token_key = (
            f"password_reset_token_{reset_token}"
        )

        cache.set(
            reset_token_key,
            user.pk,
            timeout=RESET_TOKEN_TTL_SECONDS,
        )

        cache.delete(otp_key)

        cache.delete(
            _otp_attempts_key(
                "password_reset_otp",
                email,
            )
        )

        return Response(
            {
                "message": "OTP verified successfully.",
                "action": "redirect_to_reset_password",
                "reset_token": reset_token,
                "expires_in": RESET_TOKEN_TTL_SECONDS,
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# RESET PASSWORD
# ============================================================

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_reset_password"
    parser_classes = [JSONParser]

    @extend_schema(
        tags=["Authentication"],
        description=(
            "Resets the user's password using the temporary "
            "token issued after successful OTP verification."
        ),
        request=ResetPasswordSerializer,
        responses={
            200: OpenApiResponse(
                description="Password reset successful."
            ),
            400: OpenApiResponse(
                description="Invalid token or password."
            ),
            429: OpenApiResponse(
                description="Password reset rate limit reached."
            ),
        },
        examples=[
            OpenApiExample(
                "Reset Password Request",
                request_only=True,
                value={
                    "reset_token": "temporary_secure_reset_token",
                    "new_password": "NewStrongPassword123!",
                    "confirm_password": "NewStrongPassword123!",
                },
            ),
            OpenApiExample(
                "Password Reset Successful",
                response_only=True,
                value={
                    "message": "Password reset successfully.",
                    "action": "redirect_to_login",
                    "redirect_to": "/api/v1/login/",
                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        serializer = ResetPasswordSerializer(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)

        reset_token = serializer.validated_data["reset_token"]
        new_password = serializer.validated_data["new_password"]

        reset_token_key = (
            f"password_reset_token_{reset_token}"
        )

        user_id = cache.get(reset_token_key)

        if not user_id:
            return Response(
                {"error": "Invalid or expired reset token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = __import__(
            "django.contrib.auth",
            fromlist=["get_user_model"],
        ).get_user_model().objects.filter(
            pk=user_id
        ).first()

        if user is None:
            cache.delete(reset_token_key)

            return Response(
                {"error": "Invalid or expired reset token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if is_user_locked(user) or not user.is_active:
            cache.delete(reset_token_key)

            return Response(
                {"error": "Invalid or expired reset token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.contrib.auth.password_validation import validate_password

        validate_password(
            new_password,
            user=user,
        )

        user.set_password(new_password)

        user.token_version += 1

        user.save(
            update_fields=[
                "password",
                "token_version",
                "updated_at",
            ]
        )

        cache.delete(reset_token_key)

        cache.delete(
            f"password_reset_cooldown_{user.email.lower()}"
        )

        return Response(
            {
                "message": "Password reset successfully.",
                "action": "redirect_to_login",
                "redirect_to": "/api/v1/login/",
            },
            status=status.HTTP_200_OK,
        )


# ============================================================
# REFRESH TOKEN
# ============================================================

class MarketplaceTokenRefreshView(TokenRefreshView):
    serializer_class = MarketplaceTokenRefreshSerializer