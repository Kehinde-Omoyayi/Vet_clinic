from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.conf import settings

from phonenumber_field.serializerfields import PhoneNumberField

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer

from .models import CustomUser


User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    phone_number = PhoneNumberField(region="NG")
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        trim_whitespace=False,
    )

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "password",
        ]

    def validate_first_name(self, value):
        value = value.strip()

        if not value:
            raise ValidationError("First name is required.")

        return value

    def validate_last_name(self, value):
        value = value.strip()

        if not value:
            raise ValidationError("Last name is required.")

        return value

    def validate_email(self, value):
        value = value.strip().lower()

        if CustomUser.objects.filter(email__iexact=value).exists():
            raise ValidationError(
                "A user with this email already exists."
            )

        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        return User.objects.create_user(
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            email=validated_data["email"],
            phone_number=validated_data["phone_number"],
            password=validated_data["password"],
        )


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=6, max_length=6)


class RequestOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
    )


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class LogoutResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    action = serializers.CharField()


class ResetPasswordSerializer(serializers.Serializer):
    reset_token = serializers.CharField()
    new_password = serializers.CharField(
        write_only=True,
        min_length=8,
        trim_whitespace=False,
    )
    confirm_password = serializers.CharField(
        write_only=True,
        min_length=8,
        trim_whitespace=False,
    )

    def validate(self, attrs):
        new_password = attrs["new_password"]
        confirm_password = attrs["confirm_password"]

        if new_password != confirm_password:
            raise serializers.ValidationError(
                {
                    "confirm_password": "Passwords do not match."
                }
            )

        validate_password(new_password)

        return attrs


class VerifyResetOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=6, max_length=6)


class MarketplaceTokenRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        try:
            refresh = self.token_class(attrs["refresh"])
        except Exception as exc:
            raise InvalidToken(
                "Invalid or expired refresh token."
            ) from exc

        user_id = refresh.get(
            settings.SIMPLE_JWT.get("USER_ID_CLAIM", "user_id")
        )

        token_version = refresh.get("token_version")

        user = User.objects.filter(pk=user_id).first()

        try:
            token_version = int(token_version)
        except (TypeError, ValueError):
            token_version = None

        if (
            user is None
            or token_version is None
            or token_version != user.token_version
            or not user.is_active
            or getattr(user, "security_status", "NORMAL") == "LOCKED"
        ):
            raise InvalidToken(
                "Session has been revoked or the account is unavailable."
            )

        return super().validate(attrs)