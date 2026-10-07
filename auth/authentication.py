from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken

class MarketplaceJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)

        token_version = validated_token.get("token_version")

        try:
            token_version_value = int(token_version)
        except (TypeError, ValueError):
            raise InvalidToken("Session has been revoked.")

        if token_version_value != user.token_version:
            raise InvalidToken("Session has been revoked.")

        if not user.is_active:
            raise InvalidToken("Account is inactive.")

        if user.security_status == "LOCKED":
            raise InvalidToken("Account is locked.")

        return user
