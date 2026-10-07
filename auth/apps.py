from django.apps import AppConfig


class AuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "auth"
    label = "vet_auth"
    verbose_name = "Authentication"