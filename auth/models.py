from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


SECURITY_STATUS = (
    ("NORMAL", "Normal"),
    ("LOCKED", "Locked"),
)


class CustomUserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None, **kwargs):
        if not email:
            raise ValueError("Email is required.")

        email = self.normalize_email(email).strip().lower()

        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            **kwargs,
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None, **kwargs):
        kwargs.setdefault("is_staff", True)
        kwargs.setdefault("is_superuser", True)
        kwargs.setdefault("is_active", True)

        if kwargs.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if kwargs.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        user = self.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            **kwargs,
        )

        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length=40)
    phone_number = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        unique=True,
    )

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    token_version = models.PositiveIntegerField(default=1)

    security_status = models.CharField(
        max_length=20,
        choices=SECURITY_STATUS,
        default="NORMAL",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    def __str__(self):
        return self.email