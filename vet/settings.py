from datetime import timedelta
from pathlib import Path

from decouple import Csv, config
from django.core.exceptions import ImproperlyConfigured


BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_USER_MODEL = "vet_auth.CustomUser"


# ============================================================
# ENVIRONMENT
# ============================================================

ENVIRONMENT = config("ENVIRONMENT", default="development")
DEBUG = config("DEBUG", default=ENVIRONMENT != "production", cast=bool)
SECRET_KEY = config("SECRET_KEY", default="django-insecure-change-this-key")

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="", cast=Csv())
CSRF_TRUSTED_ORIGINS = config("CSRF_TRUSTED_ORIGINS", default="", cast=Csv())

PUBLIC_API_DOCS = config(
    "PUBLIC_API_DOCS",
    default=ENVIRONMENT != "production",
    cast=bool,
)

if ENVIRONMENT == "production":
    if DEBUG:
        raise ImproperlyConfigured("DEBUG must be False in production.")

    if not ALLOWED_HOSTS:
        raise ImproperlyConfigured(
            "ALLOWED_HOSTS must be configured in production."
        )

    if not CSRF_TRUSTED_ORIGINS:
        raise ImproperlyConfigured(
            "CSRF_TRUSTED_ORIGINS must be configured in production."
        )

    if not SECRET_KEY or SECRET_KEY.startswith("django-insecure-"):
        raise ImproperlyConfigured(
            "A strong SECRET_KEY must be configured in production."
        )


# ============================================================
# APPLICATIONS
# ============================================================

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    "auth.apps.AuthConfig",
    "phonenumber_field",

    "rest_framework",
    "drf_spectacular",
    "django_filters",
    "rest_framework_simplejwt.token_blacklist",
]


# ============================================================
# MIDDLEWARE
# ============================================================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


ROOT_URLCONF = "vet.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vet.wsgi.application"


# ============================================================
# AUTHENTICATION
# ============================================================

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]


# ============================================================
# DATABASE
# ============================================================

DATABASE_URL = config("DATABASE_URL", default="")

if ENVIRONMENT == "production":
    if not DATABASE_URL:
        raise ImproperlyConfigured(
            "DATABASE_URL must be configured in production."
        )

    import dj_database_url

    DATABASES = {
        "default": dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }

else:
    DB_ENGINE = config(
        "DB_ENGINE",
        default="sqlite",
    ).strip().lower()

    if DB_ENGINE in {"postgres", "postgresql"}:
        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": config("DB_NAME"),
                "USER": config("DB_USER"),
                "PASSWORD": config("DB_PASSWORD"),
                "HOST": config("DB_HOST"),
                "PORT": config("DB_PORT", default="5432"),
                "CONN_MAX_AGE": config(
                    "DB_CONN_MAX_AGE",
                    default=60,
                    cast=int,
                ),
                "CONN_HEALTH_CHECKS": True,
                "OPTIONS": {
                    "sslmode": config(
                        "DB_SSLMODE",
                        default="prefer",
                    ),
                },
            }
        }

    else:
        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": BASE_DIR / "db.sqlite3",
            }
        }

# ============================================================
# REDIS
# ============================================================

REDIS_URL = config("REDIS_URL", default="")

if ENVIRONMENT == "production" and not REDIS_URL:
    raise ImproperlyConfigured(
        "REDIS_URL must be configured in production."
    )

if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "IGNORE_EXCEPTIONS": False,
            },
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "artisan-local-cache",
        }
    }


# ============================================================
# CELERY
# ============================================================

CELERY_BROKER_URL = config(
    "CELERY_BROKER_URL",
    default=REDIS_URL,
)

CELERY_RESULT_BACKEND = config(
    "CELERY_RESULT_BACKEND",
    default=REDIS_URL,
)

if ENVIRONMENT == "production":
    if not CELERY_BROKER_URL:
        raise ImproperlyConfigured(
            "CELERY_BROKER_URL must be configured in production."
        )

    if not CELERY_RESULT_BACKEND:
        raise ImproperlyConfigured(
            "CELERY_RESULT_BACKEND must be configured in production."
        )

CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"

CELERY_TIMEZONE = "UTC"
CELERY_ENABLE_UTC = True

CELERY_TASK_TRACK_STARTED = True

CELERY_TASK_TIME_LIMIT = 300
CELERY_TASK_SOFT_TIME_LIMIT = 240


# ============================================================
# DJANGO REST FRAMEWORK
# ============================================================

REST_FRAMEWORK = {
    "EXCEPTION_HANDLER": "rest_framework.views.exception_handler",
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "auth.authentication.MarketplaceJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": config("DRF_ANON_RATE", default="60/min"),
        "user": config("DRF_USER_RATE", default="300/min"),

        "auth_register": config(
            "THROTTLE_AUTH_REGISTER",
            default="10/hour",
        ),
        "auth_verify_otp": config(
            "THROTTLE_AUTH_VERIFY_OTP",
            default="10/hour",
        ),
        "auth_request_otp": config(
            "THROTTLE_AUTH_REQUEST_OTP",
            default="5/hour",
        ),
        "auth_login": config(
            "THROTTLE_AUTH_LOGIN",
            default="10/min",
        ),
        "auth_forgot_password": config(
            "THROTTLE_AUTH_FORGOT_PASSWORD",
            default="5/hour",
        ),
        "auth_verify_reset": config(
            "THROTTLE_AUTH_VERIFY_RESET",
            default="10/hour",
        ),
        "auth_reset_password": config(
            "THROTTLE_AUTH_RESET_PASSWORD",
            default="10/hour",
        ),
    },
}


# ============================================================
# SPECTACULAR
# ============================================================

SPECTACULAR_SETTINGS = {
    "TITLE": "Timi's Vet API",
    "DESCRIPTION": "Veterinary API configurations.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SORT_OPERATIONS": False,
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": False,
        "displayOperationId": True,
    },
}


# ============================================================
# PASSWORD VALIDATION
# ============================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]


# ============================================================
# PASSWORD HASHING
# ============================================================

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]


# ============================================================
# SIMPLE JWT
# ============================================================

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
}


# ============================================================
# INTERNATIONALIZATION
# ============================================================

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ============================================================
# STATIC / MEDIA
# ============================================================

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

STATIC_DIR = BASE_DIR / "static"
STATICFILES_DIRS = [STATIC_DIR] if STATIC_DIR.exists() else []

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"


# ============================================================
# DEFAULT PRIMARY KEY
# ============================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ============================================================
# EMAIL
# ============================================================

if ENVIRONMENT == "production":
    EMAIL_BACKEND = config("EMAIL_BACKEND")
    EMAIL_HOST = config("EMAIL_HOST")
    EMAIL_PORT = config("EMAIL_PORT", cast=int)
    EMAIL_USE_SSL = config("EMAIL_USE_SSL", cast=bool)
    EMAIL_USE_TLS = config("EMAIL_USE_TLS", cast=bool)
    EMAIL_HOST_USER = config("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
    DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL")
else:
    EMAIL_BACKEND = config(
        "EMAIL_BACKEND",
        default="django.core.mail.backends.console.EmailBackend",
    )
    EMAIL_HOST = config("EMAIL_HOST", default="")
    EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
    EMAIL_USE_SSL = config("EMAIL_USE_SSL", default=False, cast=bool)
    EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=False, cast=bool)
    EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
    EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
    DEFAULT_FROM_EMAIL = config(
        "DEFAULT_FROM_EMAIL",
        default="webmaster@localhost",
    )

EMAIL_TIMEOUT = config(
    "EMAIL_TIMEOUT",
    default=10,
    cast=float,
)

if EMAIL_USE_SSL and EMAIL_USE_TLS:
    raise ImproperlyConfigured(
        "EMAIL_USE_SSL and EMAIL_USE_TLS cannot both be True."
    )


# ============================================================
# SECURITY
# ============================================================

SECURE_SSL_REDIRECT = config(
    "SECURE_SSL_REDIRECT",
    default=ENVIRONMENT == "production",
    cast=bool,
)

SECURE_PROXY_SSL_HEADER = (
    ("HTTP_X_FORWARDED_PROTO", "https")
    if ENVIRONMENT == "production"
    else None
)

SESSION_COOKIE_SECURE = config(
    "SESSION_COOKIE_SECURE",
    default=ENVIRONMENT == "production",
    cast=bool,
)

CSRF_COOKIE_SECURE = config(
    "CSRF_COOKIE_SECURE",
    default=ENVIRONMENT == "production",
    cast=bool,
)

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_SAMESITE = "Lax"

SECURE_HSTS_SECONDS = config(
    "SECURE_HSTS_SECONDS",
    default=31536000 if ENVIRONMENT == "production" else 0,
    cast=int,
)

SECURE_HSTS_INCLUDE_SUBDOMAINS = config(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=ENVIRONMENT == "production",
    cast=bool,
)

SECURE_HSTS_PRELOAD = config(
    "SECURE_HSTS_PRELOAD",
    default=False,
    cast=bool,
)

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

X_FRAME_OPTIONS = "DENY"