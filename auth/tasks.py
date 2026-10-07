import logging
import smtplib
import socket
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone

logger = logging.getLogger(__name__)
User = get_user_model()

SMTP_RETRYABLE_EXCEPTIONS = (OSError, TimeoutError, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)


def _send_auth_email(task, *, first_name, email, subject, message):
    try:
        sent = send_mail(subject=subject, message=message, from_email=settings.DEFAULT_FROM_EMAIL, recipient_list=[email], fail_silently=False)
        if sent != 1:
            raise smtplib.SMTPException("SMTP backend did not report the authentication email as sent.")
        return {"status": "sent", "email": email}
    except SMTP_RETRYABLE_EXCEPTIONS as exc:
        logger.warning("Transient SMTP failure for authentication email to %s: %s", email, exc)
        raise task.retry(exc=exc)
    except smtplib.SMTPResponseException as exc:
        if 400 <= exc.smtp_code < 500:
            logger.warning("Transient SMTP response %s for authentication email to %s", exc.smtp_code, email)
            raise task.retry(exc=exc)
        logger.exception("Permanent SMTP response %s for authentication email to %s", exc.smtp_code, email)
        raise
    except smtplib.SMTPException:
        logger.exception("SMTP failure for authentication email to %s", email)
        raise


@shared_task(bind=True, max_retries=6, retry_backoff=True, retry_backoff_max=900, retry_jitter=True)
def send_verification_email(self, first_name, email, otp_code):
    return _send_auth_email(self, first_name=first_name, email=email, subject="Verify Your Artisan Platform Account", message=f"Hello Distinguished {first_name},\n\nYour code is: {otp_code}. It expires in 5 minutes.")


@shared_task(bind=True, max_retries=6, retry_backoff=True, retry_backoff_max=900, retry_jitter=True)
def send_password_reset_email(self, first_name, email, otp_code):
    return _send_auth_email(self, first_name=first_name, email=email, subject="Password Reset Verification Code", message=f"Hello {first_name},\n\nYour password reset code is: {otp_code}\n\nThis code expires in 5 minutes.")


@shared_task(bind=True, max_retries=6, retry_backoff=True, retry_backoff_max=900, retry_jitter=True)
def send_otp_email(self, first_name, email, otp_code):
    return _send_auth_email(self, first_name=first_name, email=email, subject="Your Artisan Platform Verification Code", message=f"Hello {first_name},\n\nYour verification code is: {otp_code}\n\nThis code expires in 5 minutes.")


@shared_task
def delete_unverified_accounts():
    cutoff = timezone.now() - timedelta(days=7)
    deleted_count, _ = User.objects.filter(is_active=False, security_status="NORMAL", is_staff=False, is_superuser=False, created_at__lte=cutoff).delete()
    return deleted_count
