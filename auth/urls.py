from django.urls import path
from .views import *

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("request-otp/", RequestOTPView.as_view(), name="request-otp"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path("verify-reset-otp/", VerifyResetOTPView.as_view(),name="verify-reset-otp"),
    path("reset-password/", ResetPasswordView.as_view(), name="reset-password"),
    path("token/refresh/", MarketplaceTokenRefreshView.as_view(), name="token-refresh"),

]
