from django.contrib import admin
from .models import *

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ["email", "first_name", "last_name", "is_active", "security_status"]
    list_filter = ["is_active", "security_status"]
    search_fields = ["email", "first_name", "last_name"]
    actions = ["suspend_users", "unsuspend_users"]

    @admin.action(description="Suspend selected users")
    def suspend_users(self, request, queryset):
        for user in queryset:
            if not user.is_superuser:
                suspend_user(user)

    @admin.action(description="Unsuspend selected users")
    def unsuspend_users(self, request, queryset):
        for user in queryset:
            unsuspend_user(user)