from django.contrib import admin
from .models import Blog, User, OTPVerify, SamplePhoto


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = [
        "email",
        "name",
        "id",
        "is_superuser",
        "is_verified",
        "date_joined",
    ]


@admin.register(OTPVerify)
class OTPVerify(admin.ModelAdmin):
    list_display = [field.name for field in OTPVerify._meta.fields]


@admin.register(Blog)
class Blog(admin.ModelAdmin):
    list_display = ["user", "title","id", "photo", "created_at"]
    search_fields = ["user__email", "title", "created_at"]


@admin.register(SamplePhoto)
class SamplePhoto(admin.ModelAdmin):
    list_display = [field.name for field in SamplePhoto._meta.fields]
