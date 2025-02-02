from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from tinymce.models import HTMLField


def get_blog_photo_path(instance, filename):
    return f"blogs_photo/{instance.user.id}_{instance.user.name.replace(' ', '_')}/{filename}"

def get_profile_photo_path(instance, filename):
    return f"profile_photo/{instance.user.id}_{instance.user.name.replace(' ', '_')}/{filename}"

def get_sample_photo_path(instance, filename):
    return f"sample_photo/{filename}"

class UserManager(BaseUserManager):
    """Custom User manager"""

    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError(("The email must be set"))

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(("Superuser must have is_staff=True."))

        if extra_fields.get("is_superuser") is not True:
            raise ValueError(("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom User model"""

    username = None
    first_name = None
    last_name = None

    name = models.CharField(max_length=50)
    email = models.EmailField(max_length=50, unique=True)
    is_verified = models.BooleanField(default=False)
    photo = models.ImageField(upload_to=get_profile_photo_path, null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return str(self.email)





class Blog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = HTMLField()  
    photo = models.ImageField(upload_to=get_blog_photo_path, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["title"]),
        ]
        unique_together = ("user", "title")

    def __str__(self):
        return self.user.email


class OTPVerify(models.Model):
    """OTP verification"""

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    expiry = models.DateTimeField()
    is_emailed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return str(self.user)


class SamplePhoto(models.Model):
    blog_photo = models.ImageField(upload_to=get_sample_photo_path)
    profile_photo = models.ImageField(upload_to=get_sample_photo_path)

    def __str__(self):
        return str(self.id)
