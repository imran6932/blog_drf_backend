from rest_framework import serializers
from django.contrib.auth import get_user_model
from .utils import generate_otp
from .models import Blog, SamplePhoto, User

User = get_user_model()


class SignupSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "name",
            "email",
            "password",
        ]

    def create(self, validated_data):
        user = super(SignupSerializer, self).create(validated_data)
        user.set_password(validated_data["password"])
        generate_otp(user)

        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=50)
    password = serializers.CharField(max_length=50)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming a password reset attempt.
    """

    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    def validate(self, attrs):
        password1 = attrs["new_password1"]
        password2 = attrs["new_password2"]
        if str(password1) != str(password2):
            raise serializers.ValidationError("Password not matched")

        return attrs


class BlogSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    photo = serializers.SerializerMethodField()

    class Meta:
        model = Blog
        fields = ("id", "user", "title", "description", "photo", "created_at")

    def get_photo(self, obj):

        if obj.photo:
            photo = obj.photo.url
        else:
            photo = SamplePhoto.objects.first().blog_photo.url
        get_host = self.context["get_host"]
        return f"http://{get_host}{photo}"

    def get_user(self, obj):
        return obj.user.name.replace(" ", "-")


class CreateUpdateBlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        exclude = ("user",)

    def validate(self, attrs):
        title = attrs["title"].strip()
        title = title.replace(" ", "").replace("-", "")
        if not title.isalpha():
            raise serializers.ValidationError(
                {
                    "message": "title must be only string, special char or integer not allowed!"
                }
            )
        else:
            format_title = attrs["title"]
            title = format_title.replace(" ", "-")
            attrs["title"] = title
            return attrs


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    photo = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["email", "name", "photo"]

    def get_photo(self, obj):

        if obj.photo:
            photo = obj.photo.url
        else:
            photo = SamplePhoto.objects.first().profile_photo.url
        get_host = self.context["get_host"]
        return f"http://{get_host}{photo}"


class UserUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)

    class Meta:
        model = User
        fields = ("name", "email", "photo")
