import logging, traceback
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework import status
from .serializers import (
    BlogSerializer,
    CreateUpdateBlogSerializer,
    LoginSerializer,
    SignupSerializer,
    PasswordResetConfirmSerializer,
    UserUpdateSerializer,
    UserSerializer,
)
from .models import Blog, SamplePhoto, User
from .utils import generate_otp, verify_otp

User = get_user_model()

class UserSignupView(APIView):
    """User Signup"""

    serializer_class = SignupSerializer

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"data": serializer.data})
        else:
            errors = [key for key, value in serializer.errors.items()]
            error_list = [
                {
                    "message": f"{errors} - {value}".replace("[", "").replace("]", ""),
                }
                for key, value in serializer.errors.items()
            ][0]

            return Response(error_list, 400)


class UserLoginView(APIView):
    """User Login"""

    serializer_class = LoginSerializer

    def post(self, request):
        try:
            data = request.data
            serializer = self.serializer_class(data=data)
            if serializer.is_valid():

                user = authenticate(username=data["email"], password=data["password"])
                if user is not None:
                    if user.is_verified:
                        access_token = AccessToken.for_user(user=user)
                        res = {
                            "id": user.id,
                            "user": user.name.replace(" ", "-"),
                            "email": user.email,
                            "access_token": str(access_token),
                        }

                        return Response({"data": res})
                    else:
                        return Response(
                            {"message": "user is not verified", "email": user.email},
                            400,
                        )

                return Response(
                    {"message": "You have entered invalid email or password."},
                    400,
                )
            errors = [key for key, value in serializer.errors.items()]
            error_list = [
                {
                    "message": f"{errors} - {value}".replace("[", "").replace("]", ""),
                }
                for key, value in serializer.errors.items()
            ][0]

            return Response(error_list, 400)

        except Exception as e:
            logging.info(f"UserLoginView exception- {str(e)}\n")
            return Response(
                {"message": f"something went wrong Exception- {str(e)}"}, 422
            )


class GenerateOTP(APIView):
    """Generate OTP"""

    def get(self, request, *args, **kwargs):
        try:
            logging.info(
                f"Generate OTP GET data- | User- {request.user} | {request.query_params}\n"
            )
            email = request.query_params["email"]
            user = User.objects.get(email=email)
            otp, msg = generate_otp(user)

            if otp and otp == True:
                return Response(
                    {
                        "message": "OTP has sent on your email",
                        "email": email,
                    }
                )

            else:
                return Response(
                    {
                        "message": f"Email not sent- {str(msg)}",
                        "email": email,
                    },
                    400,
                )

        except Exception as e:
            logging.error(
                f"Generate OTP GET exception- | User- {request.user} | {traceback.format_exc()}\n"
            )
            return Response({"message": f"something went wrong- {str(e)}"}, 422)


class AccountVerifyOTP(APIView):
    """Account Verify OTP"""

    # permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            logging.info(
                f"Verify OTP GET data- | User- {request.user} | {request.query_params}\n"
            )
            email = request.query_params["email"]
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({"message": "User has already verified"})
            otp = request.query_params["otp"]
            otp = verify_otp(user=user, otp=otp)
            token = AccessToken.for_user(user=user)
            if otp and otp == True:
                res = Response(
                    {
                        "message": "OTP verified successfully",
                        "access_token": str(token),
                        "id": user.id,
                        "name": user.name,
                        "email": user.email,
                    }
                )
                res.set_cookie(
                    key="access_token",
                    value=str(token),
                    httponly=True,
                    secure=True,  # Only secure in production
                    samesite="Lax",
                )
                return res
            elif otp:
                return Response({"message": otp})
            else:
                return Response({"message": "OTP Wrong or Expired!"}, 400)
        except Exception as e:
            logging.error(
                f"Verify OTP GET exception- | User- {request.user} | {traceback.format_exc()}\n"
            )
            return Response({"message": f"something went wrong- {str(e)}"}, 422)


class PasswordResetView(APIView):
    """Password reset OTP email send to the user"""

    def post(self, request):
        try:
            logging.info(
                f"Password reset OTP POST data- | User- {request.user} | {request.data}\n"
            )
            email = request.data["email"]
            user = User.objects.filter(email=email).exists()
            if user:
                user = User.objects.get(email=email)

                otp, msg = generate_otp(user)
                if otp:
                    logging.info(f"Password reset OTP sent successfully User-{email}\n")
                    return Response(
                        {
                            "message": "Password reset OTP sent successfully",
                            "email": email,
                        }
                    )
                else:
                    logging.info(
                        f"Password reset email not sent error User-{email} | {str(msg)}\n"
                    )
                    return Response(
                        {
                            "message": f"Email not sent- {str(msg)}",
                            "email": email,
                        },
                        422,
                    )
            else:
                logging.info(f"User Email does not exist User-{email}\n")
                return Response(
                    {"message": "User Email does not exist"},
                    400,
                )
        except Exception as e:
            logging.error(
                f"Password reset OTP POST exception- | User- {request.user} | {traceback.format_exc()}\n"
            )
            return Response({"message": str(e)}, 422)


class PasswordResetConfirmView(APIView):
    """Verify and confirm Password reset OTP and set New Password"""

    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        try:
            logging.info(
                f"Password reset confirm  POST data- | User- {request.user} | {request.data}\n"
            )
            email = request.data["email"]
            entered_otp = request.data["otp"]
            user = User.objects.get(email=email)
            otp = verify_otp(user, entered_otp)
            if otp:
                serializer = self.serializer_class(data=request.data)
                serializer.is_valid(raise_exception=True)
                if request.data["new_password1"] == request.data["new_password2"]:
                    user.set_password(request.data["new_password1"])
                    user.save()

                    logging.info(
                        f"Password has been reset with the new password. User-{email}"
                    )
                    return Response(
                        {"message": "Password has been reset with the new password."},
                    )
                else:
                    logging.error(f"Password not matched. User-{email}")
                    return Response({"message": "Password not matched"}, 400)

            else:
                logging.error(f"Invalid or Expired OTP. User-{email}")
                return Response({"message": "Invalid or Expired OTP"}, 400)
        except Exception as e:
            logging.error(
                f"Password reset confirm POST exception- | User- {request.user} | {traceback.format_exc()}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)


class ChangePasswordView(APIView):
    """User Password change"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            new_password = request.data["new_password"]

            user = User.objects.get(email=request.user.email)
            if user is not None:
                user.set_password(new_password)
                user.save()
                return Response({"message": "password changed successfully"})
            logging.error(
                f"Change old password Exception error-| User- {request.user}\n"
            )
            return Response({"message": "user not found"}, 400)
        except Exception as e:
            logging.error(
                f"Change Password POST Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)


class UserBlogView(APIView):
    """User Blog View"""

    serializer_class = BlogSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self, id, user):
        obj = Blog.objects.filter(id=id, user=user)
        if obj:
            return obj[0]
        else:
            return

    def get(self, request, id=None):

        try:
            if id:
                obj = self.get_object(id, request.user)
                if obj:
                    if obj.photo:
                        photo = obj.photo.url
                    else:
                        photo = SamplePhoto.objects.first().blog_photo.url
                    data = {
                        "user": obj.user.name.replace(" ", "-"),
                        "id": obj.id,
                        "title": obj.title,
                        "description": obj.description,
                        "photo": f"http://{request.get_host()}{photo}",
                        "created_at": obj.created_at,
                    }
                    return Response({"data": data})
                return Response({"message": "blog does not exist"}, 400)
            else:
                obj = Blog.objects.filter(user=request.user)
                serializer = self.serializer_class(
                    obj, many=True, context={"get_host": request.get_host()}
                )
                return Response({"data": serializer.data})
        except Exception as e:
            logging.error(
                f"Get blog GET Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)

    def post(self, request):
        try:
            data = request.data

            serializer = CreateUpdateBlogSerializer(data=data)

            if serializer.is_valid():
                obj = Blog.objects.create(
                    user=request.user, **serializer.validated_data
                )
                # photo = obj.photo.url
                if obj.photo:
                    photo = obj.photo.url
                else:
                    photo = SamplePhoto.objects.first().blog_photo.url

                data = {
                    "user": obj.user.name.replace(" ", "-"),
                    "id": obj.id,
                    "title": obj.title,
                    "description": obj.description,
                    "photo": f"http://{request.get_host()}{photo}",
                    "created_at": obj.created_at,
                }

                return Response({"message": "blog has created", "data": data}, 201)

            errors = [key for key, value in serializer.errors.items()]
            error_list = [
                {
                    "message": f"{errors} - {value}".replace("[", "").replace("]", ""),
                }
                for key, value in serializer.errors.items()
            ][0]
            return Response(error_list, 400)
        except Exception as e:
            logging.error(
                f"Create blog POST Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)

    def patch(self, request, id):
        try:
            data = request.data
            instance = self.get_object(id, request.user)

            if instance:
                serializer = CreateUpdateBlogSerializer(instance=instance, data=data)
                if serializer.is_valid():
                    serializer.save()
                    # photo = instance.photo.url
                    if instance.photo:
                        photo = instance.photo.url
                    else:
                        photo = SamplePhoto.objects.first().blog_photo.url
                    data = {
                        "user": instance.user.name.replace(" ", "-"),
                        "id": instance.id,
                        "title": instance.title,
                        "description": instance.description,
                        "photo": f"http://{request.get_host()}{photo}",
                        "created_at": instance.created_at,
                    }
                    return Response({"message": "blog updated", "data": data})
                errors = [key for key, value in serializer.errors.items()]
                error_list = [
                    {
                        "message": f"{errors} - {value}".replace("[", "").replace(
                            "]", ""
                        ),
                    }
                    for key, value in serializer.errors.items()
                ][0]
                return Response(error_list, 400)
            return Response({"message": "blog does not exist"}, 400)
        except Exception as e:
            logging.error(
                f"Update blog PATCH Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)

    def delete(self, request, id):
        try:
            instance = self.get_object(id, request.user)
            if instance:
                instance.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            return Response({"message": "blog does not exist"}, 400)
        except Exception as e:
            logging.error(
                f"Delete blog DELETE Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)


class AllBlogView(APIView):
    """All Blog View"""

    serializer_class = BlogSerializer

    def get_object(self, id):
        obj = Blog.objects.filter(id=id)
        if obj:
            return obj[0]
        else:
            return

    def get(self, request, id=None):

        try:
            if id:
                obj = self.get_object(id)
                if obj:
                    if obj.photo:
                        photo = obj.photo.url
                    else:
                        photo = SamplePhoto.objects.first().blog_photo.url
                    data = {
                        "user": obj.user.name.replace(" ", "-"),
                        "id": obj.id,
                        "title": obj.title,
                        "description": obj.description,
                        "photo": f"http://{request.get_host()}{photo}",
                        "created_at": obj.created_at,
                    }
                    return Response({"data": data})
                return Response({"message": "blog does not exist"}, 400)
            else:
                obj = Blog.objects.all()
                serializer = self.serializer_class(
                    obj, many=True, context={"get_host": request.get_host()}
                )
                return Response({"data": serializer.data})
        except Exception as e:
            logging.error(
                f"Get blog GET Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)


class ProfileView(APIView):
    """user profile view"""

    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request):
        try:
            user = User.objects.filter(email=request.user.email).first()
            serializer = self.serializer_class(
                user, context={"get_host": request.get_host()}
            )

            return Response({"data": serializer.data})

        except Exception as e:
            logging.error(
                f"Get Profile GET Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)

    def patch(self, request):
        try:
            instance = User.objects.get(email=request.user.email)
            serializer = UserUpdateSerializer(instance=instance, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "profile updated", "data": serializer.data})
            errors = [key for key, value in serializer.errors.items()]
            error_list = [
                {
                    "message": f"{errors} - {value}".replace("[", "").replace("]", ""),
                }
                for key, value in serializer.errors.items()
            ][0]
            return Response(error_list, 400)
        except Exception as e:
            logging.error(
                f"Get Profile PATCH Exception error- {traceback.format_exc()} | User- {request.user}\n"
            )
            return Response({"message": f"Exception- {str(e)}"}, 422)
