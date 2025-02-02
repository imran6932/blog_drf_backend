from app import views
from django.urls import path

urlpatterns = [
    path("sign-up", views.UserSignupView.as_view()),
    path("login", views.UserLoginView.as_view()),
    path("verify-otp", views.AccountVerifyOTP.as_view()),
    path("generate-otp", views.GenerateOTP.as_view()),
    path("change-password", views.ChangePasswordView.as_view()),
    path("request-reset-password", views.PasswordResetView.as_view()),
    path("confirm-reset-password", views.PasswordResetConfirmView.as_view()),
    path("blog", views.UserBlogView.as_view()),
    path("blog/<str:id>", views.UserBlogView.as_view()),
    path("all-blog", views.AllBlogView.as_view()),
    path("all-blog/<str:id>", views.AllBlogView.as_view()),
    path("profile", views.ProfileView.as_view()),
]
