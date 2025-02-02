import random, logging
from django.core import mail
from datetime import timedelta
from django.utils import timezone
from django.utils import timezone as tz
from django.template.loader import render_to_string
from .models import OTPVerify
from django.contrib.auth import get_user_model

User = get_user_model()

from django.conf import settings

FROM = settings.EMAIL_HOST_USER


def verify_otp(user, otp):
    otp_obj = OTPVerify.objects.get(user=user)
    now = timezone.now()
    # print("now-", now)
    # print("expiry", otp_obj.expiry)

    if int(otp) == int(otp_obj.otp) and otp_obj.expiry > now:
        user_ = User.objects.get(id=user.id)
        user_.is_verified = True
        user_.save()
        # print("verified")
        return True


def email_otp(user, otp):
    """Send Email OTP"""

    name = user.name

    context = {"otp": otp, "name": name}
    html_message = render_to_string("send_otp.html", context)
    sub = "Your OTP"

    try:
        with mail.get_connection() as connection:
            email = mail.EmailMessage(
                sub,
                html_message,
                FROM,
                [user.email],
                connection=connection,
            )
            email.content_subtype = "html"
            email.send()
        logging.info(f"Email sent | User- {user}\n")
        return True, "done"
    except Exception as e:
        logging.error(f"Email exception - {str(e)}| User- {user}\n")
        return False, str(e)


def generate_otp(user):

    try:

        otp = random.randint(101010, 999999)
        expiry = timezone.now() + timedelta(minutes=5)

        email, msg = email_otp(user, otp)
        if email:
            defaults = {"otp": otp, "expiry": expiry, "is_emailed": True}
            OTPVerify.objects.update_or_create(user=user, defaults=defaults)
            return True, "done"
        return False, msg

    except Exception as e:
        logging.error(
            f"Exception on generate token | User {user} | Exception- {str(e)}\n"
        )
        return False, e
