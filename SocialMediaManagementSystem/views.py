from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
import random
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import re

def send_otp_email(email, otp):
    subject = 'OTP for Account Verification'
    context = {'otp': otp}
    html_message = render_to_string('otp_verification.html', context)
    plain_message = strip_tags(html_message)
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message)

from django.conf import settings

from .models import *

def index(request):
    return render(request, 'index.html')

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        passd = request.POST['password']

        print("Email:", email)
        print("Password:", passd)
        user = Users.objects.check(email=email, password=passd)
        print("User:", user)


        if user:
            if user.status == 'verified':
                auth_login(request, user)
                return redirect('user.dashboard')
            else:
                messages.error(request, 'Your account is not verified yet. Please check your email for verification instructions.')
        else:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'login.html')

def verify_password_strength(password):
    if len(password) < 6:
        return {'length': 'Password should be 6 characters or more.'}
    if not any(char.isdigit() for char in password):
        return {'digit': 'Password should contain at least one digit.'}
    if not re.search(r'[!@#$%^&*()_+\-=[\]{};\':"|,.<>/?]', password):
        return {'symbol': 'Password should contain at least one symbol.'}
    if not any(char.isupper() for char in password):
        return {'uppercase': 'Password should contain at least one uppercase letter.'}
    if not any(char.islower() for char in password):
        return {'lowercase': 'Password should contain at least one lowercase letter.'}
    return None

def signup(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user_type = request.POST['type']

        password_strength = verify_password_strength(password)
        if password_strength:
            for key, value in password_strength.items():
                messages.error(request, value)
            return render(request, 'signup.html')

        user = Users.objects.create_user(email=email, password=password)  
        user.user_type = user_type
        user.created_at = timezone.now()
        user.updated_at = timezone.now()
        user.save()
        otp = generate_otp()
        otp_obj = OTP.objects.create(user=user, otp=otp)
        otp_obj.save()

        send_otp_email(email, otp)
        messages.success(request, 'Verifivation code sent to your email account. Please verify your account.')
        return redirect('verify-account')

    return render(request, 'signup.html')

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    subject = 'OTP for Account Verification'
    context = {'otp': otp}
    html_message = render_to_string('otp_email.html', context)
    plain_message = strip_tags(html_message)
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message)

def forgotPassword(request):
    return render(request, 'forgot-form.html')

def resetPassword(request):
    return render(request, 'reset-form.html')

def reseted_Password(request):
    return render(request, 'reset-form.html')

def verifyAccount(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')  
        otp = request.POST.get('otp', '')
        try:
            user = Users.objects.get(email=email)  
            otp_obj = OTP.objects.get(user=user)  
            if otp == otp_obj.otp:
                user.status = 'verified'
                user.email_verified_at = timezone.now()
                user.updated_at = timezone.now()
                user.save()
                messages.success(request, 'Account verified successfully. You can now log in.')
                otp_obj.delete()
                return redirect('user-login')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')

        except Users.DoesNotExist:
            messages.error(request, 'User not found. Please try again.')

        except OTP.DoesNotExist:
            messages.error(request, 'OTP not found. Please try again.')

    return render(request, 'OTP.html')

def dashboard_view(request):
    return render(request, 'dashboard.html')

def search_view(request):
    return 
def posts_view(request):
    return 
def create_post_view(request):
    return 
def chat_dashboard_view(request):
    return 
def settings_view(request):
    return 
def user_profile_view(request):
    return 
