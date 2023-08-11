from django.utils.crypto import get_random_string
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.hashers import make_password
import random
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import re
from django.urls import reverse
from django.conf import settings
from .models import *

def index(request):
    return render(request, 'index.html')

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            messages.error(request, 'User not found or incorrect email/password.')
            return redirect('user-login')
        
        if check_password(password, user.password):
            if user.status == 'verified':
                auth_login(request, user)
                user.is_active = True
                user.save()
                request.session['user_id'] = user.u_id
                request.session['email'] = user.email
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

def send_reset_link(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Users.objects.filter(email=email).exists():
            token = get_random_string(64)
            PasswordResetToken.objects.create(email=email, token=token, created_at=timezone.now())
            reset_url = request.build_absolute_uri(reverse('reset.password', kwargs={'token': token, 'email': email}))
            subject = 'Password Reset'
            context = {'reset_url': reset_url}
            html_message = render_to_string('reset-password-email.html', context)
            plain_message = strip_tags(html_message)
            send_mail(
                subject,
                plain_message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                html_message=html_message,
            )
            messages.success(request, 'A password reset link has been sent to your email accont.')
            return redirect('forget.password.form') 
        else:
            messages.error(request, 'Invalid Email. Please try again.')
            return redirect('forget.password.form')
    else:
        messages.error(request, 'Bad request')
        return redirect('forget.password.form')  
def forgotPassword(request):
    return render(request, 'forgot-form.html')

def reset_Password(request,token,email):
    context={
        'token' : token,
        'email' : email,
    }
    return render(request,'reset-form.html',context)

def save_Password(request):
    if request.method == 'POST':
        token = request.POST['token']
        email = request.POST['email']
        password = request.POST['password']
        password_confirmation = request.POST['password_confirmation']

        password_strength = verify_password_strength(password)

        if password_strength:
            for key, value in password_strength.items():
                messages.error(request, value)
                context = {
                'token': token,
                'email': email,
            }
            return render(request, 'reset-form.html', context)

        if password != password_confirmation:
            messages.error(request, "Password and confirmation do not match.")
            return redirect('reset.password', token=token, email=email)

        try:
            check_token = PasswordResetToken.objects.get(email=email, token=token)
        except PasswordResetToken.DoesNotExist:
            messages.error(request, "Invalid token.")
            return redirect('reset.password', token=token, email=email)

        # Update user's password
        user = Users.objects.get(email=email)
        user.password = make_password(password)
        user.save()

        # Delete used token
        check_token.delete()

        messages.success(request, "Password reset successful. You can now log in with your new password.")
        return redirect('user-login') 
    else:
        context = {
            'token': token,
            'email': email,
        }
        return render(request, 'reset-form.html', context)

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
    email = request.session.get('email')
    context = {
        'email': email,
    }
    return render(request, 'setting.html', context)
def changestatus(request):
    user = Users.objects.get(email=request.session.get('email'))
    if user.is_active:
        user.is_active = False
        user.save()
        messages.success(request, 'Changed to Inactive')
    else:
        user.is_active = True
        user.save()
        messages.success(request, 'Changed to Active')
    return redirect('user.settings')
def user_profile_view(request):
    return 
def logout(request):
    email = request.session.get('email')
    user = Users.objects.get(email=email)
    user.is_active = False
    user.save()
    auth_logout(request)
    return redirect('user-login') 
