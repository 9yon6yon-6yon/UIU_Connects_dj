from django.utils.crypto import get_random_string
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.hashers import make_password
import random
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import re
from django.urls import reverse
from django.http import HttpResponse
from django.conf import settings
from .models import *
import hashlib

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
                UserActivityLog.objects.create(
                user=user,
                action="loggedin",
                details="successfully logged in"
                )
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
    return render(request, 'dashboard.html')
def posts_view(request):
    return render(request, 'dashboard.html')
def create_post_view(request):
    return render(request, 'createpost.html')
def chat_dashboard_view(request):
    return render(request, 'chat.html')
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
def user_profile_view(request,user_id):
    user = get_object_or_404(Users, u_id=user_id)
    context = {'user_id': user_id}
    return render(request, 'dashboard.html', context )
def logout(request):
    email = request.session.get('email')
    user = Users.objects.get(email=email)
    user.is_active = False
    user.save()
    auth_logout(request)
    return redirect('user-login') 
def calculate_file_checksum(file):
    hasher = hashlib.sha256()
    for chunk in file.chunks():
        hasher.update(chunk)
    return hasher.hexdigest()
def user_post(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        details = request.POST.get('details')
        file_path = request.FILES.get('file_path')
        
        user_id = request.session.get('user_id')

        if user_id:
            user = Users.objects.get(u_id=user_id)
            if file_path:
                file_checksum = calculate_file_checksum(file_path)

                post = Posts(
                    user_id=user,
                    post_title=title,
                    post_details=details,
                    file_path=file_path,
                    file_checksum=file_checksum
                )
                post.save()
            else:
                post = Posts(
                    user_id=user,
                    post_title=title,
                    post_details=details
                )
                post.save()
            
            messages.success(request, 'General post created successfully.')
            return redirect('create-post')
        else:
            messages.error(request, 'User session data missing.')
            return render(request, 'createpost.html')
    else:
        messages.error(request, 'Some error occurred while creating post')
        return render(request, 'createpost.html')

def job_create(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        details = request.POST.get('details')
        file_path = request.FILES.get('file_path')
        
        user_id = request.session.get('user_id')        
        if user_id:
            user = Users.objects.get(u_id=user_id)
            if file_path:

                post = Jobs(
                    user_id=user,
                    job_title=title,
                    job_details=details,
                    file_path=file_path
                )
                post.save()
            else:
                post = Posts(
                    user_id=request.session['user_id'],
                    job_title=title,
                    job_details=details
                )
                post.save()
            messages.success(request, 'Job post created successfully.')
            return redirect('create-post')
        else:
            messages.error(request, 'User session data missing.')
            return render(request, 'createpost.html')
    else:
        messages.error(request, 'Some error occurred while creating post')
        return render(request, 'createpost.html')

def event_create(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        details = request.POST.get('details')
        file_path = request.FILES.get('file_path')
        event_date = request.POST.get('eventdate')
        
        user_id = request.session.get('user_id')
        if user_id:
            user = Users.objects.get(u_id=user_id)
            if file_path:
                post = Events(
                    user_id=user,
                    event_title=title,
                    event_details=details,
                    file_path=file_path,
                    event_date=event_date
                )
                post.save()
            else:
                post = Posts(
                    user_id=request.session['user_id'],
                    event_title=title,
                    event_details=details,
                    event_date=event_date
                )
                post.save()
            messages.success(request, 'Job post created successfully.')
            return redirect('create-post')
        else:
            messages.error(request, 'User session data missing.')
            return render(request, 'createpost.html')
    else:
        messages.error(request, 'Some error occurred while creating post')
        return render(request, 'createpost.html')

def loadChat(request):
    active_users= Users.objects.filter().exclude(u_id=request.session['user_id'])
    return render(request, 'chat.html', {'active_users': active_users})
def loadSpecificChat(request, id):
    logged_in_user_id = request.session.get('user_id')
    logged_in_user = Users.objects.get(u_id=logged_in_user_id)

    selected_user = get_object_or_404(Users, u_id=id)

    sent_messages = Chats.objects.filter(
        sender=logged_in_user, receiver=selected_user
    )
    received_messages = Chats.objects.filter(
        sender=selected_user, receiver=logged_in_user
    )

    all_messages = list(sent_messages) + list(received_messages)
    updated_messages = []

    for chat in all_messages:
        calculated_hash = hashlib.sha256(chat.message.encode()).hexdigest()
        if calculated_hash != chat.message_hash:
            chat.decrypted_message = "Message has been tampered with!"
        else:
            updated_messages.append(chat)

    updated_messages.sort(key=lambda x: x.created_at, reverse=False)

    context = {'selected_user': selected_user, 'all_messages': updated_messages}
    chat_content = render_to_string('chat-context.html', context)

    if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
        return HttpResponse(chat_content)
    else:
        return render(request, 'chat.html', context)

def sendChat(request, id):
    if request.method == 'POST':
        logged_in_user_id = request.session.get('user_id')
        logged_in_user = Users.objects.get(u_id=logged_in_user_id)
        selected_user = get_object_or_404(Users, u_id=id)

        message_text = request.POST.get('message')
        if message_text:
            message_hash = hashlib.sha256(message_text.encode()).hexdigest()
            Chats.objects.create(
                sender=logged_in_user,
                receiver=selected_user,
                message=message_text,
                message_hash=message_hash
            )
    return redirect('user.chat.show', id=id)
