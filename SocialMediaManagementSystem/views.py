from django.shortcuts import render
from .models import *

def index(request):
    return render(request, 'index.html')

def login(request):
    return render(request, 'login.html')
def signup(request):
    return render(request, 'signup.html')

def forgotPassword(request):
    return render(request, 'forgot-form.html')

def resetPassword(request):
    return render(request, 'reset-form.html')

def reseted_Password(request):
    return render(request, 'reset-form.html')

def verifyAccount(request):
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
