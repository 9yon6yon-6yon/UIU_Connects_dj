from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.shortcuts import render
from SocialMediaManagementSystem.models import Users
from django.shortcuts import redirect
from django.utils import timezone
class FailedLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST':
            ip = self.get_client_ip(request)
            cache_key = f'failed_login_attempts_{ip}'
            attempts = cache.get(cache_key, 0)

            if attempts >= 5:  # You can adjust the threshold as needed
                return HttpResponseForbidden(render(request,'forbidden.html'))

            if 'login' in request.POST:
                email = request.POST.get('email')
                password = request.POST.get('password')

                user = Users.objects.get(email=email)

                if not user.check_password(password):
                    attempts += 1
                    cache.set(cache_key, attempts, timeout=60*2)

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class BlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if request.user.is_authenticated and hasattr(request.user, 'block_end_date'):
            current_time = timezone.now()
            if request.user.is_blocked and current_time < request.user.block_end_date:
               return render(request, 'blocked.html' , { 'date' : current_time })

        return response