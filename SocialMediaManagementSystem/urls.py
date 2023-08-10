from django.contrib import admin
from django.urls import path
from .views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name='index'),
    path('user/login/',login, name='user-login'),
    path('user/signup/',signup, name='user-sign-up'),
    path('user/forgot-password/',forgotPassword, name='forget.password.form'),
    path('user/reset-password/',send_reset_link, name='forget.password.link'),
    path('user/reset-new-password/<str:token>/<str:email>',reset_Password, name='reset.password'),
    path('user/save-new-password/',save_Password, name='save.password'),
    path('user/verify-user/',verifyAccount, name='verify-account'),
    path('user/dashboard/', dashboard_view, name='user.dashboard'),
    path('user/search/', search_view, name='user.search'),
    path('user/posts/', posts_view, name='user.posts'),
    path('create-post/', create_post_view, name='create-post'),
    path('chat/dashboard/', chat_dashboard_view, name='chat.dashboard'),
    path('user/settings/', settings_view, name='user.settings'),
    path('user/logout/', logout, name='user.logout'),
    path('user/status/', changestatus, name='change.status'),
    path('user/profile/<int:user_id>/',
         user_profile_view, name='user.profile'),

]
