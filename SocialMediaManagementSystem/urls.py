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
    path('user/create-post/', create_post_view, name='create-post'),
    path('user/chat/dashboard/', loadChat, name='chat.dashboard'),
    path('user/settings/', settings_view, name='user.settings'),
    path('user/logout/', logout, name='user.logout'),
    path('user/status/', changestatus, name='change.status'),
    path('user/profile/<int:user_id>/',
         user_profile_view, name='user.profile'),

    path('user/post/create/', user_post, name='user_post'),
    path('user/jobs/create/', job_create, name='job_create'),
    path('user/events/create/',event_create, name='event_create'),

    path('user/chat/view/', loadChat, name='user.chat.view'),
    path('user/chat/show/<int:id>/', loadSpecificChat, name='user.chat.show'),
    path('user/chat/send/<int:id>/', sendChat, name='user.chat.send'),

]
