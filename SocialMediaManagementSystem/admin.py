from django.contrib import admin
from .models import Users, Posts, Events, Jobs, Sessions, UserActivityLog

class UsersAdmin(admin.ModelAdmin):
    list_display = ('email', 'user_type', 'status', 'is_blocked', 'block_end_date')
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'details', 'timestamp')
class PostsAdmin(admin.ModelAdmin):
     list_display = ('user_id', 'post_title', 'post_details', 'created_at','updated_at')
class JobsAdmin(admin.ModelAdmin):
     list_display = ('user_id', 'job_title', 'job_details', 'created_at','updated_at')
class EventsAdmin(admin.ModelAdmin):
      list_display = ('user_id', 'event_title', 'event_details', 'event_date','created_at','updated_at')



admin.site.register(Users, UsersAdmin)
admin.site.register(Posts,PostsAdmin)
admin.site.register(Events,EventsAdmin)
admin.site.register(Jobs,JobsAdmin)

admin.site.register(UserActivityLog,UserActivityLogAdmin)
