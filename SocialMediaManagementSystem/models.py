from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
class Users(AbstractBaseUser):
    u_id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    email_verified_at = models.DateTimeField(default=timezone.now)
    password = models.CharField(max_length=255)
    USER_TYPES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
    ]
    user_type = models.CharField(choices=USER_TYPES, max_length=10, default='student')
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
    ]
    status = models.CharField(choices=STATUS_CHOICES, max_length=255, default='pending')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    objects = CustomUserManager()

class OTP(models.Model):
    user = models.OneToOneField(Users, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email}: {self.otp}"
class PasswordResetToken(models.Model):
    email = models.EmailField()
    token = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Password reset token for {self.email}"
class Awards(models.Model):
    awrd_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    award_name = models.CharField(max_length=255)
    award_received = models.DateField()
    award_description = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Certificates(models.Model):
    cert_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    certification_name = models.CharField(max_length=255)
    issuing_organization = models.CharField(max_length=255)
    credentials = models.CharField(max_length=255)
    expiration_date = models.DateField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Chats(models.Model):
    chat_id = models.BigAutoField(primary_key=True)
    sender_id = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='sender_chats')
    receiver_id = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='receiver_chats')
    message = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Comments(models.Model):
    com_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    pst_id = models.ForeignKey('Posts', on_delete=models.CASCADE)
    c_details = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Contacts(models.Model):
    contact_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    email = models.EmailField()
    phone = models.CharField(max_length=25)
    others = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Education(models.Model):
    edu_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    institution = models.CharField(max_length=255)
    degree = models.CharField(max_length=255)
    field_of_study = models.CharField(max_length=255)
    graduation_date = models.DateField()
    education_description = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Events(models.Model):
    event_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    event_title = models.CharField(max_length=100)
    event_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    event_date = models.DateField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Experiences(models.Model):
    e_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    company = models.CharField(max_length=255)
    position = models.CharField(max_length=255)
    joining_date = models.DateField()
    retired_date = models.DateField(null=True)
    description = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)


class Follows(models.Model):
    follow_id = models.BigAutoField(primary_key=True)
    follower = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='follower_set')
    following = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='following_set')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Interests(models.Model):
    interest_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    interest_name = models.CharField(max_length=255)
    reason = models.TextField(null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Jobs(models.Model):
    job_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=100)
    job_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class JobApplications(models.Model):
    j_application = models.BigAutoField(primary_key=True)
    applied_user = models.ForeignKey(Users, on_delete=models.CASCADE)
    j_id = models.ForeignKey(Jobs, on_delete=models.CASCADE)
    file_path = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)



class Posts(models.Model):
    pst_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    post_title = models.CharField(max_length=100)
    post_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Sessions(models.Model):
    id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45, null=True)
    user_agent = models.TextField(null=True)
    payload = models.TextField()
    last_activity = models.DateTimeField()
    
