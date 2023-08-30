from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

import hashlib

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
    
    encryption_key = models.CharField(max_length=255,null=True)
    public_key = models.BinaryField(null=True)
    private_key = models.BinaryField(null=True)
    objects = CustomUserManager()

    def save(self, *args, **kwargs):

        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key()
        if not self.public_key or not self.private_key:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        super().save(*args, **kwargs)

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

class PersonalInfo(models.Model):
    user_id = models.OneToOneField(Users, on_delete=models.CASCADE)
    user_Name = models.CharField(max_length=50)
    fathers_Name = models.CharField(max_length=50)
    mothers_Name = models.CharField(max_length=50)
    file_path = models.FileField(upload_to='profile_pics/', null=True)
    file_checksum = models.CharField(max_length=64, blank=True)
     
    d_o_b = models.DateField()
    nationality = models.CharField(max_length=100)
    STATUS_CHOICES = [
        ('married', 'Married'),
        ('single', 'Single'),
        ('divorced', 'Divorced'),
    ]
    status = models.CharField(choices=STATUS_CHOICES, max_length=10, default='single')
    address = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user_Name

    
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
    sender = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='sender_chats')
    receiver = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='receiver_chats')
    message = models.TextField(null=True)
    message_hash = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        # Calculate and store message hash before saving
        if self.message:
            self.message_hash = hashlib.sha256(self.message.encode()).hexdigest()
        super().save(*args, **kwargs)


class Posts(models.Model):
    pst_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    post_title = models.CharField(max_length=100)
    post_details = models.TextField()
    file_path = models.FileField(upload_to='post_files/', null=True)
    file_checksum = models.CharField(max_length=64, blank=True)
     
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Comments(models.Model):
    com_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    pst_id = models.ForeignKey(Posts, on_delete=models.CASCADE)
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
    file_path = models.FileField(upload_to='event_files/', null=True)
    file_checksum = models.CharField(max_length=64, blank=True)
     
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
    file_path = models.FileField(upload_to='job_files/', null=True)
    file_checksum = models.CharField(max_length=64, blank=True)
     
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class JobApplications(models.Model):
    j_application = models.BigAutoField(primary_key=True)
    applied_user = models.ForeignKey(Users, on_delete=models.CASCADE)
    j_id = models.ForeignKey(Jobs, on_delete=models.CASCADE)
    file_path = models.FileField(upload_to='job_applications/', null=True)
    file_checksum = models.CharField(max_length=64, blank=True)
     
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

class Sessions(models.Model):
    id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45, null=True)
    user_agent = models.TextField(null=True)
    payload = models.TextField()
    last_activity = models.DateTimeField()
    
