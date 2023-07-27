from django.db import models

class Users(models.Model):
    u_id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    email_verified_at = models.DateTimeField(null=True)
    password = models.CharField(max_length=255)
    USER_TYPES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('admin', 'Admin'),
    ]
    user_type = models.CharField(choices=USER_TYPES, max_length=10, default='student')
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
    ]
    status = models.CharField(choices=STATUS_CHOICES, max_length=255, default='pending')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Awards(models.Model):
    awrd_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    award_name = models.CharField(max_length=255)
    award_received = models.DateField()
    award_description = models.TextField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Certificates(models.Model):
    cert_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    certification_name = models.CharField(max_length=255)
    issuing_organization = models.CharField(max_length=255)
    credentials = models.CharField(max_length=255)
    expiration_date = models.DateField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Chats(models.Model):
    chat_id = models.BigAutoField(primary_key=True)
    sender_id = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='sender_chats')
    receiver_id = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='receiver_chats')
    message = models.TextField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Comments(models.Model):
    com_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    pst_id = models.ForeignKey('Posts', on_delete=models.CASCADE)
    c_details = models.TextField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Contacts(models.Model):
    contact_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    email = models.EmailField()
    phone = models.CharField(max_length=25)
    others = models.CharField(max_length=255)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Education(models.Model):
    edu_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    institution = models.CharField(max_length=255)
    degree = models.CharField(max_length=255)
    field_of_study = models.CharField(max_length=255)
    graduation_date = models.DateField()
    education_description = models.TextField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Events(models.Model):
    event_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    event_title = models.CharField(max_length=100)
    event_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    event_date = models.DateField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Experiences(models.Model):
    e_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    company = models.CharField(max_length=255)
    position = models.CharField(max_length=255)
    joining_date = models.DateField()
    retired_date = models.DateField(null=True)
    description = models.TextField()
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)


class Follows(models.Model):
    follow_id = models.BigAutoField(primary_key=True)
    follower = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='follower_set')
    following = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='following_set')
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Interests(models.Model):
    interest_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    interest_name = models.CharField(max_length=255)
    reason = models.TextField(null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Jobs(models.Model):
    job_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    job_title = models.CharField(max_length=100)
    job_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class JobApplications(models.Model):
    j_application = models.BigAutoField(primary_key=True)
    applied_user = models.ForeignKey(Users, on_delete=models.CASCADE)
    j_id = models.ForeignKey(Jobs, on_delete=models.CASCADE)
    file_path = models.CharField(max_length=255)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)



class Posts(models.Model):
    pst_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    post_title = models.CharField(max_length=100)
    post_details = models.TextField()
    files = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(null=True)

class Sessions(models.Model):
    id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(Users, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=45, null=True)
    user_agent = models.TextField(null=True)
    payload = models.TextField()
    last_activity = models.DateTimeField()
    
