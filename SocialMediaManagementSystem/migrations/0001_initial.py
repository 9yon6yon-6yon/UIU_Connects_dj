# Generated by Django 4.2.2 on 2023-08-29 16:43

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordResetToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('token', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='Users',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('u_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('email_verified_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('password', models.CharField(max_length=255)),
                ('user_type', models.CharField(choices=[('student', 'Student'), ('teacher', 'Teacher')], default='student', max_length=10)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('verified', 'Verified')], default='pending', max_length=255)),
                ('is_active', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('encryption_key', models.CharField(max_length=255, null=True)),
                ('public_key', models.BinaryField(null=True)),
                ('private_key', models.BinaryField(null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Sessions',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('ip_address', models.CharField(max_length=45, null=True)),
                ('user_agent', models.TextField(null=True)),
                ('payload', models.TextField()),
                ('last_activity', models.DateTimeField()),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Posts',
            fields=[
                ('pst_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('post_title', models.CharField(max_length=100)),
                ('post_details', models.TextField()),
                ('file_path', models.FileField(null=True, upload_to='post_files/')),
                ('file_checksum', models.CharField(blank=True, max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Jobs',
            fields=[
                ('job_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('job_title', models.CharField(max_length=100)),
                ('job_details', models.TextField()),
                ('file_path', models.FileField(null=True, upload_to='job_files/')),
                ('file_checksum', models.CharField(blank=True, max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='JobApplications',
            fields=[
                ('j_application', models.BigAutoField(primary_key=True, serialize=False)),
                ('file_path', models.FileField(null=True, upload_to='job_applications/')),
                ('file_checksum', models.CharField(blank=True, max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('applied_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
                ('j_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.jobs')),
            ],
        ),
        migrations.CreateModel(
            name='Interests',
            fields=[
                ('interest_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('interest_name', models.CharField(max_length=255)),
                ('reason', models.TextField(null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Follows',
            fields=[
                ('follow_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('follower', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='follower_set', to='SocialMediaManagementSystem.users')),
                ('following', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='following_set', to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Experiences',
            fields=[
                ('e_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('company', models.CharField(max_length=255)),
                ('position', models.CharField(max_length=255)),
                ('joining_date', models.DateField()),
                ('retired_date', models.DateField(null=True)),
                ('description', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Events',
            fields=[
                ('event_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_title', models.CharField(max_length=100)),
                ('event_details', models.TextField()),
                ('file_path', models.FileField(null=True, upload_to='event_files/')),
                ('file_checksum', models.CharField(blank=True, max_length=64)),
                ('event_date', models.DateField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Education',
            fields=[
                ('edu_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('institution', models.CharField(max_length=255)),
                ('degree', models.CharField(max_length=255)),
                ('field_of_study', models.CharField(max_length=255)),
                ('graduation_date', models.DateField()),
                ('education_description', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Contacts',
            fields=[
                ('contact_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254)),
                ('phone', models.CharField(max_length=25)),
                ('others', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Comments',
            fields=[
                ('com_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('c_details', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('pst_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.posts')),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Chats',
            fields=[
                ('chat_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('message', models.TextField()),
                ('message_hash', models.CharField(blank=True, max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('receiver_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='receiver_chats', to='SocialMediaManagementSystem.users')),
                ('sender_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sender_chats', to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Certificates',
            fields=[
                ('cert_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('certification_name', models.CharField(max_length=255)),
                ('issuing_organization', models.CharField(max_length=255)),
                ('credentials', models.CharField(max_length=255)),
                ('expiration_date', models.DateField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
        migrations.CreateModel(
            name='Awards',
            fields=[
                ('awrd_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('award_name', models.CharField(max_length=255)),
                ('award_received', models.DateField()),
                ('award_description', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
    ]
