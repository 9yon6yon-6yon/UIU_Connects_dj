# Generated by Django 4.2.2 on 2023-08-29 17:09

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('SocialMediaManagementSystem', '0002_rename_receiver_id_chats_receiver_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='PersonalInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_Name', models.CharField(max_length=50)),
                ('fathers_Name', models.CharField(max_length=50)),
                ('mothers_Name', models.CharField(max_length=50)),
                ('image_path', models.FileField(null=True, upload_to='profile_pics/')),
                ('file_checksum', models.CharField(blank=True, max_length=64)),
                ('d_o_b', models.DateField()),
                ('nationality', models.CharField(max_length=100)),
                ('status', models.CharField(choices=[('married', 'Married'), ('single', 'Single'), ('divorced', 'Divorced')], default='single', max_length=10)),
                ('address', models.TextField()),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='SocialMediaManagementSystem.users')),
            ],
        ),
    ]