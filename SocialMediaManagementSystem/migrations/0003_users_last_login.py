# Generated by Django 4.2.2 on 2023-07-29 08:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SocialMediaManagementSystem', '0002_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='last_login',
            field=models.DateTimeField(blank=True, null=True, verbose_name='last login'),
        ),
    ]
