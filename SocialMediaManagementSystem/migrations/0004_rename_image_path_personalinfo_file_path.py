# Generated by Django 4.2.2 on 2023-08-29 19:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SocialMediaManagementSystem', '0003_personalinfo'),
    ]

    operations = [
        migrations.RenameField(
            model_name='personalinfo',
            old_name='image_path',
            new_name='file_path',
        ),
    ]
