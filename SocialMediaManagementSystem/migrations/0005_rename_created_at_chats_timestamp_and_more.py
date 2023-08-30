# Generated by Django 4.2.2 on 2023-08-29 20:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('SocialMediaManagementSystem', '0004_rename_image_path_personalinfo_file_path'),
    ]

    operations = [
        migrations.RenameField(
            model_name='chats',
            old_name='created_at',
            new_name='timestamp',
        ),
        migrations.RemoveField(
            model_name='chats',
            name='message',
        ),
        migrations.RemoveField(
            model_name='chats',
            name='message_hash',
        ),
        migrations.RemoveField(
            model_name='chats',
            name='updated_at',
        ),
        migrations.AddField(
            model_name='chats',
            name='encrypted_message',
            field=models.BinaryField(null=True),
        ),
        migrations.AddField(
            model_name='chats',
            name='encrypted_symmetric_key',
            field=models.BinaryField(null=True),
        ),
        migrations.AddField(
            model_name='chats',
            name='signature',
            field=models.BinaryField(null=True),
        ),
        migrations.AlterField(
            model_name='chats',
            name='receiver',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_chats', to='SocialMediaManagementSystem.users'),
        ),
        migrations.AlterField(
            model_name='chats',
            name='sender',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_chats', to='SocialMediaManagementSystem.users'),
        ),
    ]