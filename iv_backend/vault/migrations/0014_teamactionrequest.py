# Generated by Django 5.1.1 on 2024-12-18 16:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0013_file_mime_type'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TeamActionRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action_type', models.CharField(choices=[('add', 'Add'), ('edit', 'Edit'), ('delete', 'Delete')], max_length=10)),
                ('item_type', models.CharField(max_length=50)),
                ('item_data', models.JSONField()),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('admin', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='approved_actions', to=settings.AUTH_USER_MODEL)),
                ('requester', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='action_requests', to=settings.AUTH_USER_MODEL)),
                ('team_vault', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='action_requests', to='vault.vault')),
            ],
        ),
    ]
