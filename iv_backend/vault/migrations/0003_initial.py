# Generated by Django 5.1.1 on 2024-10-09 10:31

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('vault', '0002_remove_item_shared_with_remove_logininfo_item_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Vault',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='LoginInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('login_username', models.CharField(max_length=100)),
                ('login_password', models.TextField()),
                ('vault', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vault.vault')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('file_name', models.CharField(max_length=255)),
                ('file_content', models.TextField()),
                ('vault', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='vault.vault')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
