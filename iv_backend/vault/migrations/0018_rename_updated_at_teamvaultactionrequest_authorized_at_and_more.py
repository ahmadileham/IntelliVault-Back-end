# Generated by Django 5.1.1 on 2024-12-18 21:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0017_alter_teamvaultactionrequest_action'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teamvaultactionrequest',
            old_name='updated_at',
            new_name='authorized_at',
        ),
        migrations.RenameField(
            model_name='teamvaultactionrequest',
            old_name='action_by',
            new_name='authorized_by',
        ),
    ]