# Generated by Django 5.1.1 on 2024-10-31 18:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0007_alter_file_file_content_alter_shareditem_share_link_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='shareditem',
            name='share_link',
            field=models.CharField(default='LjuYGzhb5J', max_length=100, unique=True),
        ),
        migrations.AlterField(
            model_name='sharedvault',
            name='share_link',
            field=models.CharField(default='LjuYGzhb5J', max_length=100, unique=True),
        ),
    ]
