from django.db import models
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from collaboration.models import Team


class Vault(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              on_delete=models.CASCADE)
    team = models.ForeignKey(
        Team, on_delete=models.CASCADE, related_name='vaults', null=True, blank=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name + ' - ' + self.owner.username


class Item(models.Model):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class LoginInfo(Item):
    login_username = models.CharField(max_length=100)
    login_password = models.TextField()  # Encrypted password


class File(Item):
    file_name = models.CharField(max_length=255)
    file_content = models.BinaryField()  # Encrypted file content
    mime_type = models.CharField(max_length=255)

# Sharing Models


class SharedBase(models.Model):
    share_link = models.CharField(max_length=100, unique=True)
    access_password = models.CharField(max_length=256)  # Hashed password
    shared_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField()

    class Meta:
        abstract = True

    def has_expired(self):
        return timezone.now() > self.expiry_date


class SharedVault(SharedBase):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE)


class SharedItem(SharedBase):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    item = GenericForeignKey('content_type', 'object_id')
