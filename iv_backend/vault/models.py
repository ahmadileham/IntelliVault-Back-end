from django.db import models
from django.conf import settings

from collaboration.models import Team

class Vault(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='vaults', null=True, blank=True)
    name = models.CharField(max_length=100)

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
    file_content = models.TextField()  # Encrypted file content
