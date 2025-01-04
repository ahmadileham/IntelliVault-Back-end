from django.db import models
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericRelation

from collaboration.models import Team


class Vault(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              on_delete=models.CASCADE)
    team = models.ForeignKey(
        Team, on_delete=models.CASCADE, related_name='vaults', null=True, blank=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name + ' - ' + self.owner.username

    @property
    def is_team_vault(self):
        return self.team is not None


class Item(models.Model):

    FILE = 'file'
    LOGININFO = 'logininfo'

    vault = models.ForeignKey(Vault, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class LoginInfo(Item):
    login_username = models.CharField(max_length=100)
    login_password = models.TextField()  # Encrypted password
    shared_items = GenericRelation('SharedItem')


class File(Item):
    file_name = models.CharField(max_length=255)
    file_content = models.BinaryField()  # Encrypted file content
    mime_type = models.CharField(max_length=255)
    shared_items = GenericRelation('SharedItem')


class TeamVaultActionRequest(models.Model):
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'

    ACTION_CHOICES = [
        (CREATE, 'Create'),
        (UPDATE, 'Update'),
        (DELETE, 'Delete'),
    ]

    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
    ]

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='action_requests')
    authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vault_actions', null=True, blank=True)
    team_vault = models.ForeignKey(
        Vault, on_delete=models.CASCADE, related_name='action_requests')
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    item_type = models.CharField(max_length=50)
    item_data = models.JSONField()  # Store serialized data for the item
    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default=PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    authorized_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.action_type.capitalize()} request for {self.item_type} by {self.requester.username}"


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

    def __str__(self):
        return self.vault.name + ' - ' + self.shared_by.username


class SharedItem(SharedBase):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    item = GenericForeignKey('content_type', 'object_id')

    def __str__(self):
        return self.item.__class__.__name__ + ' - ' + self.shared_by.username
