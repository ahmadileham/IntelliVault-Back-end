from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class Team(models.Model):
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_teams'
    )

    def __str__(self):
        return self.name

class TeamMembership(models.Model):
    ADMIN = 'admin'
    MEMBER = 'member'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (MEMBER, 'Member'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    class Meta:
        unique_together = ('user', 'team')

    def __str__(self):
        return f'{self.user.username} - {self.team.name} ({self.role})'

def get_default_expiration_date():
    return timezone.now() + timedelta(days=7)

class Invitation(models.Model):
    ACCEPT = 'accept'
    REJECT = 'reject'

    PENDING = 'pending'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (ACCEPTED, 'Accepted'),
        (REJECTED, 'Rejected'),
    ]

    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='invitations')
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='received_invitations')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_invitations')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    expiration_date = models.DateTimeField(default=get_default_expiration_date)

    def is_expired(self):
        return timezone.now() > self.expiration_date

    def __str__(self):
        return f'Invitation to {self.recipient.username} for {self.team.name} ({self.status})'
