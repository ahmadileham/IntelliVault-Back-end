from django.db import models
from django.conf import settings
from django.utils import timezone
from vault.models import LoginInfo, Vault
from collaboration.models import Team

class GeneratedPassword(models.Model):
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='generated_passwords')
    password = models.CharField(max_length=128)
    strength = models.BooleanField()
    date_generated = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Password: {self.password} (Strength: {'Strong' if self.strength else 'Weak'})"

class PasswordAnalysis(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    analysis_date = models.DateTimeField(auto_now_add=True)
    reused_passwords_count = models.IntegerField(default=0)
    similar_passwords_count = models.IntegerField(default=0)
    breached_passwords_count = models.IntegerField(default=0)
    
    class Meta:
        verbose_name_plural = "Password Analyses"

class PasswordIssue(models.Model):
    REUSED = 'reused'
    SIMILAR = 'similar'
    BREACHED = 'breached'
    
    ISSUE_TYPES = [
        (REUSED, 'Reused Password'),
        (SIMILAR, 'Similar Password'),
        (BREACHED, 'Breached Password'),
    ]
    
    analysis = models.ForeignKey(PasswordAnalysis, on_delete=models.CASCADE, related_name='issues')
    login_info = models.ForeignKey('vault.LoginInfo', on_delete=models.CASCADE)
    issue_type = models.CharField(max_length=10, choices=ISSUE_TYPES)
    similarity_score = models.FloatField(null=True, blank=True)
    details = models.JSONField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.get_issue_type_display()} issue for {self.login_info.login_username}"