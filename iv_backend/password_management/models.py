from django.db import models
from django.utils import timezone
from django.conf import settings

class GeneratedPassword(models.Model):
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='generated_passwords')  # Link to User
    password = models.CharField(max_length=128)  # Storing the generated password
    strength = models.BooleanField()  # True = Strong, False = Weak
    date_generated = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Password: {self.password} (Strength: {'Strong' if self.strength else 'Weak'})"