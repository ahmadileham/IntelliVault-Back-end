from rest_framework import serializers
from .models import GeneratedPassword

class GeneratedPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeneratedPassword
        fields = ['id', 'generated_by', 'password', 'strength', 'date_generated']
        read_only_fields = ['generated_by', 'date_generated']  # Prevent users from manually setting these fields

# Serializer for creating a new password with user input
class PasswordCreateSerializer(serializers.Serializer):
    length = serializers.IntegerField(default=12, min_value=1, max_value=128)
    use_uppercase = serializers.BooleanField(default=False)
    use_numbers = serializers.BooleanField(default=False)
    use_special_chars = serializers.BooleanField(default=False)