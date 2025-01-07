from rest_framework import serializers
from .models import GeneratedPassword, PasswordAnalysis, PasswordIssue
from vault.models import LoginInfo

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

class PasswordAnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordAnalysis
        fields = ['id', 'vault', 'analysis_date', 'reused_passwords_count', 
                 'similar_passwords_count', 'breached_passwords_count']

class PasswordIssueSerializer(serializers.ModelSerializer):
    login_username = serializers.CharField(source='login_info.login_username')
    
    class Meta:
        model = PasswordIssue
        fields = ['id', 'issue_type', 'login_username', 'similarity_score', 'details']

class VaultAnalysisResultSerializer(serializers.ModelSerializer):
    issues = PasswordIssueSerializer(many=True, read_only=True)
    
    class Meta:
        model = PasswordAnalysis
        fields = ['id', 'vault', 'analysis_date', 'reused_passwords_count', 
                 'similar_passwords_count', 'breached_passwords_count', 'issues']