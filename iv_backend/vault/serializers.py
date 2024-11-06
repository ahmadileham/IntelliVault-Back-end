from rest_framework import serializers
from .models import Vault, LoginInfo, File, SharedVault, SharedItem
import base64


class VaultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vault
        fields = ['id', 'owner', 'team', 'name']


class LoginInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginInfo
        fields = ['id', 'vault', 'login_username', 'login_password']

class FileSerializer(serializers.ModelSerializer):
    file_uploaded = serializers.FileField(write_only=True)  # Include the file upload field
    file_content = serializers.CharField(read_only=True)  

    class Meta:
        model = File
        fields = ['id', 'vault', 'file_name', 'file_uploaded', 'file_content']  # Include fields needed for the API
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Encode the file_content as base64
        representation['file_content'] = base64.b64encode(instance.file_content).decode('utf-8')
        return representation



# Sharing serializers
class SharedItemSerializer(serializers.ModelSerializer):
    item_type = serializers.SerializerMethodField()

    class Meta:
        model = SharedItem
        fields = ['share_link', 'shared_by',
                  'shared_at', 'expiry_date', 'item_type']

    def get_item_type(self, obj):
        return obj.content_type.model


class SharedVaultSerializer(serializers.ModelSerializer):
    class Meta:
        model = SharedVault
        fields = ['share_link', 'shared_by', 'shared_at', 'expiry_date']
