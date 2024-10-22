from rest_framework import serializers
from .models import Vault, LoginInfo, File, SharedVault, SharedItem


class VaultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vault
        fields = ['id', 'owner', 'team', 'name']


class LoginInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginInfo
        fields = ['id', 'vault', 'login_username', 'login_password']

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'vault', 'file_name', 'file_content']


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
