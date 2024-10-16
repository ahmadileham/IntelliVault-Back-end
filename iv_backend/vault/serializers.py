from rest_framework import serializers
from .models import Vault, LoginInfo, File
from .encryption_utils import AESEncryption

class VaultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vault
        fields = ['id', 'owner', 'team', 'name']

class LoginInfoSerializer(serializers.ModelSerializer):
    decrypted_password = serializers.SerializerMethodField()

    class Meta:
        model = LoginInfo
        fields = ['id', 'vault', 'login_username', 'login_password', 'decrypted_password']

    def get_decrypted_password(self, obj):
        aes = AESEncryption()
        return aes.decrypt(obj.login_password)

    def create(self, validated_data):
        aes = AESEncryption()
        validated_data['login_password'] = aes.encrypt(validated_data['login_password'])
        return super().create(validated_data)

class FileSerializer(serializers.ModelSerializer):
    decrypted_content = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = ['id', 'vault', 'file_name', 'file_content', 'decrypted_content']

    def get_decrypted_content(self, obj):
        aes = AESEncryption()
        return aes.decrypt(obj.file_content)

    def create(self, validated_data):
        aes = AESEncryption()
        validated_data['file_content'] = aes.encrypt(validated_data['file_content'])
        return super().create(validated_data)
