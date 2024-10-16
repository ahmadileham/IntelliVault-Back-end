from rest_framework import viewsets, permissions
from .models import Vault, LoginInfo, File
from .serializers import VaultSerializer, LoginInfoSerializer, FileSerializer

class VaultViewSet(viewsets.ModelViewSet):
    serializer_class = VaultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return vaults that belong to the authenticated user
        return Vault.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        # Set the owner as the authenticated user when creating a vault
        serializer.save(owner=self.request.user)
        
class LoginInfoViewSet(viewsets.ModelViewSet):
    serializer_class = LoginInfoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return login info that belongs to vaults owned by the authenticated user
        return LoginInfo.objects.filter(vault__owner=self.request.user)

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return files that belong to vaults owned by the authenticated user
        return File.objects.filter(vault__owner=self.request.user)
