from rest_framework import viewsets, permissions, views, status
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from .utils import AESEncryption, create_shared_item_link, create_shared_vault_link, decrypt_item
from .serializers import VaultSerializer, LoginInfoSerializer, FileSerializer, SharedItemSerializer, SharedVaultSerializer
from .models import Vault, LoginInfo, File, SharedVault, SharedItem
from django.contrib.contenttypes.models import ContentType


def encrypt_data(data):
    aes = AESEncryption()
    return aes.encrypt(data)


def decrypt_data(data):
    aes = AESEncryption()
    return aes.decrypt(data)


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

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        # Decrypt login passwords before sending response
        for item in serializer.data:
            item['decrypted_password'] = decrypt_data(item['login_password'])

        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        # Encrypt password before saving
        request.data['login_password'] = encrypt_data(
            request.data['login_password'])
        return super().create(request, *args, **kwargs)


class FileViewSet(viewsets.ModelViewSet):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return files that belong to vaults owned by the authenticated user
        return File.objects.filter(vault__owner=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        # Decrypt file contents before sending response
        for item in serializer.data:
            item['decrypted_content'] = decrypt_data(item['file_content'])

        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        # Encrypt file content before saving
        request.data['file_content'] = encrypt_data(
            request.data['file_content'])
        return super().create(request, *args, **kwargs)


# Sharing views
class ShareItemView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, item_id, password):
        try:
            item_type = request.data.get('item_type')
            if item_type == 'logininfo':
                item_model = LoginInfo
            elif item_type == 'file':
                item_model = File
            else:
                return Response({'error': 'Invalid item type'}, status=status.HTTP_400_BAD_REQUEST)

            content_type = ContentType.objects.get_for_model(item_model)
            item = item_model.objects.get(id=item_id)

            shared_item = create_shared_item_link(item, request.user, password)

            return Response(SharedItemSerializer(shared_item).data, status=status.HTTP_201_CREATED)

        except item_model.DoesNotExist:
            return Response({'error': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)


class ShareVaultView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, vault_id, password):
        try:
            vault = Vault.objects.get(id=vault_id)
            shared_vault = create_shared_vault_link(
                vault, request.user, password)

            return Response(SharedVaultSerializer(shared_vault).data, status=status.HTTP_201_CREATED)

        except Vault.DoesNotExist:
            return Response({'error': 'Vault not found'}, status=status.HTTP_404_NOT_FOUND)


# Accessing shared vaults and items
class AccessSharedItemView(views.APIView):
    def post(self, request, share_link, password):
        try:
            shared_item = SharedItem.objects.get(share_link=share_link)

            # Check if the link has expired
            if shared_item.has_expired():
                return Response({'error': 'Link has expired'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the access password
            if check_password(password, shared_item.access_password):
                # Decrypt the shared item
                item_data = decrypt_item(shared_item.item)
                if item_data is not None:
                    return Response({'message': 'Access granted', 'item': item_data}, status=status.HTTP_200_OK)
                return Response({'error': 'Unsupported item type'}, status=status.HTTP_400_BAD_REQUEST)

            # If password doesn't match
            return Response({'error': 'Invalid password'}, status=status.HTTP_403_FORBIDDEN)

        except SharedItem.DoesNotExist:
            return Response({'error': 'Shared item not found'}, status=status.HTTP_404_NOT_FOUND)


class AccessSharedVaultView(views.APIView):
    def post(self, request, share_link, password):
        try:
            shared_vault = SharedVault.objects.get(share_link=share_link)

            # Check if the link has expired
            if shared_vault.has_expired():
                return Response({'error': 'Link has expired'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the access password
            if check_password(password, shared_vault.access_password):
                # Get all LoginInfo and File items in the vault
                login_items = LoginInfo.objects.filter(
                    vault=shared_vault.vault)
                file_items = File.objects.filter(vault=shared_vault.vault)

                decrypted_login_items = [decrypt_item(
                    login) for login in login_items]
                decrypted_file_items = [
                    decrypt_item(file) for file in file_items]

                # Return the decrypted vault items
                return Response({
                    'message': 'Access granted',
                    'login_items': decrypted_login_items,
                    'file_items': decrypted_file_items
                }, status=status.HTTP_200_OK)

            # If password doesn't match
            return Response({'error': 'Invalid password'}, status=status.HTTP_403_FORBIDDEN)

        except SharedVault.DoesNotExist:
            return Response({'error': 'Shared vault not found'}, status=status.HTTP_404_NOT_FOUND)
