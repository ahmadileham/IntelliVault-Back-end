from rest_framework import viewsets, permissions, views, status
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from .utils import AESEncryption, create_share_item, create_share_vault, decrypt_item
from .serializers import VaultSerializer, LoginInfoSerializer, FileSerializer, SharedItemSerializer, SharedVaultSerializer
from .models import Vault, LoginInfo, File, SharedVault, SharedItem
from django.urls import reverse
import mimetypes
from django.http import HttpResponse
from rest_framework.decorators import action


aes = AESEncryption() 


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
        decrypted_data = []
        for item in serializer.data:
            decrypted_item = item.copy()
            decrypted_item['decrypted_password'] = aes.decrypt_login_password(item['login_password'])
            decrypted_data.append(decrypted_item)

        return Response(decrypted_data)

    def create(self, request, *args, **kwargs):
        vault_id = request.data.get('vault')

        # Check if the vault exists and belongs to the authenticated user
        try:
            vault = Vault.objects.get(id=vault_id, owner=request.user)
        except Vault.DoesNotExist:
            return Response({'error': 'You do not have permission to add items to this vault.'},
                            status=status.HTTP_403_FORBIDDEN)
        
        # Create a mutable copy of request.data
        mutable_data = request.data.copy()
        
        # Encrypt password before saving
        mutable_data['login_password'] = aes.encrypt_login_password(
            mutable_data.get('login_password', '')
        )

        # Pass the modified data to the serializer
        serializer = self.get_serializer(data=mutable_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return File.objects.filter(vault__owner=self.request.user)

    def create(self, request, *args, **kwargs):
        # Validate and get the uploaded file
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)  # Validate the input data

        file_uploaded = request.FILES.get('file_uploaded')  # Get the uploaded file
        vault_id = request.data['vault']  # Use the validated vault ID directly
        
        # Check if the vault exists and belongs to the authenticated user
        try:
            vault = Vault.objects.get(id=vault_id, owner=request.user)
        except Vault.DoesNotExist:
            return Response({'error': 'You do not have permission to add files to this vault.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Encrypt file content before saving
        encrypted_content = aes.encrypt_file_content(file_uploaded.read())  # Encrypt the uploaded file content

        mime_type, _ = mimetypes.guess_type(file_uploaded.name)

        # Create the file instance with encrypted content
        file_instance = File.objects.create(
            vault=vault,  # Use the vault instance directly
            file_name=file_uploaded.name,
            file_content=encrypted_content,
            mime_type=mime_type
        )

        # Serialize the created instance to return
        response_serializer = self.get_serializer(file_instance)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    
    def retrieve(self, request, *args, **kwargs):
        # Decrypt file content for viewing
        file_instance = self.get_object()
        serializer = self.get_serializer(file_instance)

        # Decrypt the content for the response
        decrypted_content = aes.decrypt_file_content(file_instance.file_content)

        # Add decrypted content to response data
        response_data = serializer.data
        response_data['decrypted_content'] = decrypted_content

        return Response(response_data)
    
    @action(detail=True, methods=['get'], url_path='download')
    def download(self, request, pk=None):
        # Retrieve the file instance
        file_instance = self.get_object()

        # Decrypt the content
        decrypted_content = aes.decrypt_file_content(file_instance.file_content)

        # Create the response with the decrypted content
        response = HttpResponse(decrypted_content, content_type=file_instance.mime_type)
        response['Content-Disposition'] = f'attachment; filename="{file_instance.file_name}"'
        return response

# Sharing views
class ShareItemView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, item_id):
        password = request.data.get('password')  # Retrieve password from POST data
        
        try:
            # Dynamically determine the item type by checking if the item exists in LoginInfo or File models
            try:
                item = LoginInfo.objects.get(id=item_id)
                item_type = 'logininfo'
            except LoginInfo.DoesNotExist:
                item = File.objects.get(id=item_id)
                item_type = 'file'
            
            # Create shared item with the identified type and password
            shared_item = create_share_item(item, request.user, password)
            
            # Build the full URL for the share link
            full_share_link = request.build_absolute_uri(reverse('access-shared-item', args=[shared_item.share_link]))

            # Include the full URL in the response
            response_data = SharedItemSerializer(shared_item).data
            response_data['share_link'] = full_share_link
            response_data['item_type'] = item_type  # Optionally include item type for clarity
            
            return Response(response_data, status=status.HTTP_201_CREATED)

        except (LoginInfo.DoesNotExist, File.DoesNotExist):
            return Response({'error': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)


class ShareVaultView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, vault_id):
        password = request.data.get('password')  # Retrieve password from POST data
        
        try:
            # Check if the vault exists
            vault = Vault.objects.get(id=vault_id)

            # Create shared vault with the provided password
            shared_vault = create_share_vault(vault, request.user, password)

            # Build the full URL for the share link
            full_share_link = request.build_absolute_uri(reverse('access-shared-vault', args=[shared_vault.share_link]))

            # Include the full URL in the response
            response_data = SharedVaultSerializer(shared_vault).data
            response_data['share_link'] = full_share_link

            return Response(response_data, status=status.HTTP_201_CREATED)

        except Vault.DoesNotExist:
            return Response({'error': 'Vault not found'}, status=status.HTTP_404_NOT_FOUND)


# Accessing shared vaults and items
class AccessSharedItemView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, share_link):
        password = request.data.get('password')  # Get password from request data
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
    permission_classes = [permissions.AllowAny]

    def post(self, request, share_link):
        password = request.data.get('password')  # Get password from request data
        try:
            shared_vault = SharedVault.objects.get(share_link=share_link)

            # Check if the link has expired
            if shared_vault.has_expired():
                return Response({'error': 'Link has expired'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the access password
            if check_password(password, shared_vault.access_password):
                # Get all LoginInfo and File items in the vault
                login_items = LoginInfo.objects.filter(vault=shared_vault.vault)
                file_items = File.objects.filter(vault=shared_vault.vault)

                decrypted_login_items = [decrypt_item(login) for login in login_items]
                decrypted_file_items = [decrypt_item(file) for file in file_items]

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