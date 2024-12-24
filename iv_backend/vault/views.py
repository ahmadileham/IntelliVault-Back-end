from django.forms import ValidationError
from rest_framework import viewsets, permissions, views, status
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from .utils import AESEncryption, create_share_item, create_share_vault, unpack_shared_item, create_team_vault_action_request
from .serializers import VaultSerializer, LoginInfoSerializer, FileSerializer, SharedItemSerializer, SharedVaultSerializer, TeamVaultActionRequestSerializer
from .models import Vault, Item, LoginInfo, File, SharedVault, SharedItem, TeamVaultActionRequest
from django.urls import reverse
import mimetypes
from django.http import HttpResponse
import random
import string
from django.shortcuts import get_object_or_404
from django.contrib.contenttypes.models import ContentType
from collaboration.models import Team, TeamMembership
from django.core.exceptions import PermissionDenied
from rest_framework.decorators import action
from django.utils import timezone
from django.db.models import Q
from .mixins import TeamRequestMixin
import base64


aes = AESEncryption()


class VaultViewSet(viewsets.ModelViewSet):
    serializer_class = VaultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):

        return Vault.objects.filter(
            Q(owner=self.request.user) | Q(
                team__memberships__user=self.request.user)
        ).distinct()

    def perform_create(self, serializer):
        team_id = self.request.data.get('team')
        if team_id:
            team = get_object_or_404(Team, id=team_id)

            # Ensure the user is an admin of the team
            if not TeamMembership.objects.filter(user=self.request.user, team=team, role=TeamMembership.ADMIN).exists():
                raise PermissionDenied(
                    "Only team admins can create vaults for the team.")

            serializer.save(owner=self.request.user, team=team)
        else:
            serializer.save(owner=self.request.user)


class LoginInfoViewSet(viewsets.ModelViewSet, TeamRequestMixin):
    serializer_class = LoginInfoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return LoginInfo.objects.filter(
            Q(vault__owner=self.request.user) | Q(
                vault__team__memberships__user=self.request.user)
        ).distinct()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)

        # Decrypt login passwords before sending response
        decrypted_data = self.decrypt_passwords(serializer.data)
        return Response(decrypted_data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        # Decrypt the login_password before sending the response
        data = serializer.data
        try:
            data['decrypted_password'] = aes.decrypt_login_password(
                data['login_password'])
        except Exception as e:
            raise ValidationError(
                {"error": f"Password decryption failed: {str(e)}"})

        # Remove the encrypted password from the response if desired
        data.pop('login_password', None)

        return Response(data)

    def create(self, request, *args, **kwargs):
        vault_id = request.data.get('vault')
        vault = get_object_or_404(Vault, id=vault_id)

        # For personal vaults, create directly
        if not vault.is_team_vault:
            self.validate_vault_ownership(vault_id, request.user)
            mutable_data = self.data_with_encrypted_password(
                None, request.data.copy())
            serializer = self.get_serializer(data=mutable_data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return super().handle_team_request(request, TeamVaultActionRequest.CREATE, vault, process_data=self.data_with_encrypted_password)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        vault = instance.vault

        # For personal vaults, update directly
        if not vault.is_team_vault:
            self.validate_vault_ownership(vault.id, request.user)
            mutable_data = self.data_with_encrypted_password(
                None, request.data.copy())
            serializer = self.get_serializer(
                instance, data=mutable_data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)

        return super().handle_team_request(request, TeamVaultActionRequest.UPDATE, vault, instance, process_data=self.data_with_encrypted_password)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        vault = instance.vault

        # For personal vaults, delete directly
        if not vault.is_team_vault:
            self.validate_vault_ownership(vault.id, request.user)
            instance.delete()
            return Response({"detail": "Deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

        return super().handle_team_request(request, TeamVaultActionRequest.DELETE, vault, instance)

    def get_team_membership(self, user, team):
        return TeamMembership.objects.filter(user=user, team=team).first()

    def data_with_encrypted_password(self, request, data):
        """Encrypt the login password and return the updated data.
        The request parameter is there because FileViewSet also uses this method."""
        if 'login_password' in data and data['login_password']:
            try:
                data['login_password'] = aes.encrypt_login_password(
                    data['login_password'])
            except Exception as e:
                raise ValidationError(
                    {"error": f"Password encryption failed: {str(e)}"})
        return data

    def decrypt_passwords(self, serialized_data):
        """Decrypt passwords for a list of serialized data."""
        decrypted_data = []
        for item in serialized_data:
            try:
                decrypted_item = item.copy()
                decrypted_item['decrypted_password'] = aes.decrypt_login_password(
                    item['login_password'])
                decrypted_data.append(decrypted_item)
            except Exception as e:
                raise ValidationError(
                    {"error": f"Password decryption failed: {str(e)}"})
        return decrypted_data

    def validate_vault_ownership(self, vault_id, user):
        """Check if the vault belongs to the authenticated user."""
        try:
            return Vault.objects.get(id=vault_id, owner=user)
        except Vault.DoesNotExist:
            raise ValidationError(
                {"error": "You do not have permission to modify this vault."})


class FileViewSet(viewsets.ModelViewSet, TeamRequestMixin):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return File.objects.filter(
            Q(vault__owner=self.request.user) | Q(
                vault__team__memberships__user=self.request.user)
        ).distinct()

    def create(self, request, *args, **kwargs):
        vault_id = request.data.get('vault')
        vault = get_object_or_404(Vault, id=vault_id)

        # For personal vaults, create directly
        if not vault.is_team_vault:
            # Validate and get the uploaded file
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            file_uploaded = request.FILES.get(
                'file_uploaded')  # Get the uploaded file
            vault_id = request.data['vault']

            # Encrypt file content before saving
            encrypted_content = aes.encrypt_file_content(
                file_uploaded.read())

            mime_type, _ = mimetypes.guess_type(file_uploaded.name)

            # Create the file instance with encrypted content
            file_instance = File.objects.create(
                vault=vault,
                file_name=file_uploaded.name,
                file_content=encrypted_content,
                mime_type=mime_type
            )

            # Serialize the created instance to return
            response_serializer = self.get_serializer(file_instance)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)

        return super().handle_team_request(request, TeamVaultActionRequest.CREATE, vault, process_data=self.process_file_data)


    def process_file_data(self, request, mutable_data):
        if 'file_uploaded' in request.FILES:
            file_uploaded = request.FILES.get(
                'file_uploaded')
            encrypted_content = aes.encrypt_file_content(
                file_uploaded.read())

            # Add encrypted content to mutable data
            mutable_data['file_content'] = encrypted_content

            # Add other file metadata (if needed)
            mutable_data['file_name'] = file_uploaded.name
            mutable_data['mime_type'] = file_uploaded.content_type

        # Ensure `file_uploaded` is removed to avoid serialization issues
        if 'file_uploaded' in mutable_data:
            del mutable_data['file_uploaded']

        return mutable_data

    def validate_vault_ownership(self, vault_id, user):
        """Check if the vault belongs to the authenticated user."""
        try:
            return Vault.objects.get(id=vault_id, owner=user)
        except Vault.DoesNotExist:
            raise ValidationError(
                {"error": "You do not have permission to modify this vault."})


class FileDownloadView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, file_id, share_link=None):
        file = get_object_or_404(File, id=file_id)

        # Check if the file belongs to the authenticated user or the authenticated user is a member of the team associated with the vault
        if file.vault.owner == request.user or TeamMembership.objects.filter(user=request.user, team=file.vault.team).exists():
            decrypted_content = aes.decrypt_file_content(file.file_content)
            return self._build_file_response(file, decrypted_content)

        # If a shared link is provided, validate it
        if share_link:
            # Check if the link is valid for either SharedItem or SharedVault
            shared_resource = self._validate_shared_resource(
                request, share_link, file)

            if shared_resource is None:
                return Response({'error': 'Invalid or expired shared link'}, status=status.HTTP_403_FORBIDDEN)

            # If valid, proceed to decrypt and download the file
            decrypted_content = aes.decrypt_file_content(file.file_content)
            return self._build_file_response(file, decrypted_content)

        # If neither condition passes, deny access
        return Response({'error': 'Unauthorized access'}, status=status.HTTP_403_FORBIDDEN)

    def _validate_shared_resource(self, request, share_link, file):
        # Attempt to retrieve either a SharedItem or SharedVault
        for resource_model in (SharedItem, SharedVault):
            try:
                if resource_model == SharedItem:

                    file_content_type = ContentType.objects.get_for_model(File)

                    shared_resource = resource_model.objects.get(
                        share_link=share_link,
                        content_type=file_content_type,
                        object_id=file.id
                    )

                    # Validate the access password
                    password = request.query_params.get('password')
                    if not password or not check_password(password, shared_resource.access_password):
                        return None  # Invalid access password
                else:
                    shared_resource = resource_model.objects.get(
                        share_link=share_link
                    )

                # Check if the shared resource has expired
                if shared_resource.has_expired():
                    return None  # Link has expired

                # If valid, return the shared resource
                return shared_resource

            except resource_model.DoesNotExist:
                continue  # Try the next resource model if not found

        return None

    def _build_file_response(self, file, decrypted_content):
        random_string = ''.join(random.choices(
            string.ascii_letters + string.digits, k=5))

        # Append random string to the filename
        file_name, file_extension = file.file_name.rsplit('.', 1)
        new_file_name = f"{file_name}-{random_string}.{file_extension}"

        # Construct the response with decrypted file content and MIME type
        response = HttpResponse(decrypted_content, content_type=file.mime_type)
        response['Content-Disposition'] = f'attachment; filename="{new_file_name}"'
        return response


# Sharing views
class ShareItemView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, item_type, item_id):

        password = request.data.get('password')

        if item_type not in ['logininfo', 'file']:
            return Response({'error': 'Invalid item type'}, status=status.HTTP_400_BAD_REQUEST)

        try:

            if item_type == Item.LOGININFO:
                item = LoginInfo.objects.get(id=item_id)
            elif item_type == Item.FILE:
                item = File.objects.get(id=item_id)

            # Create shared item with the identified type and password
            shared_item = create_share_item(item, request.user, password)

            full_share_link = request.build_absolute_uri(
                reverse('access-shared-item', args=[shared_item.share_link]))

            # Include the full URL in the response
            response_data = SharedItemSerializer(shared_item).data
            response_data['share_link'] = full_share_link

            # Optionally include item type for clarity
            response_data['item_type'] = item_type

            return Response(response_data, status=status.HTTP_201_CREATED)

        except (LoginInfo.DoesNotExist, File.DoesNotExist):
            return Response({'error': 'Item not found'}, status=status.HTTP_404_NOT_FOUND)


class ShareVaultView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, vault_id):
        password = request.data.get('password')

        try:
            vault = Vault.objects.get(id=vault_id)

            # Create shared vault with the provided password
            shared_vault = create_share_vault(vault, request.user, password)

            # Build the full URL for the share link
            full_share_link = request.build_absolute_uri(
                reverse('access-shared-vault', args=[shared_vault.share_link]))

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
        password = request.data.get('password')
        try:
            shared_item = SharedItem.objects.get(share_link=share_link)

            if shared_item.has_expired():
                return Response({'error': 'Link has expired'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the access password
            if check_password(password, shared_item.access_password):
                # Unpack the shared item and pass the share_link and request for file download url
                item_data = unpack_shared_item(
                    shared_item.item, share_link, request)

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
        password = request.data.get('password')
        try:
            shared_vault = SharedVault.objects.get(share_link=share_link)

            if shared_vault.has_expired():
                return Response({'error': 'Link has expired'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the access password
            if check_password(password, shared_vault.access_password):
                # Get all LoginInfo and File items in the vault
                login_items = LoginInfo.objects.filter(
                    vault=shared_vault.vault)
                file_items = File.objects.filter(vault=shared_vault.vault)

                decrypted_login_items = [
                    unpack_shared_item(login) for login in login_items
                ]

                decrypted_file_items = [
                    unpack_shared_item(file, share_link, request) for file in file_items
                ]

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


class TeamVaultActionRequestViewSet(viewsets.ModelViewSet):
    serializer_class = TeamVaultActionRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return TeamVaultActionRequest.objects.filter(team_vault__team__memberships__user=self.request.user)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        action_request = get_object_or_404(TeamVaultActionRequest, id=pk)

        # Ensure the user is an admin
        if not TeamMembership.objects.filter(
            user=request.user, team=action_request.team_vault.team, role=TeamMembership.ADMIN
        ).exists():
            return Response({'detail': 'Only admins can approve requests.'}, status=status.HTTP_403_FORBIDDEN)

        item_data = action_request.item_data
        if action_request.item_type == Item.LOGININFO:
            model_fields = {
                field.name for field in LoginInfo._meta.get_fields()}
            filtered_item_data = {
                key: value for key, value in item_data.items() if key in model_fields
            }

            if action_request.action == TeamVaultActionRequest.CREATE:
                vault_id = filtered_item_data.pop('vault')
                vault = get_object_or_404(Vault, id=vault_id)
                filtered_item_data['vault'] = vault
                LoginInfo.objects.create(**filtered_item_data)
            elif action_request.action == TeamVaultActionRequest.UPDATE:
                vault_id = filtered_item_data.pop('vault')
                vault = get_object_or_404(Vault, id=vault_id)
                filtered_item_data['vault'] = vault
                target = get_object_or_404(LoginInfo, id=item_data.get('id'))
                for attr, value in filtered_item_data.items():
                    setattr(target, attr, value)
                target.save()
            elif action_request.action == TeamVaultActionRequest.DELETE:
                LoginInfo.objects.filter(id=item_data.get('id')).delete()

        elif action_request.item_type == Item.FILE:
            model_fields = {field.name for field in File._meta.get_fields()}
            filtered_item_data = {
                key: value for key, value in item_data.items() if key in model_fields
            }
            
            vault_id = filtered_item_data.pop('vault')
            vault = get_object_or_404(Vault, id=vault_id)
            filtered_item_data['vault'] = vault

            if action_request.action == TeamVaultActionRequest.CREATE:
                File.objects.create(**filtered_item_data)
            elif action_request.action == TeamVaultActionRequest.UPDATE:
                target = get_object_or_404(File, id=item_data.get('id'))
                for attr, value in filtered_item_data.items():
                    setattr(target, attr, value)
                target.save()
            elif action_request.action == TeamVaultActionRequest.DELETE:
                File.objects.filter(id=item_data.get('id')).delete()

        # Update request status
        action_request.status = TeamVaultActionRequest.APPROVED
        action_request.authorized_by = request.user
        action_request.authorized_at = timezone.now()
        action_request.save()

        return Response({"detail": "Request approved successfully."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        action_request = get_object_or_404(TeamVaultActionRequest, id=pk)

        # Ensure the user is an admin
        if not TeamMembership.objects.filter(
            user=request.user, team=action_request.team_vault.team, role=TeamMembership.ADMIN
        ).exists():
            return Response({'detail': 'Only admins can reject requests.'}, status=status.HTTP_403_FORBIDDEN)

        # Update request status
        action_request.status = TeamVaultActionRequest.REJECTED
        action_request.authorized_by = request.user
        action_request.save()

        return Response({"detail": "Request rejected successfully."}, status=status.HTTP_200_OK)


class VaultItemsView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, vault_id):
        try:
            # Retrieve the vault
            vault = Vault.objects.get(id=vault_id)

            # Check if the user has access to the vault
            if not self.has_access_to_vault(request.user, vault):
                return Response({'error': 'You do not have permission to access this vault.'}, status=status.HTTP_403_FORBIDDEN)

            # Retrieve all LoginInfo and File items for the vault
            login_items = LoginInfo.objects.filter(vault=vault)
            file_items = File.objects.filter(vault=vault)

            # Serialize the items
            login_serializer = LoginInfoSerializer(login_items, many=True)
            file_serializer = FileSerializer(file_items, many=True)

            # Combine the serialized data
            response_data = {
                'login_items': login_serializer.data,
                'file_items': file_serializer.data
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Vault.DoesNotExist:
            return Response({'error': 'Vault not found.'}, status=status.HTTP_404_NOT_FOUND)

    def has_access_to_vault(self, user, vault):
        """Check if the user has access to the vault."""
        return vault.owner == user or TeamMembership.objects.filter(user=user, team=vault.team).exists()
