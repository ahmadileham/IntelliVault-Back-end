from django.forms import ValidationError
from rest_framework import viewsets, permissions, views, status
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from .utils import AESEncryption, create_share_item, create_share_vault, unpack_shared_item
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
from .mixins import TeamRequestMixin, VaultItemValidationMixin
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
                raise PermissionDenied('Only team admins can create team vaults.')

            serializer.save(owner=self.request.user, team=team)
        else:
            serializer.save(owner=self.request.user)

    def perform_update(self, serializer):
        instance = self.get_object()

        # Check if the vault is associated with a team
        if instance.team:
            # Ensure the user is an admin of the team
            if not TeamMembership.objects.filter(user=self.request.user, team=instance.team, role=TeamMembership.ADMIN).exists():
                raise PermissionDenied('Only team admins can update team vaults.')
            
        if instance.owner != self.request.user:
            raise PermissionDenied('You do not have permission to modify this vault.')

        serializer.save()

    def perform_destroy(self, instance):
        # Check if the vault is associated with a team
        if instance.team:
            # Ensure the user is an admin of the team
            if not TeamMembership.objects.filter(user=self.request.user, team=instance.team, role=TeamMembership.ADMIN).exists():
                raise PermissionDenied('Only team admins can delete team vaults.')
        
        if instance.owner != self.request.user:
            raise PermissionDenied('You do not have permission to delete this vault.')

        instance.delete()


class LoginInfoViewSet(viewsets.ModelViewSet, TeamRequestMixin, VaultItemValidationMixin):
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
        
        if not self.is_user_a_member(request.user, vault.team):
            raise PermissionDenied('You do not have permission to create a logininfo in this vault.')

        return super().handle_team_request(request, TeamVaultActionRequest.CREATE, vault, process_data=self.data_with_encrypted_password)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        vault = instance.vault
        new_vault_id = request.data.get('vault')

        # Validate vault change
        self.validate_vault_change(instance.vault, new_vault_id)

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

        # Validate the vault ID
        validation_response = self.validate_vault_id(request, vault)
        if validation_response:
            return validation_response
        
        if not self.is_user_a_member(request.user, vault.team):
            raise PermissionDenied('You do not have permission to update this logininfo.')

        return super().handle_team_request(request, TeamVaultActionRequest.UPDATE, vault, instance, process_data=self.data_with_encrypted_password)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        vault = instance.vault

        # For personal vaults, delete directly
        if not vault.is_team_vault:
            self.validate_vault_ownership(vault.id, request.user)
            instance.delete()
            return Response({"detail": "Deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        if not self.is_user_a_member(request.user, vault.team):
            raise PermissionDenied('You do not have permission to delete this logininfo.')

        return super().handle_team_request(request, TeamVaultActionRequest.DELETE, vault, instance)

    def is_user_a_member(self, user, team):
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


class FileViewSet(viewsets.ModelViewSet, TeamRequestMixin, VaultItemValidationMixin):
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

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        vault = instance.vault
        new_vault_id = request.data.get('vault')

        # Validate vault change
        self.validate_vault_change(instance.vault, new_vault_id)

        # For personal vaults, update directly
        if not vault.is_team_vault:
            # Handle file upload during update
            if 'file_uploaded' in request.FILES:
                file_uploaded = request.FILES['file_uploaded']
                instance.file_content = aes.encrypt_file_content(file_uploaded.read())
                instance.file_name = file_uploaded.name
                instance.mime_type = file_uploaded.content_type

            serializer = self.get_serializer(
                instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

        # Validate the vault ID
        validation_response = self.validate_vault_id(request, vault)
        if validation_response:
            return validation_response

        # For team vaults, create an action request
        return super().handle_team_request(
            request, TeamVaultActionRequest.UPDATE, vault, instance=instance, process_data=self.process_file_data
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        vault = instance.vault

        # For personal vaults, delete directly
        if not vault.is_team_vault:
            instance.delete()
            return Response({"detail": "File deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

        # For team vaults, create an action request
        return super().handle_team_request(
            request, TeamVaultActionRequest.DELETE, vault, instance=instance
        )

    def process_file_data(self, request, mutable_data):
        if 'file_uploaded' in request.FILES:
            file_uploaded = request.FILES.get(
                'file_uploaded')

            # Encrypt the file content and pass the encoded content to make it json serializable
            encrypted_content = aes.encrypt_file_content(
                file_uploaded.read())
            encoded_content = base64.b64encode(
                encrypted_content).decode('utf-8')

            # Update the mutable data with the encoded content
            mutable_data['file_content'] = encoded_content
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

        if request.user.is_authenticated:
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

            if item.vault.is_team_vault:
                raise PermissionDenied('Team vault items cannot be shared.')

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

            if vault.is_team_vault:
                raise PermissionDenied('Team vaults cannot be shared.')

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

    def list(self, request, *args, **kwargs):
        status_param = request.query_params.get("status")
        team_id = request.query_params.get("team")
        vault_id = request.query_params.get("vault")

        # Validate required `team_id`
        if not team_id:
            return Response({"detail": "Team ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the user is an admin for the team
        team = get_object_or_404(Team, id=team_id)
        self._ensure_user_is_admin(team, request.user)

        # Base queryset
        queryset = TeamVaultActionRequest.objects.filter(team_vault__team=team)

        # Filter by `vault_id` if provided
        if vault_id:
            queryset = queryset.filter(team_vault__id=vault_id)

        # Filter by `status` if provided
        if status_param == "pending":
            queryset = queryset.filter(status=TeamVaultActionRequest.PENDING)
        elif status_param in ["approved", "rejected"]:
            queryset = queryset.filter(status=status_param)
        elif status_param:
            return Response({"detail": "Invalid status parameter."}, status=status.HTTP_400_BAD_REQUEST)

        serialized_data = self.get_serializer(queryset, many=True).data
        decrypted_data = self.decrypt_passwords(serialized_data)
        return Response(decrypted_data, status=status.HTTP_200_OK)
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        # Decrypt the login_password in item_data
        data = serializer.data
        try:
            if data['item_type'] == 'logininfo' and 'login_password' in data['item_data']:
                data['item_data']['login_password'] = aes.decrypt_login_password(data['item_data']['login_password'])
        except Exception as e:
            raise ValidationError({"error": f"Password decryption failed: {str(e)}"})

        return Response(data)
    
    def decrypt_passwords(self, serialized_data):
        """Decrypt passwords for a list of serialized data."""
        decrypted_data = []
        for item in serialized_data:
            try:
                decrypted_item = item.copy()
                if item['item_type'] == 'logininfo' and 'login_password' in item['item_data']:
                    decrypted_item['item_data']['login_password'] = aes.decrypt_login_password(
                        item['item_data']['login_password'])
                decrypted_data.append(decrypted_item)
            except Exception as e:
                raise ValidationError({"error": f"Password decryption failed: {str(e)}"})
        return decrypted_data

    def _ensure_user_is_admin(self, team, user):
        """Ensure the requesting user is an admin for the team."""
        if not TeamMembership.objects.filter(user=user, team=team, role=TeamMembership.ADMIN).exists():
            raise PermissionDenied("Only team admins can view action requests.")

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        action_request = self._get_and_validate_action_request(pk)
        self._ensure_user_is_admin(
            action_request.team_vault.team, request.user)

        if action_request.item_type == Item.LOGININFO:
            self._handle_login_info_action(action_request)
        elif action_request.item_type == Item.FILE:
            self._handle_file_action(action_request)

        self._update_request_status(
            action_request, TeamVaultActionRequest.APPROVED, request.user)
        return Response({"detail": "Request approved successfully."}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        action_request = self._get_and_validate_action_request(pk)
        self._ensure_user_is_admin(
            action_request.team_vault.team, request.user)

        self._update_request_status(
            action_request, TeamVaultActionRequest.REJECTED, request.user)
        return Response({"detail": "Request rejected successfully."}, status=status.HTTP_200_OK)

    def _get_and_validate_action_request(self, pk):
        action_request = get_object_or_404(TeamVaultActionRequest, id=pk)
        if action_request.status != TeamVaultActionRequest.PENDING:
            raise Response({'detail': 'Request has already been processed.'},
                           status=status.HTTP_400_BAD_REQUEST)
        return action_request

    def _ensure_user_is_admin(self, team, user):
        if not TeamMembership.objects.filter(user=user, team=team, role=TeamMembership.ADMIN).exists():
            raise PermissionDenied('Only team admins can approve/reject action requests.')

    def _handle_login_info_action(self, action_request):
        item_data = self._filter_item_data(action_request.item_data, LoginInfo)

        if action_request.action == TeamVaultActionRequest.CREATE:
            vault = self._get_vault(item_data.pop('vault'))
            LoginInfo.objects.create(vault=vault, **item_data)
        elif action_request.action == TeamVaultActionRequest.UPDATE:
            vault = self._get_vault(item_data.pop('vault')) if 'vault' in item_data else None
            target = get_object_or_404(LoginInfo, id=item_data.get('id'))
            self._update_model_instance(target, item_data)
        elif action_request.action == TeamVaultActionRequest.DELETE:
            LoginInfo.objects.filter(id=item_data.get('id')).delete()

    def _handle_file_action(self, action_request):
        item_data = self._filter_item_data(action_request.item_data, File)
        if "file_content" in item_data:
            item_data["file_content"] = base64.b64decode(
                item_data["file_content"])

        if action_request.action == TeamVaultActionRequest.CREATE:
            vault = self._get_vault(item_data.pop('vault'))
            File.objects.create(vault=vault, **item_data)
        elif action_request.action == TeamVaultActionRequest.UPDATE:
            vault = self._get_vault(item_data.pop('vault')) if 'vault' in item_data else None
            target = get_object_or_404(File, id=item_data.get('id'))
            self._update_model_instance(target, item_data)
        elif action_request.action == TeamVaultActionRequest.DELETE:
            File.objects.filter(id=item_data.get('id')).delete()

    def _filter_item_data(self, item_data, model):
        model_fields = {field.name for field in model._meta.get_fields()}
        return {key: value for key, value in item_data.items() if key in model_fields}

    def _get_vault(self, vault_id):
        return get_object_or_404(Vault, id=vault_id)

    def _update_model_instance(self, instance, data):
        for attr, value in data.items():
            setattr(instance, attr, value)
        instance.save()

    def _update_request_status(self, action_request, status, user):
        action_request.status = status
        action_request.authorized_by = user
        if status == TeamVaultActionRequest.APPROVED:
            action_request.authorized_at = timezone.now()
        action_request.save()


class VaultItemsView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, vault_id):
        try:
            # Retrieve the vault
            vault = Vault.objects.get(id=vault_id)

            # Check if the user has access to the vault
            if not self.has_access_to_vault(request.user, vault):
                raise PermissionDenied('You do not have access to this vault.')

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


class MyVaultItemsView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Get filter parameter
        item_type = request.query_params.get('type')
        
        # Base querysets for both types
        login_items = LoginInfo.objects.filter(vault__owner=request.user, vault__is_team_vault=False)
        
        file_items = File.objects.filter(vault__owner=request.user, vault__is_team_vault=False)

        # Apply type filter if specified
        if item_type:
            if item_type.lower() == 'login':
                file_items = File.objects.none()
            elif item_type.lower() == 'file':
                login_items = LoginInfo.objects.none()

        # Serialize the items
        login_serializer = LoginInfoSerializer(login_items, many=True)
        file_serializer = FileSerializer(file_items, many=True)

        # For login items, decrypt passwords
        decrypted_logins = []
        for item in login_serializer.data:
            try:
                item_copy = item.copy()
                item_copy['decrypted_password'] = aes.decrypt_login_password(
                    item['login_password'])
                decrypted_logins.append(item_copy)
            except Exception as e:
                raise ValidationError(
                    {"error": f"Password decryption failed: {str(e)}"})

        response_data = {
            'login_items': decrypted_logins,
            'file_items': file_serializer.data,
            'total_items': len(decrypted_logins) + len(file_serializer.data)
        }

        return Response(response_data, status=status.HTTP_200_OK)
