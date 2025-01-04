from collaboration.models import TeamMembership
from .models import TeamVaultActionRequest, Item, Vault
from .utils import create_team_vault_action_request
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework import status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404


class TeamRequestMixin:

    def validate_vault_id(self, request, vault):
        """
        Validate that the vault ID in the request data matches the current vault's ID.
        Prevents changing the vault for items in a team vault.
        """
        if 'vault' in request.data:
            try:
                request_vault_id = int(request.data['vault'])
            except (ValueError, TypeError):
                return Response({"error": "Invalid vault ID format."}, status=status.HTTP_400_BAD_REQUEST)

            if request_vault_id != vault.id:
                return Response({"error": "Cannot change the vault for items in a team vault."}, status=status.HTTP_400_BAD_REQUEST)
        return None

    def handle_team_request(self, request, action, vault, instance=None, process_data=None):
        """
        Handles team requests for creating, updating, or deleting an item in a team vault.
        Allows specific views to customize how data is processed.
        """
        try:
            if not self.check_team_membership(request, vault):
                raise PermissionDenied("You are not a member of this team.")

            mutable_data = request.data.copy()

            # Process mutable data based on the action
            mutable_data = self.process_mutable_data(
                request, action, mutable_data, instance, process_data
            )

            # Determine the item type based on the instance or mutable data
            item_type = self.get_item_type(action, instance, mutable_data)

            # Create the action request
            action_request = create_team_vault_action_request(
                action,
                request.user,
                vault,
                item_type,
                target=instance if action in [
                    TeamVaultActionRequest.UPDATE, TeamVaultActionRequest.DELETE] else None,
                data=mutable_data if action != TeamVaultActionRequest.DELETE else None
            )
            return Response({"detail": "Action request created.", "request_id": action_request.id}, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({"error": e.detail}, status=status.HTTP_400_BAD_REQUEST)

    def get_item_type(self, action, instance, mutable_data=None):
        """Determine the item type based on the instance or mutable data."""
        if instance:
            if hasattr(instance, "login_username"):
                return Item.LOGININFO
            return Item.FILE
        elif mutable_data:
            if 'login_username' in mutable_data:
                return Item.LOGININFO
            return Item.FILE
        return Item.FILE  # Default item type if neither instance nor mutable_data is available

    def process_mutable_data(self, request, action, mutable_data, instance, process_data):
        """Process mutable data if a processing function is provided."""
        if action in [TeamVaultActionRequest.CREATE, TeamVaultActionRequest.UPDATE] and process_data and callable(process_data):
            mutable_data = process_data(request, mutable_data)
        if action in [TeamVaultActionRequest.UPDATE, TeamVaultActionRequest.DELETE] and instance:
            mutable_data['id'] = instance.id
        return mutable_data

    def check_team_membership(self, request, vault):
        """Check if the user is a member of the team associated with the vault."""
        return TeamMembership.objects.filter(user=request.user, team=vault.team).exists()

class VaultItemValidationMixin:
    """Mixin to handle vault validation logic for items."""

    def validate_vault_change(self, current_vault, new_vault_id):
        """Validate the vault change rules."""
        if not new_vault_id or str(current_vault.id) == str(new_vault_id):
            return  # No change in vault, so no validation needed

        new_vault = get_object_or_404(Vault, id=new_vault_id)

        # Rule 1: Cannot change the vault of items that belong to a team vault
        if current_vault.is_team_vault:
            raise ValidationError(
                {"error": "Cannot change the vault of items belonging to a team vault."}
            )

        # Rule 2: Cannot move personal vault items to a team vault
        if not current_vault.is_team_vault and new_vault.is_team_vault:
            raise ValidationError(
                {"error": "Cannot move personal vault items to a team vault."}
            )

        return new_vault