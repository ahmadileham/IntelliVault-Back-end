from collaboration.models import TeamMembership
from .models import TeamVaultActionRequest, Item
from .utils import create_team_vault_action_request
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework import status
from rest_framework.response import Response


class TeamRequestMixin:
    def handle_team_request(self, request, action, vault, instance=None, process_data=None):
        """
        Handles team requests for creating, updating, or deleting an item in a team vault.
        Allows specific views to customize how data is processed.
        """
        try:
            # Check if the user is part of the team
            team_membership = TeamMembership.objects.filter(
                user=request.user, team=vault.team).first()
            if not team_membership:
                raise PermissionDenied("You are not a member of this team.")

            mutable_data = request.data.copy()

            # Determine the item type based on the instance or mutable data
            item_type = self.get_item_type(action, instance, mutable_data)

            # Allow the view to process data (e.g., encrypt file/password)
            if action in [TeamVaultActionRequest.CREATE, TeamVaultActionRequest.UPDATE] and process_data and callable(process_data):
                mutable_data = process_data(request, mutable_data)

            # Include instance ID for updates and deletes
            if action in [TeamVaultActionRequest.UPDATE, TeamVaultActionRequest.DELETE] and instance:
                mutable_data['id'] = instance.id

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
