from django.contrib.auth import get_user_model
from rest_framework import viewsets, permissions
from .models import Team, TeamMembership, Invitation
from .serializers import TeamSerializer, TeamMembershipSerializer, InvitationSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from vault.models import Vault
from vault.serializers import VaultSerializer

class TeamViewSet(viewsets.ModelViewSet):
    serializer_class = TeamSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return teams that the authenticated user is a creator of
        return Team.objects.filter(creator=self.request.user)

    def perform_create(self, serializer):
        # Set the creator as the authenticated user when creating a team
        team = serializer.save(creator=self.request.user)

        # Create a TeamMembership instance for the creator with the role of admin
        TeamMembership.objects.create(
            user=self.request.user, team=team, role='admin')
        
    @action(detail=False, methods=['get'])
    def my_teams(self, request):
        memberships = TeamMembership.objects.filter(user=request.user)
        teams = [membership.team for membership in memberships]
        serializer = self.get_serializer(teams, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def members(self, request, pk=None):
        # Check if the user is a member of the team
        team = get_object_or_404(Team, pk=pk)
        if not TeamMembership.objects.filter(user=request.user, team=team).exists():
            raise PermissionDenied("You are not a member of this team.")

        # Retrieve all members of the team
        memberships = TeamMembership.objects.filter(team=team)
        serializer = TeamMembershipSerializer(memberships, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    # get admins
    @action(detail=True, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def admins(self, request, pk=None):
        # Check if the user is a member of the team
        team = get_object_or_404(Team, pk=pk)
        if not TeamMembership.objects.filter(user=request.user, team=team).exists():
            raise PermissionDenied("You are not a member of this team.")

        # Retrieve all admins of the team
        memberships = TeamMembership.objects.filter(team=team, role='admin')
        serializer = TeamMembershipSerializer(memberships, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


    @action(detail=True, methods=['get'], url_path='vaults', permission_classes=[IsAuthenticated])
    def get_team_vaults(self, request, pk=None):
        # Ensure the team exists
        team = get_object_or_404(Team, pk=pk)

        # Check if the user is a member of the team
        if not TeamMembership.objects.filter(user=request.user, team=team).exists():
            raise PermissionDenied("You are not a member of this team.")

        # Retrieve all vaults associated with the team
        vaults = Vault.objects.filter(team=team)
        serializer = VaultSerializer(vaults, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TeamMembershipViewSet(viewsets.ModelViewSet):
    serializer_class = TeamMembershipSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return TeamMembership.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def perform_update(self, serializer):
        membership = self.get_object()
        self._ensure_admin_privileges(membership.team)
        serializer.save()

    def _ensure_admin_privileges(self, team):
        """Check if the authenticated user is an admin of the specified team."""
        if not TeamMembership.objects.filter(
            user=self.request.user, team=team, role=TeamMembership.ADMIN
        ).exists():
            raise PermissionDenied("Only team admins can perform this action.")

    def _ensure_not_self_action(self, membership):
        """Prevent admins from performing certain actions on themselves."""
        if membership.user == self.request.user:
            raise PermissionDenied("Admins cannot perform this action on themselves.")

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def leave_team(self, request, pk=None):
        membership = get_object_or_404(TeamMembership, id=pk, user=request.user)

        # Prevent the only admin from leaving the team
        if membership.role == TeamMembership.ADMIN:
            if TeamMembership.objects.filter(
                team=membership.team, role=TeamMembership.ADMIN
            ).count() <= 1:
                return Response(
                    {"detail": "You cannot leave the team as the only admin."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        membership.delete()
        return Response(
            {"detail": "You have successfully left the team."},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def kick_member(self, request, pk=None):
        membership = get_object_or_404(TeamMembership, id=pk)
        team = membership.team

        self._ensure_admin_privileges(team)
        self._ensure_not_self_action(membership)

        membership.delete()
        return Response(
            {"detail": f"{membership.user.username} has been removed from the team."},
            status=status.HTTP_200_OK,
        )


class CreateInvitationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, team_id):
        team = get_object_or_404(Team, id=team_id)

        # Check if the user is an admin of the team
        if not TeamMembership.objects.filter(user=request.user, team=team, role='admin').exists():
            return Response({'detail': 'Only team admins can invite members.'}, status=status.HTTP_403_FORBIDDEN)

        recipient_id = request.data.get('recipient_id')
        User = get_user_model()  # Get the user model
        recipient = get_object_or_404(
            User, id=recipient_id)  # Use the user model

        # Create the invitation with a 7-day expiration date
        invitation = Invitation.objects.create(
            team=team,
            recipient=recipient,
            sender=request.user,
        )

        return Response(InvitationSerializer(invitation).data, status=status.HTTP_201_CREATED)


class RespondInvitationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, invitation_id):
        invitation = get_object_or_404(
            Invitation, id=invitation_id, recipient=request.user)

        if invitation.is_expired():
            return Response({'detail': 'This invitation has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        action = request.data.get('action')
        if action == Invitation.ACCEPT:
            invitation.status = Invitation.ACCEPTED
            invitation.save()

            # Add the user to the team as a member
            TeamMembership.objects.create(
                user=request.user, team=invitation.team, role=TeamMembership.MEMBER)
            return Response({'detail': 'Invitation accepted.'}, status=status.HTTP_200_OK)

        elif action == Invitation.REJECT:
            invitation.status = Invitation.REJECTED
            invitation.save()
            return Response({'detail': 'Invitation rejected.'}, status=status.HTTP_200_OK)

        return Response({'detail': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)


class InvitationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        invitations = Invitation.objects.filter(
            recipient=request.user, status=Invitation.PENDING, expiration_date__gte=timezone.now())
        serializer = InvitationSerializer(invitations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)