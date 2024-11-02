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
        TeamMembership.objects.create(user=self.request.user, team=team, role='admin')


class TeamMembershipViewSet(viewsets.ModelViewSet):
    serializer_class = TeamMembershipSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Only return team memberships for the authenticated user
        return TeamMembership.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Set the user as the authenticated user when creating a team membership
        serializer.save(user=self.request.user)

class CreateInvitationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, team_id):
        team = get_object_or_404(Team, id=team_id)
        
        # Check if the user is an admin of the team
        if not TeamMembership.objects.filter(user=request.user, team=team, role='admin').exists():
            return Response({'detail': 'Only team admins can invite members.'}, status=status.HTTP_403_FORBIDDEN)

        recipient_id = request.data.get('recipient_id')
        User = get_user_model()  # Get the user model
        recipient = get_object_or_404(User, id=recipient_id)  # Use the user model

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
        invitation = get_object_or_404(Invitation, id=invitation_id, recipient=request.user)
        
        if invitation.is_expired():
            return Response({'detail': 'This invitation has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        action = request.data.get('action')
        if action == Invitation.ACCEPT:
            invitation.status = Invitation.ACCEPTED
            invitation.save()

            # Add the user to the team as a member
            TeamMembership.objects.create(user=request.user, team=invitation.team, role=TeamMembership.MEMBER)
            return Response({'detail': 'Invitation accepted.'}, status=status.HTTP_200_OK)
        
        elif action == Invitation.REJECT:
            invitation.status = Invitation.REJECTED
            invitation.save()
            return Response({'detail': 'Invitation rejected.'}, status=status.HTTP_200_OK)

        return Response({'detail': 'Invalid action.'}, status=status.HTTP_400_BAD_REQUEST)

class InvitationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        invitations = Invitation.objects.filter(recipient=request.user, status=Invitation.PENDING, expiration_date__gte=timezone.now())
        serializer = InvitationSerializer(invitations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)