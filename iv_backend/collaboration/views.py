from rest_framework import viewsets, permissions
from .models import Team, TeamMembership
from .serializers import TeamSerializer, TeamMembershipSerializer

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