from rest_framework import serializers

from authentication.serializers import CustomUserSerializer
from .models import Team, TeamMembership, Invitation

class TeamSerializer(serializers.ModelSerializer):
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = Team
        fields = ['id', 'name', 'created_at', 'creator']

class TeamMembershipSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')

    class Meta:
        model = TeamMembership
        fields = ['id', 'user', 'team', 'role']

class InvitationSerializer(serializers.ModelSerializer):
    team = TeamSerializer()  
    sender = CustomUserSerializer()

    class Meta:
        model = Invitation
        fields = ['id', 'team', 'recipient', 'sender', 'status', 'expiration_date']