from rest_framework import serializers
from authentication.serializers import CustomUserSerializer
from .models import Team, TeamMembership, Invitation

class TeamSerializer(serializers.ModelSerializer):
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = Team
        fields = ['id', 'name', 'created_at', 'creator']

class TeamMembershipSerializer(serializers.ModelSerializer):
    username = serializers.ReadOnlyField(source='user.username')
    team_name = serializers.SerializerMethodField()

    def get_team_name(self, obj):
        return obj.team.name

    class Meta:
        model = TeamMembership
        fields = ['id', 'user', 'username','team', 'role', 'team_name']

class InvitationSerializer(serializers.ModelSerializer):
    team = TeamSerializer()  
    sender = CustomUserSerializer()
    class Meta:
        model = Invitation
        fields = ['id', 'team', 'recipient', 'sender', 'status', 'expiration_date']