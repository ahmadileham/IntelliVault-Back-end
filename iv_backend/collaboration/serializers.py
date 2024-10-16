from rest_framework import serializers
from .models import Team, TeamMembership

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
