from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from datetime import timedelta
from django.contrib.auth import get_user_model
from .models import Team, TeamMembership, Invitation

User = get_user_model()

class InvitationTests(APITestCase):
    def setUp(self):
        # Set up users with email
        self.admin_user = User.objects.create_user(username="admin", email="admin@example.com", password="adminpass")
        self.member_user = User.objects.create_user(username="member", email="member@example.com", password="memberpass")
        self.other_user = User.objects.create_user(username="other", email="other@example.com", password="otherpass")

        # Create a team and add the admin
        self.team = Team.objects.create(name="Test Team", creator=self.admin_user)
        TeamMembership.objects.create(user=self.admin_user, team=self.team, role=TeamMembership.ADMIN)

        # Auth clients for users
        self.admin_client = APIClient()
        self.admin_client.login(username="admin", password="adminpass")

        self.member_client = APIClient()
        self.member_client.login(username="member", password="memberpass")
        
    def test_admin_can_invite_member(self):
        url = reverse('create-invitation', kwargs={'team_id': self.team.id})
        data = {'recipient_id': self.member_user.id}

        # Admin creates invitation
        response = self.admin_client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        invitation = Invitation.objects.get(recipient=self.member_user)
        self.assertEqual(invitation.team, self.team)
        self.assertEqual(invitation.sender, self.admin_user)
        self.assertEqual(invitation.status, Invitation.PENDING)
        self.assertAlmostEqual(
            invitation.expiration_date, timezone.now() + timedelta(days=7), delta=timedelta(seconds=1)
        )

    def test_non_admin_cannot_invite(self):
        url = reverse('create-invitation', kwargs={'team_id': self.team.id})
        data = {'recipient_id': self.other_user.id}

        # Non-admin attempts to create invitation
        response = self.member_client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_accept_invitation(self):
        # Admin creates an invitation
        invitation = Invitation.objects.create(
            team=self.team,
            recipient=self.member_user,
            sender=self.admin_user,
            expiration_date=timezone.now() + timedelta(days=7)
        )

        url = reverse('respond-invitation', kwargs={'invitation_id': invitation.id})
        data = {'action': Invitation.ACCEPT}

        # Member accepts the invitation
        response = self.member_client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify member is added to the team
        membership = TeamMembership.objects.get(user=self.member_user, team=self.team)
        self.assertEqual(membership.role, TeamMembership.MEMBER)

    def test_reject_invitation(self):
        # Admin creates an invitation
        invitation = Invitation.objects.create(
            team=self.team,
            recipient=self.member_user,
            sender=self.admin_user,
            expiration_date=timezone.now() + timedelta(days=7)
        )

        url = reverse('respond-invitation', kwargs={'invitation_id': invitation.id})
        data = {'action': Invitation.REJECT}

        # Member rejects the invitation
        response = self.member_client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify the invitation status is updated
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, Invitation.REJECTED)

    def test_expired_invitation_cannot_be_accepted(self):
        # Create an expired invitation
        invitation = Invitation.objects.create(
            team=self.team,
            recipient=self.member_user,
            sender=self.admin_user,
            expiration_date=timezone.now() - timedelta(days=1)
        )

        url = reverse('respond-invitation', kwargs={'invitation_id': invitation.id})
        data = {'action': Invitation.ACCEPT}

        # Member attempts to accept expired invitation
        response = self.member_client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'This invitation has expired.')
