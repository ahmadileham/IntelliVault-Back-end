# tests.py

from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.urls import reverse
from collaboration.models import Team, TeamMembership
from vault.models import Vault

User = get_user_model()


class VaultViewSetTestCase(APITestCase):

    def setUp(self):
        # Create users
        self.user1 = User.objects.create_user(username="user1", email="user1@example.com", password="password123")
        self.user2 = User.objects.create_user(username="user2", email="user2@example.com", password="password123")
        
        # Create teams
        self.team1 = Team.objects.create(name="Team 1", creator=self.user1)
        self.team2 = Team.objects.create(name="Team 2", creator=self.user2)
        
        # Create team memberships
        TeamMembership.objects.create(user=self.user1, team=self.team1, role=TeamMembership.ADMIN)
        TeamMembership.objects.create(user=self.user2, team=self.team1, role=TeamMembership.MEMBER)
        TeamMembership.objects.create(user=self.user2, team=self.team2, role=TeamMembership.ADMIN)

        self.client = APIClient()

        # Vault API endpoint
        self.vault_url = reverse("vault-list")

    def test_create_personal_vault(self):
        self.client.force_authenticate(user=self.user1)
        data = {"name": "Personal Vault", "owner": self.user1.id}
        response = self.client.post(self.vault_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Vault.objects.count(), 1)
        self.assertEqual(Vault.objects.first().owner, self.user1)

    def test_create_team_vault_as_admin(self):
        self.client.force_authenticate(user=self.user1)
        data = {"name": "Team Vault", "team": self.team1.id, "owner": self.user1.id}
        response = self.client.post(self.vault_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Vault.objects.count(), 1)
        self.assertEqual(Vault.objects.first().team, self.team1)

    def test_create_team_vault_as_non_admin(self):
        self.client.force_authenticate(user=self.user2)
        
        data = {"name": "Unauthorized Team Vault", "team": self.team1.id, "owner": self.user2.id}
        response = self.client.post(self.vault_url, data)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Vault.objects.count(), 0)

    def test_update_vault_as_owner(self):
        self.client.force_authenticate(user=self.user1)
        vault = Vault.objects.create(name="Old Vault", owner=self.user1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Updated Vault"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        vault.refresh_from_db()
        self.assertEqual(vault.name, "Updated Vault")

    def test_update_vault_as_non_owner(self):
        self.client.force_authenticate(user=self.user2) # User 2 is not the owner
        vault = Vault.objects.create(name="Old Vault", owner=self.user1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Unauthorized Update"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_team_vault_as_admin(self):
        self.client.force_authenticate(user=self.user1) # User 1 is an admin of the team
        vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Updated Team Vault"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        vault.refresh_from_db()
        self.assertEqual(vault.name, "Updated Team Vault")

    def test_update_team_vault_as_non_admin(self):
        self.client.force_authenticate(user=self.user2) # User 2 is not an admin of the team
        vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Unauthorized Update"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_vault_as_owner(self):
        self.client.force_authenticate(user=self.user1)
        vault = Vault.objects.create(name="Vault to Delete", owner=self.user1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Vault.objects.count(), 0)
    
    def test_delete_vault_as_non_owner(self):
        self.client.force_authenticate(user=self.user2) # User 2 is not the owner
        vault = Vault.objects.create(name="Vault to Delete", owner=self.user1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(Vault.objects.count(), 1)
    
    def test_delete_team_vault_as_admin(self):
        self.client.force_authenticate(user=self.user1) # User 1 is an admin of the team
        vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Vault.objects.count(), 0)

    def test_delete_team_vault_as_non_admin(self):
        self.client.force_authenticate(user=self.user2)
        vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Vault.objects.count(), 1)

    def test_get_vault_queryset(self):
        self.client.force_authenticate(user=self.user1)
        Vault.objects.create(name="User 1 Vault", owner=self.user1)
        Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        Vault.objects.create(name="User 2 Vault", owner=self.user2)

        response = self.client.get(self.vault_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # User 1's vault and Team Vault
        # User 2 vault is not inside the queryset (no assertIn)
        self.assertNotIn("User 2 Vault", [vault["name"] for vault in response.data])

    def test_retrieve_team_vault_as_non_member(self):
        # Create a team vault owned by user1
        team_vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        
        # Authenticate as a non-member user (user2 is a member, so we create user3)
        user3 = User.objects.create_user(username="user3", email="user3@example.com", password="password123")
        self.client.force_authenticate(user=user3)

        # Attempt to retrieve the team vault
        retrieve_url = reverse("vault-detail", args=[team_vault.id])
        response = self.client.get(retrieve_url)

        # Assert that the response is a 404 NOT FOUND
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_team_vault_as_member(self):
        # Create a team vault owned by user1
        team_vault = Vault.objects.create(name="Team Vault", owner=self.user1, team=self.team1)
        
        # Authenticate as a team member (user2)
        self.client.force_authenticate(user=self.user2)

        # Retrieve the team vault
        retrieve_url = reverse("vault-detail", args=[team_vault.id])
        response = self.client.get(retrieve_url)

        # Assert that the response is a 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

