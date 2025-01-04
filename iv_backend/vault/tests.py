# tests.py

from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.urls import reverse
from collaboration.models import Team, TeamMembership
from vault.models import Vault, Item, LoginInfo, File, TeamVaultActionRequest
from django.test import TestCase

User = get_user_model()


class VaultViewSetTestCase(APITestCase):

    def setUp(self):
        # Create users
        self.user1 = User.objects.create_user(
            username="user1", email="user1@example.com", password="password123")
        self.user2 = User.objects.create_user(
            username="user2", email="user2@example.com", password="password123")

        # Create teams
        self.team1 = Team.objects.create(name="Team 1", creator=self.user1)
        self.team2 = Team.objects.create(name="Team 2", creator=self.user2)

        # Create team memberships
        TeamMembership.objects.create(
            user=self.user1, team=self.team1, role=TeamMembership.ADMIN)
        TeamMembership.objects.create(
            user=self.user2, team=self.team1, role=TeamMembership.MEMBER)
        TeamMembership.objects.create(
            user=self.user2, team=self.team2, role=TeamMembership.ADMIN)

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
        data = {"name": "Team Vault",
                "team": self.team1.id, "owner": self.user1.id}
        response = self.client.post(self.vault_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Vault.objects.count(), 1)
        self.assertEqual(Vault.objects.first().team, self.team1)

    def test_create_team_vault_as_non_admin(self):
        self.client.force_authenticate(user=self.user2)

        data = {"name": "Unauthorized Team Vault",
                "team": self.team1.id, "owner": self.user2.id}
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
        self.client.force_authenticate(
            user=self.user2)  # User 2 is not the owner
        vault = Vault.objects.create(name="Old Vault", owner=self.user1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Unauthorized Update"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_team_vault_as_admin(self):
        # User 1 is an admin of the team
        self.client.force_authenticate(user=self.user1)
        vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)
        update_url = reverse("vault-detail", args=[vault.id])
        data = {"name": "Updated Team Vault"}
        response = self.client.patch(update_url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        vault.refresh_from_db()
        self.assertEqual(vault.name, "Updated Team Vault")

    def test_update_team_vault_as_non_admin(self):
        # User 2 is not an admin of the team
        self.client.force_authenticate(user=self.user2)
        vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)
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
        self.client.force_authenticate(
            user=self.user2)  # User 2 is not the owner
        vault = Vault.objects.create(name="Vault to Delete", owner=self.user1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(Vault.objects.count(), 1)

    def test_delete_team_vault_as_admin(self):
        # User 1 is an admin of the team
        self.client.force_authenticate(user=self.user1)
        vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Vault.objects.count(), 0)

    def test_delete_team_vault_as_non_admin(self):
        self.client.force_authenticate(user=self.user2)
        vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)
        delete_url = reverse("vault-detail", args=[vault.id])
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Vault.objects.count(), 1)

    def test_get_vault_queryset(self):
        self.client.force_authenticate(user=self.user1)
        Vault.objects.create(name="User 1 Vault", owner=self.user1)
        Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)
        Vault.objects.create(name="User 2 Vault", owner=self.user2)

        response = self.client.get(self.vault_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # User 1's vault and Team Vault
        self.assertEqual(len(response.data), 2)
        # User 2 vault is not inside the queryset (no assertIn)
        self.assertNotIn("User 2 Vault", [vault["name"]
                         for vault in response.data])

    def test_retrieve_team_vault_as_non_member(self):
        # Create a team vault owned by user1
        team_vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)

        # Authenticate as a non-member user (user2 is a member, so we create user3)
        user3 = User.objects.create_user(
            username="user3", email="user3@example.com", password="password123")
        self.client.force_authenticate(user=user3)

        # Attempt to retrieve the team vault
        retrieve_url = reverse("vault-detail", args=[team_vault.id])
        response = self.client.get(retrieve_url)

        # Assert that the response is a 404 NOT FOUND
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_team_vault_as_member(self):
        # Create a team vault owned by user1
        team_vault = Vault.objects.create(
            name="Team Vault", owner=self.user1, team=self.team1)

        # Authenticate as a team member (user2)
        self.client.force_authenticate(user=self.user2)

        # Retrieve the team vault
        retrieve_url = reverse("vault-detail", args=[team_vault.id])
        response = self.client.get(retrieve_url)

        # Assert that the response is a 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class LoginInfoTests(TestCase):
    def setUp(self):
        # Create users with emails
        self.user1 = User.objects.create_user(
            username='user1', password='password1', email='user1@example.com')
        self.user2 = User.objects.create_user(
            username='user2', password='password2', email='user2@example.com')
        self.user3 = User.objects.create_user(
            username='user3', password='password3', email='user3@example.com')  # No access user

        # Create personal vaults
        self.personal_vault_user1 = Vault.objects.create(
            owner=self.user1, name="User1 Personal Vault")
        self.personal_vault_user2 = Vault.objects.create(
            owner=self.user2, name="User2 Personal Vault")

        # Create a team and team vault
        self.team = Team.objects.create(name="Team1", creator=self.user1)
        self.team_vault = Vault.objects.create(
            owner=self.user1, team=self.team, name="Team Vault")

        # Add memberships
        TeamMembership.objects.create(
            user=self.user1, team=self.team, role=TeamMembership.ADMIN)
        TeamMembership.objects.create(
            user=self.user2, team=self.team, role=TeamMembership.MEMBER)

        # Set up API client
        self.client = APIClient()
        # Default login as user1
        self.client.login(username='user1', password='password1')

    def test_create_logininfo_personal_vault(self):
        url = reverse('login-info-list')
        data = {
            "vault": self.personal_vault_user1.id,
            "login_username": "test_user",
            "login_password": "test_password"
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(LoginInfo.objects.count(), 1)
        self.assertEqual(LoginInfo.objects.first().vault,
                         self.personal_vault_user1)

    def test_update_logininfo_personal_vault(self):
        login_info = LoginInfo.objects.create(
            vault=self.personal_vault_user1,
            login_username="old_user",
            login_password="old_password"
        )
        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_user",
                "login_password": "updated_password"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        login_info.refresh_from_db()
        self.assertEqual(login_info.login_username, "updated_user")

    def test_delete_logininfo_personal_vault(self):
        login_info = LoginInfo.objects.create(
            vault=self.personal_vault_user1,
            login_username="test_user",
            login_password="test_password"
        )
        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(LoginInfo.objects.count(), 0)

    def test_unauthorized_access(self):
        # Create a LoginInfo in user1's vault
        login_info = LoginInfo.objects.create(
            vault=self.personal_vault_user1,
            login_username="unauthorized_user",
            login_password="unauthorized_password"
        )
        # Login as user2 (no access)
        self.client.login(username='user2', password='password2')
        url = reverse('login-info-detail', args=[login_info.id])

        # Attempt to access the LoginInfo
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Attempt to update the LoginInfo
        data = {"login_username": "new_user", "login_password": "new_password"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Attempt to delete the LoginInfo
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_create_logininfo_team_vault(self):
        url = reverse('login-info-list')
        data = {
            "vault": self.team_vault.id,
            "login_username": "team_user",
            "login_password": "team_password"
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.CREATE)

    def test_create_logininfo_team_vault_as_non_member(self):
        self.client.login(username='user3', password='password3')
        url = reverse('login-info-list')
        data = {
            "vault": self.team_vault.id,
            "login_username": "unauthorized_team_user",
            "login_password": "unauthorized_team_password"
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_update_logininfo_team_vault(self):
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )
        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_team_user",
                "login_password": "updated_team_password"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.UPDATE)

    def test_update_logininfo_team_vault_as_non_member(self):
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )
        self.client.login(username='user3', password='password3')
        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "unauthorized_team_user",
                "login_password": "unauthorized_team_password"}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_delete_logininfo_team_vault(self):
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="delete_team_user",
            login_password="delete_team_password"
        )
        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

    def test_delete_logininfo_team_vault_as_non_member(self):
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="delete_team_user",
            login_password="delete_team_password"
        )
        self.client.login(username='user3', password='password3')
        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_admin_approve_team_vault_action_request_create(self):
        # Create a login info into the vault
        login_info_url = reverse('login-info-list')

        data = {
            "vault": self.team_vault.id,
            "login_username": "team_user",
            "login_password": "team_password"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(login_info_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.APPROVED)

        # Check if the logininfo instance is created
        self.assertEqual(LoginInfo.objects.count(), 1)
        login_info = LoginInfo.objects.first()
        self.assertEqual(login_info.login_username, "team_user")

    def test_non_admin_approve_team_vault_action_request_create(self):
        # Create a login info into the vault
        login_info_url = reverse('login-info-list')

        data = {
            "vault": self.team_vault.id,
            "login_username": "team_user",
            "login_password": "team_password"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(login_info_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        # Non-admin tries to approve the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the logininfo instance is not created
        self.assertEqual(LoginInfo.objects.count(), 0)

    def test_admin_approve_team_vault_action_request_update(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_team_user",
                "login_password": "updated_team_password"}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.APPROVED)

        # Check if the logininfo instance is updated
        login_info.refresh_from_db()
        self.assertEqual(login_info.login_username, "updated_team_user")

    def test_non_admin_approve_team_vault_action_request_update(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_team_user",
                "login_password": "updated_team_password"}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        # Non-admin tries to approve the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the logininfo instance is not updated
        login_info.refresh_from_db()
        self.assertEqual(login_info.login_username, "old_team_user")

    def test_admin_approve_team_vault_action_request_delete(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="delete_team_user",
            login_password="delete_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.APPROVED)

        # Check if the logininfo instance is deleted
        self.assertEqual(LoginInfo.objects.count(), 0)

    def test_admin_reject_team_vault_action_request_create(self):
        # Create a login info into the vault
        login_info_url = reverse('login-info-list')

        data = {
            "vault": self.team_vault.id,
            "login_username": "team_user",
            "login_password": "team_password"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(login_info_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin rejects the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.REJECTED)

        # Check if the logininfo instance is not created
        self.assertEqual(LoginInfo.objects.count(), 0)

    def test_non_admin_reject_team_vault_action_request_create(self):
        # Create a login info into the vault
        login_info_url = reverse('login-info-list')

        data = {
            "vault": self.team_vault.id,
            "login_username": "team_user",
            "login_password": "team_password"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(login_info_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        # Non-admin tries to reject the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the logininfo instance is not created
        self.assertEqual(LoginInfo.objects.count(), 0)

    def test_admin_reject_team_vault_action_request_update(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_team_user",
                "login_password": "updated_team_password"}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin rejects the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.REJECTED)

        # Check if the logininfo instance is not updated
        login_info.refresh_from_db()
        self.assertEqual(login_info.login_username, "old_team_user")

    def test_non_admin_reject_team_vault_action_request_update(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="old_team_user",
            login_password="old_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        data = {"login_username": "updated_team_user",
                "login_password": "updated_team_password"}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        # Non-admin tries to reject the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the logininfo instance is not updated
        login_info.refresh_from_db()
        self.assertEqual(login_info.login_username, "old_team_user")

    def test_admin_reject_team_vault_action_request_delete(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="delete_team_user",
            login_password="delete_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin rejects the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.REJECTED)

        # Check if the logininfo instance is not deleted
        self.assertEqual(LoginInfo.objects.count(), 1)

    def test_non_admin_reject_team_vault_action_request_delete(self):
        # Create a login info into the vault
        login_info = LoginInfo.objects.create(
            vault=self.team_vault,
            login_username="delete_team_user",
            login_password="delete_team_password"
        )

        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        # Non-admin tries to reject the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the logininfo instance is not deleted
        self.assertEqual(LoginInfo.objects.count(), 1)
