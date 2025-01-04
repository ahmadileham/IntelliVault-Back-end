# tests.py

from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.urls import reverse
from collaboration.models import Team, TeamMembership
from vault.models import Vault, LoginInfo, File, TeamVaultActionRequest, Item, SharedItem, SharedVault
from django.test import TestCase
from .utils import AESEncryption
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.timezone import now, timedelta
from django.contrib.contenttypes.models import ContentType
from io import BytesIO
from django.contrib.auth.hashers import make_password
from .serializers import LoginInfoSerializer, FileSerializer
from django.utils import timezone



User = get_user_model()
aes = AESEncryption()


class VaultTests(APITestCase):

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

    def test_retrieve_logininfo_list(self):
        url = reverse('login-info-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_other_user_logininfo(self):
        login_info = LoginInfo.objects.create(
            vault=self.personal_vault_user2,
            login_username="test_user",
            login_password="test_password"
        )
        url = reverse('login-info-detail', args=[login_info.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

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


class FileTests(TestCase):
    def setUp(self):
        # Create users
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
        self.client.login(username='user1', password='password1')

    def create_in_memory_file(self, name, content, mime_type="text/plain"):
        """
        Helper method to create an in-memory file with the specified content.
        """
        return SimpleUploadedFile(name, content.encode(), content_type=mime_type)

    def test_retrieve_file_list(self):
        url = reverse('file-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_file_detail(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.personal_vault_user1,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_other_user_file(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.personal_vault_user2,
            file_name="unauthorizedfile.txt",
            file_content=aes.encrypt_file_content(b"Unauthorized content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_other_user_file_list(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.personal_vault_user2,
            file_name="unauthorizedfile.txt",
            file_content=aes.encrypt_file_content(b"Unauthorized content"),
            mime_type="text/plain"
        )

        url = reverse('file-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_create_file_personal_vault(self):
        url = reverse('file-list')

        # Use helper to create in-memory file
        in_memory_file = self.create_in_memory_file(
            "testfile.txt", "This is a test file content.")

        data = {
            "vault": self.personal_vault_user1.id,
            "file_uploaded": in_memory_file,
            "file_name": "testfile.txt"
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(File.objects.count(), 1)
        self.assertEqual(File.objects.first().vault, self.personal_vault_user1)

    def test_update_file_personal_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.personal_vault_user1,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to create updated file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file, "file_name": "updatedfile.txt"}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        file_instance.refresh_from_db()
        decrypted_content = aes.decrypt_file_content(
            file_instance.file_content)
        self.assertEqual(decrypted_content, b"Updated content.")
        self.assertEqual(file_instance.file_name, "updatedfile.txt")

    def test_delete_file_personal_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.personal_vault_user1,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(File.objects.count(), 0)

    def test_unauthorized_access(self):
        # Create a file in user1's vault
        file_instance = File.objects.create(
            vault=self.personal_vault_user1,
            file_name="unauthorizedfile.txt",
            file_content=aes.encrypt_file_content(b"Unauthorized content"),
            mime_type="text/plain"
        )

        # Authenticate as user2 (no access)
        self.client.login(username='user2', password='password2')
        url = reverse('file-detail', args=[file_instance.id])

        # Attempt to access the file
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Attempt to update the file
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")
        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Attempt to delete the file
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_create_file_team_vault(self):
        url = reverse('file-list')

        # Use helper to create team file
        in_memory_file = self.create_in_memory_file(
            "teamfile.txt", "This is a team vault file content.")

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": in_memory_file,
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.CREATE)

    def test_non_member_create_file_team_vault(self):
        self.client.login(username='user3', password='password3')
        url = reverse('file-list')

        # Use helper to create unauthorized file
        in_memory_file = self.create_in_memory_file(
            "unauthorizedfile.txt", "This is unauthorized content.")

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": in_memory_file,
        }
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_update_file_team_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to create updated file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.UPDATE)

    def test_non_member_update_file_team_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to create updated file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        self.client.login(username='user3', password='password3')
        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_delete_file_team_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

    def test_non_member_delete_file_team_vault(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        self.client.login(username='user3', password='password3')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 0)

    def test_admin_approve_team_vault_action_request_create(self):
        # Create a login info into the vault
        file_url = reverse('file-list')

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": self.create_in_memory_file(
                "teamfile.txt", "This is a team vault file content."),
            "file_name": "teamfile.txt"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(file_url, data)
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
        self.assertEqual(File.objects.count(), 1)
        file = File.objects.first()
        self.assertEqual(file.file_name, "teamfile.txt")

    def test_non_admin_approve_team_vault_action_request_create(self):
        # Create a login info into the vault
        file_url = reverse('file-list')

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": self.create_in_memory_file(
                "teamfile.txt", "This is a team vault file content."),
            "file_name": "teamfile.txt"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(file_url, data)
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
        self.assertEqual(File.objects.count(), 0)

    def test_admin_approve_team_vault_action_request_update(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to update file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.UPDATE)

        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.APPROVED)

        # Check if the file instance is updated
        file_instance.refresh_from_db()
        self.assertEqual(file_instance.file_name, "updatedfile.txt")

    def test_non_admin_approve_team_vault_action_request_update(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to update file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.UPDATE)

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        # Non-admin tries to approve the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the file instance is not updated
        file_instance.refresh_from_db()
        self.assertEqual(file_instance.file_name, "testfile.txt")

    def test_admin_approve_team_vault_action_request_delete(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.APPROVED)

        # Check if the file instance is deleted
        self.assertEqual(File.objects.count(), 0)

    def test_non_admin_approve_team_vault_action_request_delete(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-approve',
                      args=[action_request.id])
        # Non-admin tries to approve the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the file instance is not deleted
        self.assertEqual(File.objects.count(), 1)

    def test_admin_reject_team_vault_action_request_create(self):
        # Create a FILE into the vault
        file_url = reverse('file-list')

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": self.create_in_memory_file(
                "teamfile.txt", "This is a team vault file content."),
            "file_name": "teamfile.txt"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(file_url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()

        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        response = self.client.post(url)  # Admin approves the request
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.REJECTED)

        # Check if the file instance is created
        self.assertEqual(File.objects.count(), 0)

    def test_non_admin_reject_team_vault_action_request_create(self):
        # Create a FILE into the vault
        file_url = reverse('file-list')

        data = {
            "vault": self.team_vault.id,
            "file_uploaded": self.create_in_memory_file(
                "teamfile.txt", "This is a team vault file content."),
            "file_name": "teamfile.txt"
        }

        client2 = APIClient()
        client2.force_authenticate(user=self.user2)

        response = client2.post(file_url, data)
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

        # Check if the file instance is not created
        self.assertEqual(File.objects.count(), 0)

    def test_admin_reject_team_vault_action_request_update(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to create updated file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
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

        # Check if the file instance is not updated
        file_instance.refresh_from_db()
        self.assertEqual(file_instance.file_name, "testfile.txt")

    def test_non_admin_reject_team_vault_action_request_update(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Old content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])

        # Use helper to create updated file content
        updated_file = self.create_in_memory_file(
            "updatedfile.txt", "Updated content.")

        data = {"file_uploaded": updated_file}
        response = self.client.patch(url, data, format='multipart')
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

        # Check if the file instance is not updated
        file_instance.refresh_from_db()
        self.assertEqual(file_instance.file_name, "testfile.txt")

    def test_admin_reject_team_vault_action_request_delete(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status,
                         TeamVaultActionRequest.REJECTED)

        # Check if the file instance is not deleted
        self.assertEqual(File.objects.count(), 1)

    def test_non_admin_reject_team_vault_action_request_delete(self):
        # Create a file instance
        file_instance = File.objects.create(
            vault=self.team_vault,
            file_name="testfile.txt",
            file_content=aes.encrypt_file_content(b"Test content"),
            mime_type="text/plain"
        )

        url = reverse('file-detail', args=[file_instance.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(TeamVaultActionRequest.objects.count(), 1)
        action_request = TeamVaultActionRequest.objects.first()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)
        self.assertEqual(action_request.action, TeamVaultActionRequest.DELETE)

        self.client.force_authenticate(user=self.user2)
        url = reverse('team-vault-action-request-reject',
                      args=[action_request.id])
        # Non-admin tries to reject the request
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        action_request.refresh_from_db()
        self.assertEqual(action_request.status, TeamVaultActionRequest.PENDING)

        # Check if the file instance is not deleted
        self.assertEqual(File.objects.count(), 1)


class FileDownloadTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser", password="testpass", email="user@example.com")
        self.vault = Vault.objects.create(name="Test Vault", owner=self.user)

        # Use SimpleUploadedFile to create the file
        self.uploaded_file = SimpleUploadedFile(
            "test.txt", b"Sample file content", content_type="text/plain"
        )
        self.file = File.objects.create(
            file_name=self.uploaded_file.name,
            file_content=aes.encrypt_file_content(self.uploaded_file.read()),
            mime_type=self.uploaded_file.content_type,
            vault=self.vault,
        )

        self.share_link = "validsharelink"
        self.shared_item = SharedItem.objects.create(
            share_link=self.share_link,
            access_password=make_password("hashedpassword"),
            shared_by=self.user,
            expiry_date=now() + timedelta(days=1),
            content_type=ContentType.objects.get_for_model(File),
            object_id=self.file.id,
        )

    def test_authenticated_file_download(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(
            reverse("file-download", args=[self.file.id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_file_download_with_valid_share_link(self):
        response = self.client.get(
            reverse("file-download-shared", args=[self.file.id, self.share_link]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_file_download_with_invalid_share_link(self):
        response = self.client.get(
            reverse("file-download-shared", args=[self.file.id, "invalidlink"]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthorized_file_download(self):
        response = self.client.get(
            reverse("file-download", args=[self.file.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class SharingTests(TestCase):
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword', email="p@e.com")
        self.client = APIClient()
        self.client.login(username='testuser', password='testpassword')

        # Create a test vault
        self.vault = Vault.objects.create(owner=self.user, name="Test Vault")

        # Create a test LoginInfo
        self.login_info = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_username",
            login_password=aes.encrypt_login_password("test_password")
        )

        # Create a test file
        file_content = BytesIO(b"Test file content")
        encrypted_content = aes.encrypt_file_content(file_content.read())
        self.file = File.objects.create(
            vault=self.vault,
            file_name="test_file.txt",
            file_content=encrypted_content,
            mime_type="text/plain"
        )

        self.expired_shared_item = SharedItem.objects.create(
            item=self.login_info,
            shared_by=self.user,
            share_link="expiredlink123",
            access_password=aes.encrypt_login_password("expired_password"),
            expiry_date=timezone.now() - timedelta(days=1)  # Expired yesterday
        )

    def test_create_shared_item(self):
        """Test creating a shared item (LoginInfo and File) with a password."""
        for item_type, item_id in [('logininfo', self.login_info.id), ('file', self.file.id)]:
            response = self.client.post(
                reverse('share-item', args=[item_type, item_id]),
                data={'password': 'test_share_password'},
                format='json'
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIn('share_link', response.data)
            self.assertIn('item_type', response.data)
            self.assertEqual(response.data['item_type'], item_type)

    def test_access_shared_item(self):
        """Test accessing a shared item using the correct password."""
        shared_item = SharedItem.objects.create(
            item=self.login_info,
            shared_by=self.user,
            share_link="testshare123",
            access_password=make_password("correct_password"),
            expiry_date="2099-01-01"
        )
        response = self.client.post(
            reverse('access-shared-item', args=[shared_item.share_link]),
            data={'password': 'correct_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('item', response.data)

    def test_access_shared_item_wrong_password(self):
        """Test accessing a shared item using the wrong password."""
        shared_item = SharedItem.objects.create(
            item=self.login_info,
            shared_by=self.user,
            share_link="testshare123",
            access_password=make_password("correct_password"),
            expiry_date="2099-01-01"
        )
        response = self.client.post(
            reverse('access-shared-item', args=[shared_item.share_link]),
            data={'password': 'wrong_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)

    def test_create_shared_vault(self):
        """Test creating a shared vault."""
        response = self.client.post(
            reverse('share-vault', args=[self.vault.id]),
            data={'password': 'test_vault_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('share_link', response.data)

    def test_access_shared_vault(self):
        """Test accessing a shared vault."""
        shared_vault = SharedVault.objects.create(
            vault=self.vault,
            shared_by=self.user,
            share_link="vaultshare123",
            access_password=make_password("correct_vault_password"),
            expiry_date="2099-01-01"
        )
        response = self.client.post(
            reverse('access-shared-vault', args=[shared_vault.share_link]),
            data={'password': 'correct_vault_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('login_items', response.data)
        self.assertIn('file_items', response.data)

    def test_access_shared_vault_wrong_password(self):
        """Test accessing a shared vault with the wrong password."""
        shared_vault = SharedVault.objects.create(
            vault=self.vault,
            shared_by=self.user,
            share_link="vaultshare123",
            access_password=make_password("correct_vault_password"),
            expiry_date="2099-01-01"
        )
        response = self.client.post(
            reverse('access-shared-vault', args=[shared_vault.share_link]),
            data={'password': 'wrong_vault_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
    
    def test_expired_shared_item_access(self):
        """Test accessing an expired shared item."""
        response = self.client.post(
            reverse('access-shared-item', args=[self.expired_shared_item.share_link]),
            data={'password': 'expired_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Link has expired')

    def test_invalid_item_id(self):
        """Test sharing with a non-existent item ID."""
        response = self.client.post(
            reverse('share-item', args=['logininfo', 9999]),  # Non-existent ID
            data={'password': 'test_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Item not found')

    def test_invalid_shared_item_access(self):
        """Test accessing a shared item with a non-existent share link."""
        response = self.client.post(
            reverse('access-shared-item', args=['nonexistentlink123']),
            data={'password': 'some_password'},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Shared item not found')
    

class VaultItemsTests(TestCase):
    def setUp(self):
        # Create test users
        self.user = User.objects.create_user(username='testuser', password='testpassword', email="e@e.com")
        self.other_user = User.objects.create_user(username='otheruser', password='otherpassword', email="f@f.com")

        # Create test client and authenticate
        self.client = APIClient()
        self.client.login(username='testuser', password='testpassword')
        self.other_client = APIClient()
        self.other_client.login(username='otheruser', password='otherpassword')

        # Create a test vault
        self.vault = Vault.objects.create(owner=self.user, name="Test Vault")

        # Create another user's vault
        self.other_vault = Vault.objects.create(owner=self.other_user, name="Other Vault")

        # Create a test team and add users
        self.team = Team.objects.create(name="Test Team", creator=self.user)
        TeamMembership.objects.create(user=self.user, team=self.team, role=TeamMembership.ADMIN)
        self.team_vault = Vault.objects.create(owner=self.user, name="Team Vault", team=self.team)

        # Add items to the test vault
        self.login_info = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_user",
            login_password=aes.encrypt_login_password("test_password")
        )
        file_content = BytesIO(b"Test file content")
        encrypted_content = aes.encrypt_file_content(file_content.read())
        self.file = File.objects.create(
            vault=self.vault,
            file_name="test_file.txt",
            file_content=encrypted_content,
            mime_type="text/plain"
        )

    def test_get_vault_items_success(self):
        """Test retrieving items from a vault the user owns."""
        response = self.client.get(reverse('vault-items', args=[self.vault.id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify the data in the response
        login_data = LoginInfoSerializer(self.login_info).data
        file_data = FileSerializer(self.file).data
        self.assertIn('login_items', response.data)
        self.assertIn('file_items', response.data)
        self.assertIn(login_data, response.data['login_items'])
        self.assertIn(file_data, response.data['file_items'])

    def test_get_vault_items_no_permission(self):
        """Test retrieving items from a vault the user does not own and is not part of the team."""
        response = self.client.get(reverse('vault-items', args=[self.other_vault.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        response = self.other_client.get(reverse('vault-items', args=[self.team_vault.id]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_vault_items_team_access(self):
        """Test retrieving items from a team vault where the user has access."""
        response = self.client.get(reverse('vault-items', args=[self.team_vault.id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('login_items', response.data)
        self.assertIn('file_items', response.data)

    def test_get_vault_items_vault_not_found(self):
        """Test retrieving items from a non-existent vault."""
        response = self.client.get(reverse('vault-items', args=[9999]))  # Non-existent vault ID
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)

    def test_get_vault_items_empty_vault(self):
        """Test retrieving items from an empty vault."""
        empty_vault = Vault.objects.create(owner=self.user, name="Empty Vault")
        response = self.client.get(reverse('vault-items', args=[empty_vault.id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['login_items'], [])
        self.assertEqual(response.data['file_items'], [])