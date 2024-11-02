from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from .models import Vault, LoginInfo, SharedItem, SharedVault
from .utils import AESEncryption
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.hashers import make_password

User = get_user_model()


class VaultAppAPITestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpass', email='testemail@example.com')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.aes = AESEncryption()

        # Create a Vault instance
        self.vault = Vault.objects.create(name="Test Vault", owner=self.user)

        # URL names for reverse lookups
        self.vault_list_url = 'vault-list'
        self.login_info_list_url = 'login-info-list'
        self.share_item_url = 'share-item'
        self.share_vault_url = 'share-vault'
        self.access_shared_item_url = 'access-shared-item'
        self.access_shared_vault_url = 'access-shared-vault'

    def test_create_vault(self):
        data = {'name': 'New Vault', 'owner': self.user.id}
        response = self.client.post(reverse(self.vault_list_url), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Vault')

    def test_list_vaults(self):
        response = self.client.get(reverse(self.vault_list_url))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Only one vault created in setUp
        self.assertEqual(len(response.data), 1)

    def test_create_login_info(self):
        data = {
            'vault': self.vault.id,
            'login_username': 'example_user',
            'login_password': self.aes.encrypt('example_pass')
        }
        response = self.client.post(reverse(self.login_info_list_url), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['login_username'], 'example_user')

    def test_list_login_info(self):
        LoginInfo.objects.create(
            vault=self.vault,
            login_username='example_user',
            login_password=self.aes.encrypt('example_pass')
        )
        response = self.client.get(reverse(self.login_info_list_url))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        # Check for decrypted field
        self.assertIn('decrypted_password', response.data[0])

    def test_share_item(self):
        # Create LoginInfo item to share
        login_info = LoginInfo.objects.create(
            vault=self.vault,
            login_username='share_user',
            login_password=self.aes.encrypt('share_pass')
        )
        data = {'password': 'access_password'}
        response = self.client.post(
            reverse(self.share_item_url, args=[login_info.id]), data
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('share_link', response.data)

    def test_share_vault(self):
        data = {'password': 'access_password'}
        response = self.client.post(
            reverse(self.share_vault_url, args=[self.vault.id]), data
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('share_link', response.data)

    def test_access_shared_item(self):
        # Create shared item for access testing
        login_info = LoginInfo.objects.create(
            vault=self.vault,
            login_username='access_user',
            login_password=self.aes.encrypt('access_pass')
        )
        shared_item = SharedItem.objects.create(
            item=login_info,
            shared_by=self.user,
            share_link='samplelink123',
            access_password=make_password('access_password'),
            expiry_date=timezone.now() + timedelta(minutes=10)
        )
        data = {'password': 'access_password'}
        response = self.client.post(
            reverse(self.access_shared_item_url, args=[
                    shared_item.share_link]), data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Access granted')
        self.assertIn('item', response.data)

    def test_access_shared_vault(self):
        # Create shared vault for access testing
        shared_vault = SharedVault.objects.create(
            vault=self.vault,
            shared_by=self.user,
            share_link='samplevaultlink123',
            access_password=make_password('access_password'),
            expiry_date=timezone.now() + timedelta(minutes=10)
        )
        data = {'password': 'access_password'}
        response = self.client.post(
            reverse(self.access_shared_vault_url, args=[
                    shared_vault.share_link]), data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Access granted')
        self.assertIn('login_items', response.data)
