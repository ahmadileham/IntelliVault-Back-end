from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from .models import GeneratedPassword
from vault.models import Vault, LoginInfo
from vault.utils import AESEncryption

User = get_user_model()
aes = AESEncryption()


class GeneratedPasswordTests(APITestCase):

    def setUp(self):
        # Create a user for authentication
        self.user = User.objects.create_user(
            username='testuser', password='testpass', email='testuser@example.com')
        self.client.login(username='testuser', password='testpass')

    def test_create_generated_password(self):
        # Test creating a generated password with valid data
        url = reverse('generated-password-list')
        data = {
            'length': 16,
            'use_uppercase': True,
            'use_numbers': True,
            'use_special_chars': True
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue('password' in response.data)
        self.assertTrue('strength' in response.data)
        self.assertEqual(response.data['generated_by'], self.user.id)

        # Verify the password is saved in the database
        password_instance = GeneratedPassword.objects.last()
        self.assertEqual(password_instance.generated_by, self.user)
        self.assertEqual(password_instance.password, response.data['password'])
        self.assertEqual(password_instance.strength, len(
            response.data['password']) >= 12 and data['use_uppercase'] and data['use_numbers'] and data['use_special_chars'])

    def test_list_generated_passwords(self):
        # Test listing generated passwords for the authenticated user
        GeneratedPassword.objects.create(
            generated_by=self.user,
            password='TestPassword123!',
            strength=True
        )
        GeneratedPassword.objects.create(
            generated_by=self.user,
            password='AnotherPass456@',
            strength=True
        )

        url = reverse('generated-password-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Should return 2 passwords

    def test_list_generated_passwords_no_auth(self):
        # Test listing generated passwords without authentication
        self.client.logout()
        url = reverse('generated-password-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PasswordAnalysisTests(APITestCase):

    def setUp(self):
        # Create a user for authentication
        self.user = User.objects.create_user(
            username='testuser', password='testpass', email='testuser@example.com'
        )
        self.client.login(username='testuser', password='testpass')

        # Create a vault for the user
        self.vault = Vault.objects.create(owner=self.user, name="Test Vault")

        # Create a login info entry in the vault
        self.login_info = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_user",
            login_password=aes.encrypt_login_password("test_password")  # This should be encrypted in a real scenario
        )
        # Create additional login info entries in the vault
        self.login_info_2 = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_user_2",
            login_password=aes.encrypt_login_password("test_password")
        )
        self.login_info_3 = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_user_3",
            login_password=aes.encrypt_login_password("test_password_3")
        )
        self.login_info_4 = LoginInfo.objects.create(
            vault=self.vault,
            login_username="test_user_4",
            login_password=aes.encrypt_login_password("test_password_4")
        )

    def test_analyze_passwords(self):
        url = reverse('password-analysis-analyze-passwords')  # Adjust the URL name as necessary
        
        response = self.client.post(url, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('id', response.data)  # Check if analysis ID is returned
        print(response.data)

    def test_latest_analysis(self):
        # First, perform an analysis to create an analysis record
        self.test_analyze_passwords()

        url = reverse('password-analysis-latest-analysis')  # Adjust the URL name as necessary
        
        response = self.client.get(url,format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('id', response.data)  # Check if analysis ID is returned