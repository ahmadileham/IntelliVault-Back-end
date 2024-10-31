from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64
from django.contrib.auth.hashers import make_password
from datetime import timedelta
from .models import SharedItem, SharedVault, LoginInfo, File
from django.utils import timezone
from django.utils.crypto import get_random_string
import hvac
import environ

# Initialize environ and load conf.env file
env = environ.Env()
environ.Env.read_env("conf.env")

class AESEncryption:
    def __init__(self):
        # Initialize the Vault client with the address from environment variables
        self.client = hvac.Client(url=env('VAULT_ADDR'))

        # Retrieve Role ID and Secret ID from environment variables
        self.role_id = env('VAULT_ROLE_ID')
        self.secret_id = env('VAULT_SECRET_ID')

        # Authenticate with AppRole
        self.login_to_vault()

        # Fetch the secret key from Vault
        self.fetch_secret_key()

    def login_to_vault(self):
        try:
            self.client.auth.approle.login(role_id=self.role_id, secret_id=self.secret_id)
            print("Successfully logged in to Vault.")
        except Exception as e:
            raise Exception("Failed to login to Vault.")

    def fetch_secret_key(self):
        try:
            secret_response = self.client.secrets.kv.v1.read_secret(path="aes-key")
            key_base64 = secret_response["data"]["value"]
            self.key = base64.b64decode(key_base64)
            print("Successfully retrieved AES key.")
        except Exception as e:
            print("nigga")

    def encrypt(self, data: str) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode('utf-8')

# Custom Method for Generating Links with Expiry
def create_share_item(item, user, password, expiry_days=7):
    hashed_password = make_password(password)
    expiry_date = timezone.now() + timedelta(days=expiry_days)
    
    return SharedItem.objects.create(
        item=item,
        shared_by=user,
        share_link=get_random_string(10),
        access_password=hashed_password,
        expiry_date=expiry_date
    )

def create_share_vault(vault, user, password, expiry_days=7):
    hashed_password = make_password(password)
    expiry_date = timezone.now() + timedelta(days=expiry_days)
    
    return SharedVault.objects.create(
        vault=vault,
        shared_by=user,
        share_link=get_random_string(10),
        access_password=hashed_password,
        expiry_date=expiry_date
    )

# Used in views.py to return decrypted shared items/vaults
def decrypt_item(item):
    aes = AESEncryption()
    if isinstance(item, LoginInfo):
        decrypted_password = aes.decrypt(item.login_password)
        return {
            'login_username': item.login_username,
            'login_password': decrypted_password,
        }
    elif isinstance(item, File):
        decrypted_content = aes.decrypt(item.file_content)
        return {
            'file_name': item.file_name,
            'file_content': decrypted_content,
        }
    return None  # For unsupported item types
