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

class AESEncryption:
    def __init__(self):
        # Hardcoded secret key for development (must be 32 bytes for AES-256)
        self.key = b'hardcodedsecretkeythatis32bytes!'

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
def create_shared_item_link(item, user, password, expiry_days=7):
    hashed_password = make_password(password)
    expiry_date = timezone.now() + timedelta(days=expiry_days)
    
    return SharedItem.objects.create(
        item=item,
        shared_by=user,
        share_link=get_random_string(10),
        access_password=hashed_password,
        expiry_date=expiry_date
    )

def create_shared_vault_link(vault, user, password, expiry_days=7):
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