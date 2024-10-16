from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

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
