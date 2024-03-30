from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class AESEncryption:
    def __init__(self, password: str, salt: bytes):
        self.key_aes = self.derive_key(password, salt, key_length=32)  # 256-bit key

    @staticmethod
    def derive_key(password: str, salt: bytes, key_length: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: str) -> bytes:
        iv = os.urandom(16)  # Generate a new IV for each encryption
        cipher_aes = Cipher(algorithms.AES(self.key_aes), modes.CBC(iv), backend=default_backend())
        encryptor_aes = cipher_aes.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        encrypted_aes = encryptor_aes.update(padded_data) + encryptor_aes.finalize()

        return iv + encrypted_aes  # Prepend the IV to the encrypted data

    def decrypt(self, data: bytes) -> str:
        iv = data[:16]  # Extract the IV
        ciphertext = data[16:]
        cipher_aes = Cipher(algorithms.AES(self.key_aes), modes.CBC(iv), backend=default_backend())
        decryptor_aes = cipher_aes.decryptor()
        decrypted_padded = decryptor_aes.update(ciphertext) + decryptor_aes.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted_data.decode('utf-8')

# Example usage:
# aes_encryption = AESEncryption(password="your_password", salt=os.urandom(16))
# encrypted_data = aes_encryption.encrypt("Hello, World!")
# decrypted_data = aes_encryption.decrypt(encrypted_data)
# print("Encrypted:", encrypted_data)
# print("Decrypted:", decrypted_data)

try:
    aes_encryption = AESEncryption(password="test110", salt=os.urandom(16))
    encrypted_data = aes_encryption.encrypt("Hello, World!")
    decrypted_data = aes_encryption.decrypt(encrypted_data)

    test_result = {
        "encrypted_data": encrypted_data,
        "decrypted_data": decrypted_data
    }
except Exception as e:
    test_result = str(e)

print(test_result)
