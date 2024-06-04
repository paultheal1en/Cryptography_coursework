from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class SE:
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    def Enc(self, plaintext):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(
            self.iv), backend=default_backend())
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def Dec(self, ciphertext):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(
            self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_plaintext = decryptor.update(
            ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_plaintext = unpadder.update(
            decrypted_padded_plaintext) + unpadder.finalize()
        return decrypted_plaintext
