import ctypes
import os


sopath = os.path.join(os.getcwd(), "middlewares/sofile/AES_CTR_256.so")


class SE:
    def __init__(self, iv, key):
        self.iv = (ctypes.c_ubyte * len(iv))(*iv)
        self.key = (ctypes.c_ubyte * len(key))(*key)
        self.lib = ctypes.CDLL(sopath)

        # Define argument types for Enc and Dec functions
        self.lib.Enc.argtypes = [
            ctypes.c_ubyte * 32, ctypes.c_ubyte * 16,
            ctypes.c_ubyte * 4096, ctypes.c_size_t,
            ctypes.c_ubyte * 4096, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.lib.Dec.argtypes = [
            ctypes.c_ubyte * 32, ctypes.c_ubyte * 16,
            ctypes.c_ubyte * 4096, ctypes.c_size_t,
            ctypes.c_ubyte * 4096, ctypes.POINTER(ctypes.c_size_t)
        ]

    def Enc(self, plaintext):
        plaintext_len = len(plaintext)
        plaintext_arr = (ctypes.c_ubyte * 4096)(*plaintext)
        ciphertext = (ctypes.c_ubyte * 4096)()
        ciphertext_len = ctypes.c_size_t(4096)

        self.lib.Enc(
            self.key,
            self.iv,
            plaintext_arr,
            ctypes.c_size_t(plaintext_len),
            ciphertext,
            ctypes.byref(ciphertext_len)
        )

        return bytes(ciphertext[:ciphertext_len.value])

    def Dec(self, ciphertext):
        ciphertext_len = len(ciphertext)
        ciphertext_arr = (ctypes.c_ubyte * 4096)(*ciphertext)
        plaintext = (ctypes.c_ubyte * 4096)()
        plaintext_len = ctypes.c_size_t(4096)

        self.lib.Dec(
            self.key,
            self.iv,
            ciphertext_arr,
            ctypes.c_size_t(ciphertext_len),
            plaintext,
            ctypes.byref(plaintext_len)
        )

        return bytes(plaintext[:plaintext_len.value])

# # Example usage
# key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
# key = bytes.fromhex(key_hex)  # 32 bytes key for AES-256
# iv = b'abcdef9876543210'      # 16 bytes IV
# plaintext = b'This is a secret mes+sage'

# se = SE(iv, key)
# ciphertext = se.Enc(plaintext)
# print("Ciphertext:", ciphertext)
# decrypted = se.Dec(ciphertext)
# print("Decrypted:", decrypted)