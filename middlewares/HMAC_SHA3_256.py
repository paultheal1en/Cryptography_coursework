import ctypes
from ctypes import c_char_p
import sys
import os

# .so path
sopath = os.path.join(os.getcwd(),"HMAC_SHA3_256.so")

#load the shared library
lib = ctypes.CDLL(sopath,winmode=ctypes.DEFAULT_MODE)

# Set up the prototype of the function
# All of then are strings (char*)
HMAC_SHA3_256 = lib.HMAC_SHA3_256
HMAC_SHA3_256.argtypes = [c_char_p,c_char_p,c_char_p,ctypes.c_size_t]
HMAC_SHA3_256.restype = None  

# Wrapped functions
def hmac_sha3_256(key, data):
    key = key.encode('utf-8')
    data = data.encode('utf-8')

    # Chuẩn bị bộ đệm cho kết quả hexmac
    output_hexmac = ctypes.create_string_buffer(64)  # SHA3-256 sẽ cho ra 32 bytes, hex là 64 bytes
    # Gọi hàm từ thư viện C++
    HMAC_SHA3_256(key, data, output_hexmac, ctypes.sizeof(output_hexmac))

    return output_hexmac.value.decode('utf-8')
# Ví dụ sử dụng hàm HMAC_SHA3_256
# key = 'secret_key'
# data = 'encrypted_data'
# hexmac = hmac_sha3_256(key, data)
# print(hexmac)