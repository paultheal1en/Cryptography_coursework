import ctypes
from ctypes import c_char_p
import sys
import os
import json
from middlewares.Conversion import int_to_bytes
# def int_to_bytes(n):    
#     return n.to_bytes((n.bit_length() + 7) // 8, 'big')
# .so path
sopath = os.path.join(os.getcwd(),"middlewares/HMAC_SHA3_256.so")

#load the shared library
lib = ctypes.CDLL(sopath,winmode=ctypes.DEFAULT_MODE)

HMAC_SHA3_256 = lib._Z13HMAC_SHA3_256PKhyS0_yPcy
HMAC_SHA3_256.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t
]
HMAC_SHA3_256.restype = None  

# Hàm bọc
def hmac_sha256(key, data):
    key_bytes = int_to_bytes(key)
    
    # Chuyển đổi data thành mảng byte
    data_bytes = ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte))
    
    # Chuẩn bị bộ đệm cho kết quả hexmac
    output_hexmac = ctypes.create_string_buffer(64)  # SHA3-256 produces 32 bytes, hex is 64 bytes

    # Gọi hàm từ thư viện C++
    HMAC_SHA3_256(
        (ctypes.c_ubyte * len(key_bytes)).from_buffer_copy(key_bytes),
        ctypes.c_size_t(len(key_bytes)),
        data_bytes,
        ctypes.c_size_t(len(data)),
        output_hexmac,
        ctypes.sizeof(output_hexmac)
    )

    return output_hexmac.value.decode('utf-8')

# key = 1234567890
# data = b"Hello, world!"  # Chú ý tiền tố "b" để biểu thị là bytes
# print(hmac_sha256(key, data))