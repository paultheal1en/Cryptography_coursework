import ctypes
import os
from middlewares.Conversion import int_to_bytes

# .so path
sopath = os.path.join(os.getcwd(), "./middlewares/HMAC_SHA3_256.so")

# Load the shared library
lib = ctypes.CDLL(sopath, winmode=ctypes.DEFAULT_MODE)

HMAC_SHA3_256 = lib._Z13HMAC_SHA3_256PKhyS0_yPh
HMAC_SHA3_256.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
]
HMAC_SHA3_256.restype = None  

# Hàm bọc
def hmac_sha256(key: int, data: bytes):
    key_bytes = int_to_bytes(key)
    
    # Chuyển đổi data thành mảng byte
    data_bytes = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    
    # Chuẩn bị bộ đệm cho kết quả mac
    output_mac = (ctypes.c_ubyte * 32)()  # SHA3-256 produces 32 bytes

    # Gọi hàm từ thư viện C++
    HMAC_SHA3_256(
        (ctypes.c_ubyte * len(key_bytes)).from_buffer_copy(key_bytes),
        ctypes.c_size_t(len(key_bytes)),
        data_bytes,
        ctypes.c_size_t(len(data)),
        output_mac,
    )

    # Trả về kết quả dưới dạng chuỗi byte
    return bytes(output_mac)

# Ví dụ sử dụng
if __name__ == "__main__":
    key = 1234567890  # Khóa dưới dạng số nguyên
    message = b'This is a test message'  # Thông điệp dưới dạng byte

    hmac_digest = hmac_sha256(key, message)

    # In kết quả dưới dạng chuỗi byte và dưới dạng hex
    print("HMAC Digest (byte):", hmac_digest)
    print("HMAC Digest (hex):", hmac_digest.hex())