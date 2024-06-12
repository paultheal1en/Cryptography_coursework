import struct


def int_to_bytes(n):    
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def bytes_to_int(byte_array):
    return int.from_bytes(byte_array, byteorder='big')


def float_to_bytes(f):
    # Convert float to byte representation
    byte_string = struct.pack('!f', f)
    return byte_string


def bytes_to_float(byte_representation):
    # Convert byte representation to float
    return float(byte_representation)


def prepare_keyword(k):
    try:
        k = float(k)
        return round(k)
    except:
        return bytes_to_int(k)
