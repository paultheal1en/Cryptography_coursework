import ssl
from gmpy2 import *
from middlewares.AES_CBC_256 import SE
from middlewares.ModifiedPaillier import E
from middlewares.HMAC_SHA_256 import hmac_sha256
from middlewares.Conversion import int_to_bytes, prepare_keyword
import socket
import hashlib
import hmac
import os
import time
import random
import json
from base64 import b64encode


def recvuntilendl(client):
    res = b''
    while (True):
        ch = client.recv(1)
        if not ch:
            break
        if (ch == b'\n'):
            break
        res += ch
    return res

# Kết nối với TA
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # Tắt kiểm tra tên máy chủ
context.verify_mode = ssl.CERT_NONE  # Tắt xác minh chứng chỉ
# Tạo socket và bọc nó trong SSL
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='localhost')
# Kết nối đến Trust Authority
s.connect(('127.0.0.1', 2810))
# Gửi dữ liệu đến Trust Authority và nhận phản hồi
s.sendall(b"IOTgateway\n")
data = recvuntilendl(s).decode().replace(',', '\n')
exec(data)
print(data)
# Modified Paillier Parameters
pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}

# Secure Symmetric Encryption Parameters
key = bytes.fromhex(kkw)
kkw, iv = key[0:32], key[32:]
key = bytes.fromhex(kse)
kse, iv = key[0:32], key[32:]


f = []
w = []
id = 1
vitalsigns = [b"age",
              b"gender",
              b"tot_bilirubin",
              b"direct_bilirubin",
              b"alkphos",
              b"sgpt",
              b"sgot",
              b"tot_proteins",
              b"albumin",
              b"ag_ratio",
              b"is_patient"]

# fo = open('DataSet/SA.txt', 'w+')
# Kết nối với SA
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='localhost')
s.connect(('127.0.0.1', 2808))
with open('PHI.csv', 'r') as fi:
    for fv in fi.readlines()[:100]:
        w = [i.encode() for i in fv.strip().split(',')]

        fv = fv.strip().encode()

        Mac = hmac_sha256(k, fv)

        fvq = Mac + fv
        # print(fvq)

        Cv = SE(iv, kse).Enc(fvq)

        Cw = []
        for i in range(len(w)):
            Cw.append(SE(iv, kkw).Enc(int_to_bytes(prepare_keyword(
                vitalsigns[i]) + prepare_keyword(w[i]))))
        # Cw = [SE(iv, kkw).Enc(wi) for wi in w]

        Ew = []
        for i in range(len(w)):
            Ew.append(E(pk, prepare_keyword(
                vitalsigns[i]) + prepare_keyword(w[i])))

        mac = hmac_sha256(t0, Cv + b', '.join(Cw) +
                          b','.join(json.dumps(wi).encode() for wi in Ew))

        data = {'Cv': b64encode(Cv).decode(),
                'Cw': b64encode(b', '.join(Cw)).decode(),
                'Ew': b64encode(b','.join(json.dumps(wi).encode() for wi in Ew)).decode(),
                'id': id,
                'mac': b64encode(mac).decode()}

        # fo.write(json.dumps(data) + '\n')
        s.sendall(b'IOTgateway\n')
        s.sendall((json.dumps(data) + '\n').encode())
        print(id)
        # exit()
        id += 1
s.close()
# print(w)
