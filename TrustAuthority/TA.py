import threading
import random
import os
from gmpy2 import *
import socket
import ssl
import traceback
import logging

from Crypto.Util.number import getPrime

# Khởi tạo một trạng thái ngẫu nhiên
rs = gmpy2.random_state(hash(gmpy2.random_state()))

# Tạo số nguyên tố p và q có 1024 bit
p = mpz(getPrime(1024))
q = mpz(getPrime(1024))
n = p * q  # Tính tích của p và q
n2 = n * n  # Bình phương của n
g = mpz_random(rs, n2)  # Tạo số ngẫu nhiên g

t0 = mpz_random(rs, n)  # Tạo số ngẫu nhiên t0
k = mpz_random(rs, n)  # Tạo số ngẫu nhiên k

# Tạo skp1 và skp2 sao cho skp1 + skp2 nằm trong khoảng [1, n)
while True:
    skp1 = mpz_random(rs, n)
    skp2 = mpz_random(rs, n)
    skp = skp1 + skp2
    if 1 <= skp < n:
        break

h = powmod(g, skp, n2)  # Tính h = g^skp mod n2

# Tạo chuỗi kse và kkw ngẫu nhiên
kse = random.randbytes(32).hex()
kkw = random.randbytes(32).hex()
iv = random.randbytes(16).hex()

payload_a = ("h = " + str(h) + ',').encode()
payload_a += ("g = " + str(g) + ',').encode()
payload_a += ("n = " + str(n) + ',').encode()
payload_a += ("skp1 = " + str(skp1) + ',').encode()
payload_a += ("t0 = " + str(t0) + '\n').encode()

payload_b = ("h = " + str(h) + ',').encode()
payload_b += ("g = " + str(g) + ',').encode()
payload_b += ("n = " + str(n) + ',').encode()
payload_b += ("skp2 = " + str(skp2) + '\n').encode()

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # Tắt kiểm tra tên máy chủ
context.verify_mode = ssl.CERT_NONE  # Tắt xác minh chứng chỉ
# Gửi data cho SA
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='localhost')
s.connect(('127.0.0.1', 2808))
s.sendall(b"TrustAuthority\n")
s.sendall(payload_a)



# Gửi data cho SB
sb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sb = context.wrap_socket(sb, server_hostname='localhost')
sb.connect(('127.0.0.1', 2809))
sb.sendall(b"TrustAuthority\n")
sb.sendall(payload_b)

def recvuntilendl(client):
    res = b''
    while True:
        ch = client.recv(1)
        if not ch:
            break
        if ch == b'\n':
            break
        res += ch
    return res


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        context_server = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH)
        context_server.check_hostname = False  # Tắt kiểm tra tên máy chủ
        context_server.verify_mode = ssl.CERT_NONE 
        context_server.load_cert_chain(
            certfile='./trust-authority.wuaze.com/self-signed-cert.pem',
            keyfile='./trust-authority.wuaze.com/ec-private-key.pem')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.s_sock = context_server.wrap_socket(self.sock, server_side=True)

    def listen(self):
        while True:
            try:
                client, address = self.s_sock.accept()
                client.settimeout(60)
                threading.Thread(target=self.listenToClient,
                                 args=(client, address)).start()
            except ssl.SSLEOFError as e:
                logging.error(f"SSL connection error: {e}")
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def listenToClient(self, client, address):
        try:
            while True:
                data = recvuntilendl(client)

                if data:
                    if (data.decode() == 'IOTgateway'):
                        payload = ""
                        payload += "h = " + str(h) + ','
                        payload += "g = " + str(g) + ','
                        payload += "n = " + str(n) + ','
                        payload += "kse = " + f"\"{kse + iv}\"" + ','
                        payload += "kkw = " + f"\"{kkw + iv}\"" + ','
                        payload += "t0 = " + str(t0) + ','
                        payload += "k = " + str(k) + '\n'
                        client.send(payload.encode())
                    elif data.decode() == 'DataUser':
                        payload = ""
                        payload += "h = " + str(h) + ','
                        payload += "g = " + str(g) + ','
                        payload += "n = " + str(n) + ','
                        payload += "kse = " + f"\"{kse + iv}\"" + ','
                        payload += "k = " + str(k) + '\n'
                        client.send(payload.encode())
                else:
                    print('Client disconnected (1)')
                    break  # Thoát khỏi vòng lặp khi client ngắt kết nối
        except Exception as e:
            print('Client disconnected (2)')
        finally:
            client.close()


if __name__ == "__main__":
    while True:
        ThreadedServer('0.0.0.0', 2810).listen()
