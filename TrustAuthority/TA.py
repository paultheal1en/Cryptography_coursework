# from charm.schemes.pkenc.pkenc_paillier99 import Pai99
# from charm.toolbox.integergroup import RSAGroup, lcm, gcd, integer, toInt
import threading
import random
import os
from gmpy2 import *
import socket
import ssl
# group = RSAGroup()
# pai = Pai99(group)
# public_key, private_key = pai.keygen()
from Crypto.Util.number import getPrime
rs = gmpy2.random_state(hash(gmpy2.random_state()))

p = mpz(getPrime(1024))
q = mpz(getPrime(1024))
n = p * q
n2 = n * n
g = mpz_random(rs, n2)
# n2 = public_key['n2'] 
# lamda = private_key['lamda']
# l = gcd(pai.L(((g % n2) ** lamda), n), n)
t0 = mpz_random(rs, n)
k = mpz_random(rs, n)
while True:
    skp1 = mpz_random(rs, n)
    skp2 = mpz_random(rs, n)
    skp = skp1 + skp2
    if 1 <= skp < n:
        break

h = powmod(g, skp, n2)
# SE.GenKey
kse = random.randbytes(32).hex()
kkw = random.randbytes(32).hex()
iv = random.randbytes(16).hex()

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='cloudsashs.wuaze.com')
# Send key to SA
HOST = 'cloudsashs.wuaze.com'
PORT = 2808
s.connect((HOST, PORT))
s.send(b"TrustAuthority\n")

payload = ("h = " + str(h) + ',').encode()
payload += ("g = " + str(g) + ',').encode()
payload += ("n = " + str(n) + ',').encode()


payload += ("skp1 = " + str(skp1) + ',').encode()
payload += ("t0 = " + str(t0) + '\n').encode()
s.sendall(payload)
s.close()
# exit()
# Send key to SB

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname='cloudsbshs.wuaze.com')
HOST = 'cloudsbshs.wuaze.com'
PORT = 2809
s.connect((HOST, PORT))
s.send(b"TrustAuthority\n")

payload = ("h = " + str(h) + ',').encode()
payload += ("g = " + str(g) + ',').encode()
payload += ("n = " + str(n) + ',').encode()


payload += ("skp2 = " + str(skp2) + '\n').encode()
s.sendall(payload)
s.close()
# exit()


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


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        context_server = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH)
        context_server.load_cert_chain(
            certfile='./trust-authority.wuaze.com/certificate.crt', keyfile='./trust-authority.wuaze.com/ec-private-key.pem')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.s_sock = context_server.wrap_socket(self.sock, server_side=True)

    def listen(self):
        while True:
            client, address = self.s_sock.accept()
            client.settimeout(60)
            threading.Thread(target=self.listenToClient,
                             args=(client, address)).start()

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
                    raise Exception('Client disconnected')
        except Exception as e:
            print_exception(e)
            print('Client disconnected')
            client.close()


if __name__ == "__main__":
    while True:
        ThreadedServer('0.0.0.0', 2810).listen()

# with open('key/public_key.txt', 'w+') as f:
#     f.write("h = " + str(h) + '\n')
#     f.write("g = " + str(g) + '\n')
#     f.write("n = " + str(n) + '\n')

# with open('key/IOTgateway_key.txt', 'w+') as f:
#     f.write("kse = " + f"\"{kse + iv}\"" + '\n')
#     f.write("kkw = " + f"\"{kkw + iv}\"" + '\n')
#     f.write("t0 = " + str(t0) + '\n')
#     f.write("k = " + str(k) + '\n')

# with open('key/CloudServerSA_key.txt', 'w+') as f:
#     f.write("skp1 = " + str(skp1) + '\n')
#     f.write("t0 = " + str(t0) + '\n')

# with open('key/CloudServerSB_key.txt', 'w+') as f:
#     f.write("skp2 = " + str(skp2) + '\n')

# with open('key/DataUser_key.txt', 'w+') as f:
#     f.write("kse = " + f"\"{kse + iv}\"" + '\n')
#     f.write("k = " + str(k) + '\n')
