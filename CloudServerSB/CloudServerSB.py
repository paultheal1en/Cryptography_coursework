import ssl
import json
import socket
import threading
from traceback import print_exception
from middlewares.Conversion import *
from middlewares.ModifiedPaillier import *
from gmpy2 import *
import logging

# Thiết lập logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        context_server.load_cert_chain(
            certfile='./cloudsbshs.duckdns.org/certificate.crt', keyfile='./cloudsbshs.duckdns.org/ec-private-key.pem')
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
            except socket.timeout as e:
                logging.error(f"Socket timeout error: {e}")
            except ssl.SSLError as e:
                logging.error(f"SSL error: {e}")
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def listenToClient(self, client, address):
        try:
            while True:
                data = recvuntilendl(client)
                logging.info(f"Dữ liệu nhận từ {address}: {data}")
                if data:
                    if data.decode() == 'DataUser':
                        data = recvuntilendl(client).decode()
                        data = json.loads(data)
                        # print(data)
                        context_client = ssl.create_default_context(
                            ssl.Purpose.SERVER_AUTH)
                        sa = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sa = context_client.wrap_socket(
                            sa, server_hostname='cloudsashs.duckdns.org')
                        # Connect to SA
                        sa.connect(('cloudsashs.duckdns.org', 2808))
    
                        if type(data) == type({}):
                            a = []
                            r = data['r']
                            Esw = data['Esw']
                            for i in range(r + 1):
                                a.append(oppoE(pk, prepare_keyword(i)))
                            query = {'Esw': Esw, 'a': a}
                            # print(query)
                        else:
                            query = data
                            pass

                        sa.sendall(b'CloudServerSB\n')
                        sa.sendall((json.dumps(query) + '\n').encode())
                        result = []
                        while True:
                            Dq = recvuntilendl(sa)
                            if Dq == b'End':
                                break
                            Dq = json.loads(Dq.decode())
                            Dqq = DEp2(pk, skp2, Dq)
                            if Dqq == 0:
                                msg = {'res': 1}
                            else:
                                msg = {'res': 0}
                            sa.sendall((json.dumps(msg) + '\n').encode())
                        result = recvuntilendl(sa).decode()
                        client.sendall(
                            (json.dumps(result) + '\n').encode())
                        # print(result)
                        # sa.close()
                    elif data.decode() == 'TrustAuthority':
                        data = recvuntilendl(client).decode().replace(',', '\n')
                        exec(data, globals(), globals())
                        exec("pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}", globals(), globals())
                        # logging.info(f"Dữ liệu bổ sung từ TrustAuthority: {pk}")
                else:
                    logging.info('Client disconnected (1)')
                    break  # Thoát khỏi vòng lặp khi client ngắt kết nối
        except Exception as e:
            logging.error(f"Client disconnected (2): {e}")
        finally:
            client.close()

if __name__ == "__main__":
    while True:
        ThreadedServer('0.0.0.0', 2809).listen()