import ssl
import socket
from traceback import print_exception
import threading
from middlewares.ModifiedPaillier import _mul_, oppoE, DEp1, DEp2
from middlewares.HMAC_SHA_256 import hmac_sha256, int_to_bytes
from middlewares.VariantBloomFilter import *
from pybloom_live import BloomFilter
from base64 import b64decode, b64encode
import json
import time
import logging
import base64
from gmpy2 import *

# Thiết lập logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Khởi tạo Bloom Filter
VBF = BloomFilter(capacity=10000)

# Biến toàn cục
TBL = {}
EncodedFile = {}
label = 1

# Hàm ghi dữ liệu Bloom Filter vào file
def save_vbf(vbf):
    with open('../DataSetVBF.txt', 'w') as file:
        file.write('\n'.join([str(item) for item in vbf.bitarray.tolist()]))


# Hàm ghi dữ liệu bảng từ khóa vào file
def save_tbl(tbl):
    with open('../DataSet/TBL.txt', 'w') as file:
        for key, value in tbl.items():
            file.write(f"{key}: {value}\n")

# Hàm ghi dữ liệu từ điển mã hóa vào file
def save_encodedfile(encodedfile):
    with open('../DataSet/EncodedFile.txt', 'w') as file:
        for key, value in encodedfile.items():
            file.write(f"{key}: {value}\n")
# Hàm nhận dữ liệu từ client cho đến khi gặp ký tự xuống dòng
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
            certfile='./cloudsashs.wuaze.com/self-signed-cert.pem', keyfile='./cloudsashs.wuaze.com/ec-private-key.pem')
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
                threading.Thread(target=self.listenToClient, args=(client, address)).start()
            except ssl.SSLEOFError as e:
                logging.error(f"Lỗi kết nối SSL: {e}")
            except socket.timeout as e:
                logging.error(f"Lỗi timeout socket: {e}")
            except ssl.SSLError as e:
                logging.error(f"Lỗi SSL: {e}")
            except Exception as e:
                logging.error(f"Lỗi khi chấp nhận kết nối: {e}")

    def listenToClient(self, client, address):
        try:
            while True:
                data = recvuntilendl(client)
                logging.info(f"Dữ liệu nhận từ {address}: {data}")
                if data:
                    if data.decode() == 'IOTgateway':
                        data = recvuntilendl(client)
                        data = json.loads(data.decode())
                        Cv = b64decode(data['Cv'])
                        Cw = b64decode(data['Cw']).split(b', ')
                        Ew = [json.loads(wi.replace(b". ", b", ").decode()) for wi in b64decode(data['Ew']).replace(b", ", b". ").split(b',')]
                        id = data['id']
                        mac = b64decode(data['mac'])
                        macq = (hmac_sha256(t0, Cv + b', '.join(Cw) + b','.join(json.dumps(wi).encode() for wi in Ew)))
                        # print (mac)
                        # print (macq)
                        assert mac == macq
                        for i in range(len(Cw)):
                            if VBFVerify(VBF, Cw[i]) == 1:
                                TBL[Cw[i]]['fileid'].append(id)
                            else:
                                TBL[Cw[i]] = {}
                                TBL[Cw[i]]['keyword'] = Ew[i]
                                TBL[Cw[i]]['fileid'] = [id]
                                VBFAdd(VBF, Cw[i])
                        EncodedFile[id] = b64encode(Cv).decode()
                        logging.info(f"Thêm file mã hóa với ID: {id}. Tổng số file: {len(EncodedFile)}")
                        logging.info(f"Số lượng từ khóa trong TBL: {len(TBL.keys())}")

                        # Ghi dữ liệu vào file
                        save_vbf(VBF)
                        save_tbl(TBL)
                        save_encodedfile(EncodedFile)
                        client.sendall(b'ACK\n')  # Gửi ACK để thông báo đã nhận và xử lý xong
                    elif data.decode() == 'CloudServerSB':
                        query = recvuntilendl(client)
                        query = json.loads(query.decode())
                        logging.info(f"query : {query}")
                        fileIDresults = set()
                        cnt = 1
                        if isinstance(query, dict):
                            for Et in query['a']:
                                for key in TBL.keys():
                                    D = _mul_(pk, TBL[key]['keyword'], query['Esw'])
                                    D = _mul_(pk, D, Et)
                                    Dq = DEp1(pk, skp1, D)
                                    client.sendall((json.dumps(Dq) + '\n').encode())
                                    res = json.loads(recvuntilendl(client).decode())['res']
                                    logging.info(f"res = {res}") 
                                    if res == 1:
                                        fileIDresults.update(TBL[key]['fileid'])
                                    logging.info(f"Đã xử lý phần truy vấn {cnt}")
                                    cnt += 1
                            client.sendall(b'End\n')
                        else:
                            for Esw in query:
                                logging.info(f"Đã xử lý phần truy vấn {Esw}")
                                res_tmp = set()
                                for key in TBL.keys():
                                    D = _mul_(pk, TBL[key]['keyword'], Esw)
                                    Dq = DEp1(pk, skp1, D)
                                    client.sendall((json.dumps(Dq) + '\n').encode())
                                    res = json.loads(recvuntilendl(client).decode())['res']
                                    logging.info(f"res = {res}") 
                                    if res == 1:
                                        res_tmp.update(TBL[key]['fileid'])
                                    logging.info(f"Đã xử lý phần truy vấn {cnt}")
                                    cnt += 1
                                if Esw == query[0]:
                                    fileIDresults.update(res_tmp)
                                else:
                                    fileIDresults.intersection_update(res_tmp)
                            client.sendall(b'End\n')

                        result = []
                        logging.info(f"Kết quả truy vấn: {fileIDresults}")
                        for id in fileIDresults:
                            result.append([id, EncodedFile[id]])
                        logging.info(f"Result: {result}")
                        client.sendall((json.dumps(result) + '\n').encode())
                    elif data.decode() == 'TrustAuthority':
                        data = recvuntilendl(client).decode().replace(',', '\n')
                        logging.info(f"Dữ liệu bổ sung từ TrustAuthority: {data}")
                        exec(data, globals(), globals())
                        exec("pk = {'n': mpz(n), 'h': mpz(h), 'g': mpz(g)}", globals(), globals())
                else:
                    logging.info('Client đã ngắt kết nối (1)')
                    break  # Thoát khỏi vòng lặp khi client ngắt kết nối
        except Exception as e:
            logging.error(f"Client đã ngắt kết nối (2): {e}")
        finally:
            try:
                client.sendall(b'End\n')  # Gửi End để đảm bảo client biết kết thúc dữ liệu
            except:
                pass
            client.close()

if __name__ == "__main__":
    while True:
        ThreadedServer('0.0.0.0', 2808).listen()
