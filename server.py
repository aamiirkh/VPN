import socket
import ssl
from Crypto.Cipher import AES
import threading

HOST = '127.0.0.1'
PORT = 9999
BUF_SIZE = 4096
KEY = 'secretkey'
IV = 'secretIV'

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]


def do_encrypt(plaintext):
    obj = AES.new(KEY.encode("utf-8"), AES.MODE_CBC, IV.encode("utf-8"))
    plaintext = pad(plaintext)
    ciphertext = obj.encrypt(plaintext)
    return ciphertext


def do_decrypt(ciphertext):
    obj2 = AES.new(KEY.encode("utf-8"), AES.MODE_CBC, IV.encode("utf-8"))
    plaintext = unpad(obj2.decrypt(ciphertext))
    return plaintext.decode('utf-8')


def https(request, webserver, client_sock):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock = context.wrap_socket(server_sock, server_hostname=webserver, do_handshake_on_connect=False)
    server_sock.connect((webserver, 443))
    server_sock.send(request)

    chunk = ''
    data = ''

    server_sock.settimeout(1)

    while True:
        try:
            chunk = server_sock.recv(BUF_SIZE).decode(encoding='utf-8', errors='ignore')
            data += chunk
        except socket.error as e:
            server_sock.close()
            break

    client_sock.send(data.encode())


def http(request, webserver, client_sock):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((webserver, 80))
    server_sock.send(request)

    chunk = ''
    data = ''

    server_sock.settimeout(1)

    while True:
        try:
            chunk = server_sock.recv(BUF_SIZE).decode(encoding='utf-8', errors='ignore')
            data += chunk
        except socket.error as e:
            server_sock.close()
            break

    client_sock.send(data.encode())


def parse(request, conn):
    try:
        header = request.split(b'\n')[0]

        url = header.split(b' ')[1]

        hostIndex = url.find(b"://")
        if hostIndex == -1:
            temp = url
        else:
            temp = url[(hostIndex + 3):]
        portIndex = temp.find(b":")
        serverIndex = temp.find(b"/")

        if serverIndex == -1:
            serverIndex = len(temp)
        webserver = ""
        port = -1
        if portIndex == -1 or serverIndex < portIndex:
            port = 80
            webserver = temp[:serverIndex]
        else:
            port = int((temp[portIndex + 1:])[:serverIndex - portIndex - 1])
            webserver = temp[:portIndex]

        method = request.split(b" ")[0]
        print(webserver)
        print(request)
        if method == b"CONNECT":
            https(request, webserver, conn)
        if method == b"GET":
            http(request, webserver, conn)

    except Exception as e:
        pass


def connect_to_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # client socket
    try:
        sock.bind((HOST, PORT))
    except socket.error as e:
        print(e)

    print('[*] Socket is Listening')
    sock.listen(5)

    while True:
        try:
            conn, address = sock.accept()
            print('[*] Connected To Client.')
            request = conn.recv(BUF_SIZE).decode()
            if request:
                threading.Thread(target=parse, args=(request, conn,)).start()    # threads for multiple requests
        except socket.error as e:
            pass


if __name__ == "__main__":
    connect_to_client()