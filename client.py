import socket
import sys
import threading
from Crypto.Cipher import AES

HOST = '127.0.0.1'
CLIENT_PORT = 5555
SERVER_PORT = 9999
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


def receive_from_browser(server_sock, client_sock):
    data = ''

    while True:
        try:
            data = client_sock.recv(BUF_SIZE).decode()
            if data:
                server_sock.send(data.encode())

        except socket.error as e:
            print(e)


def receive_from_server(client_sock, server_sock):
    data = ''
    while True:
        try:
            data = server_sock.recv(BUF_SIZE).decode()
            if data:
                print(data)
                client_sock.send(data.encode())
        except socket.error as e:
            print(e)


def connection():
    # connection with vpn
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for sending domain to vpn server

    print("[*] Connecting to vpn server")
    try:
        server_sock.connect((HOST, SERVER_PORT))
        print("[*] Connected to vpn server successfully.")
    except Exception as e:
        print(e)

    # connection with browser
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for receiving data from browser

    try:
        sock.bind((HOST, CLIENT_PORT))
        sock.listen(5)
    except socket.error as e:
        print(e)

    try:
        conn, addr = sock.accept()

        threading.Thread(target=receive_from_browser, args=(server_sock, conn,)).start()
        threading.Thread(target=receive_from_server, args=(conn, server_sock,)).start()

    except socket.error as e:
        sock.close()
        sys.exit()


if __name__ == "__main__":
    connection()