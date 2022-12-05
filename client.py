import socket
import sys
import threading
from Crypto.Cipher import AES

HOST = '127.0.0.1'
CLIENT_PORT = 6666
SERVER_PORT = 9999
BUF_SIZE = 4096


BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]


def do_encrypt(plaintext):
    obj = AES.new('This is a key123'.encode("utf-8"), AES.MODE_CFB, 'This is an IV456'.encode("utf-8"))
    plaintext = pad(plaintext)
    ciphertext = obj.encrypt(plaintext)
    return ciphertext


def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123'.encode("utf-8"), AES.MODE_CFB, 'This is an IV456'.encode("utf-8"))
    plaintext = unpad(obj2.decrypt(ciphertext))
    return plaintext


def receive_from_server(client_sock, server_sock):
    data = ''
    chunk = ''
    while True:
        try:
            while True:
                chunk = server_sock.recv(BUF_SIZE)
                if chunk:
                    print(do_decrypt(chunk))
                    client_sock.send(do_decrypt(chunk))
                else:
                    break
        except (socket.error, KeyboardInterrupt) as e:
            print(e)
            sys.exit()



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

        threading.Thread(target=receive_from_server, args=(conn, server_sock,)).start()

        while True:
            try:
                data = conn.recv(BUF_SIZE).decode(encoding='utf-8', errors='ignore')
                if data:
                    print(data)
                    server_sock.send(do_encrypt(data))

            except (socket.error, KeyboardInterrupt) as e:
                print(e)
                sys.exit()

    except socket.error as e:
        sock.close()
        sys.exit()


if __name__ == "__main__":
    connection()