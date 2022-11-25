import socket
import sys
import threading
from Crypto.Cipher import AES

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]


def do_encrypt(plaintext):
    obj = AES.new('secretkey'.encode("utf-8"), AES.MODE_CBC, 'secretIV'.encode("utf-8"))
    plaintext = pad(plaintext)
    ciphertext = obj.encrypt(plaintext)
    return ciphertext


def do_decrypt(ciphertext):
    obj2 = AES.new('secretkey'.encode("utf-8"), AES.MODE_CBC, 'secretIV'.encode("utf-8"))
    plaintext = unpad(obj2.decrypt(ciphertext))
    return plaintext.decode('utf-8')


def forward_data(server_sock, client_sock):
    try:
        while True:
            data = client_sock.recv(999999)
            print(data)
            if len(data) < 1:
                break
            server_sock.sendall(data)

    except socket.error as e:
        print(e)
        sys.exit()


def connection():
    # connection with vpn
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for sending domain to vpn server
    host = '127.0.0.1'
    port = 6666

    print("[*] Connecting to vpn server")
    try:
        server_sock.connect((host, int(port)))
        print("[*] Connected to vpn server successfully.")
    except Exception as e:
        print(e)

    # connection with browser
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for receiving data from browser
    host = '127.0.0.1'
    port = 9999

    try:
        sock.bind((host, int(port)))
        sock.listen(5)
    except socket.error as e:
        print(e)

    while True:
        try:
            conn, addr = sock.accept()
            request = conn.recv(4096).decode()
            if request:
                request = request.split('\n')[0]
                server_sock.sendall(request.encode())
                threading.Thread(target=forward_data, args=(conn, server_sock,)).start()
                threading.Thread(target=forward_data, args=(server_sock, conn,)).start()
        except socket.error as e:
            print(e)
            sock.close()
            sys.exit()


if __name__ == "__main__":
    connection()