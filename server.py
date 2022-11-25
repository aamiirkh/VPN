import socket
import os
import requests
import ssl
from Crypto.Cipher import AES
import threading

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

ThreadCount = 0

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]


def do_encrypt(plaintext):
    obj = AES.new('This is a key123'.encode("utf-8"), AES.MODE_CBC, 'This is an IV456'.encode("utf-8"))
    plaintext = pad(plaintext)
    ciphertext = obj.encrypt(plaintext)
    return ciphertext


def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123'.encode("utf-8"), AES.MODE_CBC, 'This is an IV456'.encode("utf-8"))
    plaintext = unpad(obj2.decrypt(ciphertext))
    return plaintext.decode('utf-8')


def forward_data(server_sock, client_sock):
    try:
        while True:
            data = client_sock.recv(4096)
            if data:
                print(data)
                server_sock.send(data.encode())
            else:
                break
    except:
        pass


def https(client_sock, domain, port, request):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock = context.wrap_socket(server_sock, server_side=True, do_handshake_on_connect=False)
        server_sock.do_handshake()

        # Connect to the server
        server_sock.connect((domain, int(port)))
        client_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')

        threading.Thread(target=forward_data, args=(server_sock, client_sock,)).start()
        threading.Thread(target=forward_data, args=(client_sock, server_sock,)).start()

    except socket.error as e:
        print(e)

    return


def http(conn, domain, port, request):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((request, port))
    s.send(request)
    try:
        while True:
            data = s.recv(4096).decode()
            if data == '':
                break
            conn.send(data).encode()
            print(data)
        return data
    except Exception as e:
        print(e)
        s.close()


def parse(conn, request):
    try:
        port = request.split(':')[1].split('HTTP/1.1')[0].strip()
        if port == '443':
            domain = request.split('CONNECT')[1].split(':')[0].strip()
            https(conn, domain, port, request)
        elif port == '80':
            domain = request.split('GET')[1].split(':')[0].strip()
            http(conn, domain, port, request)

    except Exception as e:
        print(e)


def connect_to_client():
    global ThreadCount
    host = '127.0.0.1'
    port = 6666
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # client socket

    try:
        sock.bind((host, port))
    except socket.error as e:
        print(e)

    print('[*] Socket is Listening')
    sock.listen(5)

    while True:
        Client, address = sock.accept()
        print('[*] Connected To Client.')
        while True:
            try:
                data = Client.recv(4096).decode()
                parse(sock, data)
            except socket.error as e:
                pass


if __name__ == "__main__":
    connect_to_client()