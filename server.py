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
            data = client_sock.recv(9999999).decode()
            if data:
                print(data)
                server_sock.send(data.encode())
            else:
                break
    except:
        pass


def https(client_sock, domain, port):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock = context.wrap_socket(server_sock, server_hostname="github.com", do_handshake_on_connect=False)
        # Connect to the server
        server_sock.connect(("github.com", 443))
        client_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        server_sock.do_handshake()
        server_sock.send(f"GET / HTTP/1.1\r\nHost: www.github.com\r\n\r\n ".encode())

        threading.Thread(target=forward_data, args=(client_sock, server_sock,)).start()
        threading.Thread(target=forward_data, args=(server_sock, client_sock,)).start()


    except socket.error as e:
        print(e)

    return


def http(conn, domain, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((domain, 80))
    s.send(b"GET / HTTP/1.1\r\nHost:" + domain.encode() + b"\r\n\r\n")
    try:
        while True:
            data = s.recv(4096).decode()
            if len(data) < 1:
                break
            conn.send(data.encode())
            print(data)
    except Exception as e:
        print(e)
        s.close()


def parse(request, conn):
    print(request)
    try:
        port = request.split(' ')[0].strip()
        if port == 'CONNECT':
            domain = request.split('CONNECT')[1].split(':')[0].strip()
            https(conn, domain, port)
        elif port == 'GET':
            domain = request.split('GET')[1].split(':')[0].strip()
            http(conn, domain, port)

    except socket.error as e:
        print(e)


def connect_to_client():
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
        try:
            conn, address = sock.accept()
            print('[*] Connected To Client.')
            request = conn.recv(4096).decode()
            threading.Thread(target=parse, args=(request, conn,)).start()
            parse(request, conn)
        except socket.error as e:
            pass


if __name__ == "__main__":
    connect_to_client()