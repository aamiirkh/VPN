import socket
import os
import requests
from Crypto.Cipher import AES

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


def get_html(data):
    try:
        headers = requests.get(data)
        print(headers.content)
        return headers.content
    except Exception as e:
        print(e)


def connect_to_client():
    global ThreadCount
    host = '127.0.0.1'
    port = 6666
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.bind((host, port))
    except socket.error as e:
        print(e)

    print('[*] Socket is Listening')
    sock.listen(5)

    while True:
        try:
            Client, address = sock.accept()
            print('[*] Connected To Client.')
            while True:
                data = Client.recv(2048).decode()
                if data != '':
                    output = get_html(data)
                    Client.sendall(output)
        except socket.error as e:
            print(e)
            sock.close()


if __name__ == "__main__":
    connect_to_client()