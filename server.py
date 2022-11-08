import socket
import os
from _thread import *
from Crypto.Cipher import AES

host = '127.0.0.1'
port = 9999
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


def multi_threaded_client(connection):
    while True:
        data = connection.recv(2048)
        if data != '':
            response = 'Server message: ' + str(do_decrypt(data))
            print("From client: " + str(do_decrypt(data)))
            connection.sendall(do_encrypt(response))


def make_conn():
    global ThreadCount
    ServerSideSocket = socket.socket()

    try:
        ServerSideSocket.bind((host, port))
    except socket.error as e:
        print(str(e))

    print('[*] Socket is listening..')
    ServerSideSocket.listen(5)

    while True:
        try:
            Client, address = ServerSideSocket.accept()
            print('\n[*] Connected to: ' + address[0] + ':' + str(address[1]))
            start_new_thread(multi_threaded_client, (Client,))
            ThreadCount += 1
            print('Thread Number: ' + str(ThreadCount))
        except socket.error as e:
            print(str(e))
            ServerSideSocket.close()


if __name__ == "__main__":
    make_conn()