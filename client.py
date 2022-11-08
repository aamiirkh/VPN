import socket
from Crypto.Cipher import AES

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


def make_conn():
    ClientMultiSocket = socket.socket()
    host = '127.0.0.1'
    port = 9999

    print('[*] Waiting for connection response')
    try:
        ClientMultiSocket.connect((host, port))
        print('[*] Connected to server successfully')
    except socket.error as e:
        print(str(e))

    while True:
        Input = input('Hey there: ')
        data = do_encrypt(Input)
        try:
            ClientMultiSocket.send(data)
            res = ClientMultiSocket.recv(2048)
            print(do_decrypt(res))
        except socket.error as e:
            print(str(e))
            ClientMultiSocket.close()
            exit(0)


if __name__ == "__main__":
    make_conn()