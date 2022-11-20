import socket
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


def send_to_server(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for sending domain to vpn server
    host = '127.0.0.1'
    port = 6666

    print("[*] Connecting to vpn server")
    try:
        sock.connect((host, int(port)))
        print("[*] Connected to vpn server successfully.")
        sock.send(domain.encode())

        output = sock.recv(4096)
        print(output)
    except Exception as e:
        print(e


def parse(conn):
    try:
        request = conn.recv(4098).decode()
        domain = request.split('CONNECT')[1].split(':')[0].strip()
        port = request.split(':')[1].split('HTTP/1.1')[0].strip()

        if port == '443':
            domain = "https://" + domain
        elif port == '80':
            domain = "http://" + domain

        send_to_server(domain)
    except Exception as e:
        print(e)


def connection_with_browser():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for receiving data from browser
    host = '127.0.0.1'
    port = 9999

    try:
        sock.bind((host, int(port)))
        sock.listen(5)
        print(f"[*] Listening on port {port}")
    except socket.error as e:
        print(e)

    while True:
        while True:
            try:
                conn, addr = sock.accept()
                parse(conn)
            except Exception as e:
                print(e)
                sock.close()


if __name__ == "__main__":
    connection_with_browser()