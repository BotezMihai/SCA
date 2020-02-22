import socket
import threading
import functions
import random
import base64
from random import randint


def config():
    sck = socket.socket()
    print("Server")
    try:
        sck.bind(("127.0.0.1", 1234))
        sck.listen(5)
        return sck
    except Exception as e:
        raise SystemExit("Eroare la bind")


def on_new_client(client, connection):
    ip = connection[0]
    port = connection[1]
    print(f"S-a conectat un nou client cu adresa ip {ip}, si portul: {port}!")

    msg = client.recv(1024)
    print(f"Mesajul de la client: {msg}")
    pub_k_c_encrypted = msg
    pub_k_c = functions.decrypt_asymmetric(pub_k_c_encrypted, "Merchant")
    # mesajul 2
    print("Pregatim mesajul 2\n")
    sid = str(randint(1000, 9999))
    signature = functions.sign("Merchant", sid)
    message2 = sid.encode("utf-8") + signature
    message2_encrypted = functions.encrypt_symmetric(message2, pub_k_c)
    client.sendall(message2_encrypted)

    msg = client.recv(1024)
    print("Pregatim mesajul 4 sa-l trimitem\n")


    print(f"Clientul cu adresa ip: {ip}, si portul: {port}, a iesit!")
    client.close()


def main(sck):
    while True:
        try:
            client, ip = sck.accept()
            print("aici")
            t = threading.Thread(target=on_new_client, args=(client, ip))
            t.start()
        except Exception as e:
            print(f"Eroare la acceptarea de noi clienti: {e}")


if __name__ == '__main__':
    print("Serverul vanzator")
    sck = config()
    main(sck)
    sck.close()
