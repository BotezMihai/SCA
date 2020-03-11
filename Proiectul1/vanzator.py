import socket
import threading
import functions
import random
import base64
from random import randint
import json
import ast
import hashlib
from Crypto.Util.Padding import pad, unpad


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

    msg = client.recv(3072)
    print(f"Mesajul pe care l-am primit: {msg}")
    # pub_k_c_encrypted = msg
    # pub_k_c = functions.decrypt_asymmetric(pub_k_c_encrypted, "Merchant")
    msg_json = msg.decode("utf8")
    msg_json = ast.literal_eval(msg_json)
    aes_encrypted = msg_json['aes_encrypted']
    pub_k_c_encrypted = msg_json['pub_k_c_encrypted']
    pub_k_c_encrypted = bytes.fromhex(pub_k_c_encrypted)
    aes_encrypted = bytes.fromhex(aes_encrypted)
    aes = functions.decrypt_asymmetric(aes_encrypted, "Merchant")
    pub_k_c = unpad(functions.decrypt_symmetric(pub_k_c_encrypted, aes), 48)
    # mesajul 2
    print("Pregatim mesajul 2\n")
    sid = str(randint(1000, 9999))
    signature = functions.sign("Merchant", sid)
    message2 = sid.encode("utf-8") + signature
    print("lungimea e", len(aes))
    message2_encrypted = functions.encrypt_symmetric(message2, aes)
    client.sendall(message2_encrypted)

    msg = client.recv(8192)
    print(f"Mesajul pe care l-am primit: {msg}")
    print("Pregatim mesajul 4 sa-l trimitem\n")
    print("lungimea mesajului este", len(msg))
    msg2_decrypted = unpad(functions.decrypt_symmetric(msg, aes), 48)
    msg2_decrypted = msg2_decrypted.decode("utf8")

    json_data = ast.literal_eval(msg2_decrypted)
    po = json_data['PO']
    oi = po['OI']
    json_oi = ast.literal_eval(oi)
    amount = json_oi['Amount']
    oi = str(oi)
    oi_signature = po['OI_signature']
    if functions.verify("Client", oi, oi_signature):
        print("Semnatura clientului asupra lui OI este in regula")
    else:
        client.sendall(b"ABORT")
    PM = json_data['PM']
    sid_pubkc_amount = {"sid": sid, "pubkc": pub_k_c, "amount": amount}
    signature_sid_pubkc_amount = functions.sign("Merchant", str(sid_pubkc_amount))
    message4_encrypted = {"PM": functions.encrypt_symmetric(str(PM).encode("utf8"), aes),
                          "signature": signature_sid_pubkc_amount,
                          "aes": functions.encrypt_asymmetric(aes, "PG")}
    # message4_encrypted = functions.encrypt_asymmetric(str(message4).encode("utf8"), "PG")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sckTTP:
        try:
            sckTTP.connect(("127.0.0.2", 4321))
        except Exception as e:
            raise SystemExit(f"Eroare la conecatarea la server: {e}")
        sckTTP.sendall(str(message4_encrypted).encode("utf8"))

        msg = sckTTP.recv(4096)
        print(f"Mesajul pe care l-am primit: {msg}")
        if msg == b'ABORT':
            client.sendall(b'ABORT')
        msg5_decrypted = unpad(functions.decrypt_symmetric(msg, aes), 48)
        print("Pregatim mesajul 6")
        msg6 = functions.encrypt_symmetric(msg5_decrypted, aes)
        client.sendall(msg6)
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
