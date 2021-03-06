import socket
import threading
import functions
import ast
import json
import hashlib
from Crypto.Util.Padding import pad, unpad
import json


def config():
    sck = socket.socket()
    print("Server")
    try:
        sck.bind(("127.0.0.2", 4321))
        sck.listen(5)
        return sck
    except Exception as e:
        raise SystemExit("Eroare la bind")


def on_new_client(client, connection):
    ip = connection[0]
    port = connection[1]
    print(f"S-a conectat un nou client cu adresa ip {ip}, si portul: {port}!")
    msg = client.recv(25600)
    print(f"Mesajul pe care l-am primit: {msg}")
    json_msg = ast.literal_eval(msg.decode("utf8"))
    # msg4_decrypted = functions.decrypt_asymmetric(msg, "PG").decode("utf8")
    # json_msg4_decrypted = ast.literal_eval(msg4_decrypted)
    aes = functions.decrypt_asymmetric(json_msg['aes'], "PG")
    pm = json_msg['PM']
    pm = unpad(functions.decrypt_symmetric(pm, aes), 48)
    # print("tipul este", type(pm))
    # print(pm)
    pm_ascii = bytes.fromhex(pm.decode("utf8"))
    # print(pm_ascii)
    pm_ascii = functions.decrypt_asymmetric(pm_ascii,
                                            "PG")
    # print("pm ascii este", pm_ascii)
    # test = input("test")
    # pm_decrypted = functions.decrypt_asymmetric(pm_ascii, "PG")
    pm_decrypted_json = ast.literal_eval(pm_ascii.decode("utf8"))
    pi = pm_decrypted_json['PI']
    pi_signature = pm_decrypted_json['PI_signature']
    if functions.verify("Client", str(pi), pi_signature):
        print("Putem continua, semnatura digitala asupra lui PI e autentica")
    else:
        client.sendall(b'ABORT')
    # signature_decrypted = unpad(functions.decrypt_symmetric(pi_signature, pi['PubKC']), 24)
    # pi_hash = hashlib.md5(str(pi).encode("utf8")).hexdigest()
    # if pi_hash == signature_decrypted.decode("utf8"):
    #     print("Putem continua, semnatura digitala asupra lui PI e autentica")
    # else:
    #     print("nu sunt egale")
    #     client.sendall(b'ABORT')
    with open("PG\cc.txt") as fd:
        text = fd.read()
    card = pi['cardN']
    ccode = pi['CCode']
    amount = pi['Amount']
    with open("./BD/bd.json") as fd:
        informations = json.load(fd)
    for client_detail in informations:
        if client_detail['cardN'] == card:
            if int(ccode) != client_detail['ccode'] or int(amount) >= client_detail['amount']:
                client.sendall(b'ABORT')
    sid = pi['Sid']
    pub_k_c = pi['PubKC']
    amount = pi['Amount']
    sid_pubkc_amount = {"sid": sid.decode("utf8"), "pubkc": pub_k_c, "amount": amount}
    signature_merchant = json_msg['signature']
    if functions.verify("Merchant", str(sid_pubkc_amount), signature_merchant):
        print("Semnatura digitala asupra sid, pubKC si amount e autentica")
    else:
        client.sendall(b'ABORT')

    print("Pregatim mesajul 5 catre merchant")
    resp = "ok"
    message5_info = {"resp": resp, "sid": sid.decode("utf8"), "amount": amount, "NC": pi['NC']}
    message5_info_signature = functions.sign("PG", str(message5_info))
    message5 = {"resp": resp, "sid": sid.decode("utf8"), "signature": message5_info_signature.hex()}
    # message5_encrypted = functions.encrypt_asymmetric(str(message5).encode("utf8"), "Merchant")
    message5_encrypted = functions.encrypt_symmetric(str(message5).encode("utf8"), aes)
    client.sendall(message5_encrypted)
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
    print("Payment gateway")
    sck = config()
    main(sck)
    sck.close()
