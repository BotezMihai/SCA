import socket
import functions
import time
from Crypto.Util.Padding import pad, unpad
import ast
from Crypto.PublicKey import RSA

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sck:
    try:
        sck.connect(("127.0.0.1", 1234))
    except Exception as e:
        raise SystemExit(f"Eroare la conecatarea la server: {e}")
    # primul mesaj C->M
    aes = functions.generate_symmetric_key()

    # pub_k_c_encrypted = functions.encrypt_asymmetric(pub_k_c, "Merchant")
    pub_k_c = RSA.import_key(open("Client" + "/" + "public_pem.pem", 'r').read())
    pub_k_c = pub_k_c.exportKey()
    pub_k_c_encrypted = functions.encrypt_symmetric(pub_k_c, aes)
    aes_encrypted = functions.encrypt_asymmetric(aes, "Merchant")
    data_to_send = {"pub_k_c_encrypted": pub_k_c_encrypted.hex(), "aes_encrypted": aes_encrypted.hex()}
    data_to_send = str(data_to_send)
    data_to_send = data_to_send.encode("utf8")
    print(data_to_send)
    sck.sendall(data_to_send)
    data = sck.recv(3072)
    print(f"Mesajul pe care l-am primit: {data}")
    print("lungimea e", len(aes))
    message2_decrypted = unpad(functions.decrypt_symmetric(data, aes), 24)
    sid = message2_decrypted[:4]
    signature = message2_decrypted[4:]
    if not functions.verify("Merchant", sid.decode("utf8"), signature):
        raise SystemExit("Certificatul este invalid!!!")
    else:
        print("Certificatul este valid!!!")
    # mesajul 3  C->M, PM, PO
    print("Suntem in etapa mesajului 3")
    cardN = "3141592653589793"
    with open("PG\cc.txt") as fd:
        text = fd.read()
    CCode = text
    Amount = "999"
    NC = functions.generate_once()
    CardExp = "12/04"
    PI = {"cardN": cardN, "CCode": CCode, "Sid": sid, "Amount": Amount, "PubKC": pub_k_c, "NC": NC}
    PI_signature = functions.sign("Client", str(PI))
    PM = {"PI": PI, "PI_signature": PI_signature}
    PM = str(PM)
    PM_encrypted_by_KPG = functions.encrypt_asymmetric(PM.encode("utf8"), "PG")
    # print("criptarea este", len(PM_encrypted_by_KPG.hex()), "\n", hex_key)
    # print(bytes.fromhex(hex_key))
    OrderDesc = "Bicicleta, id=123"
    OI = {"OrderDesc": OrderDesc, "Sid": sid, "Amount": Amount}
    OI = str(OI)
    OI_signature = functions.sign("Client", OI)
    PO = {"OI": OI, "OI_signature": OI_signature}
    message3 = {"PM": PM_encrypted_by_KPG.hex(), "PO": PO}
    message3 = str(message3)
    print("mesajul 3 este", message3)
    print("pm hex este", PM_encrypted_by_KPG.hex())
    # message3_encrypted = functions.encrypt_asymmetric(message3.encode("utf8"), "Merchant")
    message3_encrypted = functions.encrypt_symmetric(message3.encode("utf8"), aes)
    print(message3_encrypted)
    print("mesajul decriptat este", unpad(functions.decrypt_symmetric(message3_encrypted, aes), 48))
    print(len(message3_encrypted))
    sck.sendall(message3_encrypted)

    msg = sck.recv(3072)
    print(f"Mesajul pe care l-am primit: {msg}")
    if msg == b"ABORT":
        print("Datele au fost alterate! Se anuleaza tranzactia!")
        raise SystemExit("Date alterate! Oprim tranzactia!")
    msg_decrypted = unpad(functions.decrypt_symmetric(msg, aes), 48)
    msg_decrypted = msg_decrypted.decode("utf8")
    msg_decrypted_json = ast.literal_eval(msg_decrypted)
    signature = msg_decrypted_json['signature']
    signature_ascii = bytes.fromhex(signature)
    data_for_verify = {"resp": msg_decrypted_json['resp'], "sid": msg_decrypted_json['sid'], "amount": Amount, "NC": NC}
    if functions.verify("PG", str(data_for_verify), signature_ascii):
        print("Tranzactia s-a facut cu success!!!")
    else:
        print("Datele au fost alterate")
