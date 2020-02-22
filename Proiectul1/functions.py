import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import shutil
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_key(path):
    private_key = RSA.generate(4096)
    public_key = private_key.publickey()
    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()
    with open('private_pem.pem', 'w') as fd:
        fd.write(private_pem)
    with open('public_pem.pem', 'w') as fd:
        fd.write(public_pem)
    shutil.move("private_pem.pem", path)
    shutil.move("public_pem.pem", path)


def sign(who, data):
    private_key = RSA.import_key(open(who + '/' + "private_pem.pem", 'r').read())
    h = SHA256.new(data.encode("utf8"))
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def signC(key, data):
    h = hashlib.md5(data.encode("utf8"))
    return encrypt_symmetric(h.hexdigest().encode("utf8"), key)


def verify(who, data, signature):
    public_key = RSA.import_key(open(who + '/' + "public_pem.pem", 'r').read())
    h = SHA256.new(data.encode("utf8"))
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        print(e)
        return False


def generate_symmetric_key():
    # .hex()
    return os.urandom(24)


def generate_once():
    return os.urandom(10)


def encrypt_asymmetric(data, key):
    public_key = RSA.import_key(open(key + "/" + "public_pem.pem", 'r').read())
    cipher_text = b''
    cipher = PKCS1_OAEP.new(key=public_key)
    try:
        cipher_text = cipher.encrypt(data)
    except (ValueError, TypeError) as e:
        print("Am intrat in except pt. ca lungimea textului de criptat este prea mare, impart textul in chunk-uri si criptez ", e)
        for i in range(0, len(data), 470):
            cipher_text += cipher.encrypt(data[i:i + 470])
        return cipher_text
    return cipher_text


def decrypt_asymmetric(data, key):
    private_key = RSA.import_key(open(key + "/" + "private_pem.pem", 'r').read())
    decrypt = PKCS1_OAEP.new(key=private_key)
    decrypted_message = b''
    try:
        decrypted_message = decrypt.decrypt(data)
    except (ValueError, TypeError) as e:
        print("Am intrat in except pt. ca lungimea textului de decriptat este prea mare, impart ciphertext-ul in chunk-uri si decriptez  ", e)
        for i in range(0, len(data), 512):
            decrypted_message += decrypt.decrypt(data[i:i + 512])
    return decrypted_message


def test():
    print("sunt in test")
    s = ''
    for i in range(1089):
        s += "1"
    sc = encrypt_asymmetric(s.encode("utf8"), "Merchant")
    print(sc)
    print(decrypt_asymmetric(sc, "Merchant"))


def encrypt_symmetric(data, key):
    print(len(key))
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(pad(data, 24))
    return msg


def decrypt_symmetric(data, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(data)
