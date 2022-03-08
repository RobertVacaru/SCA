import ast
from hashlib import sha512

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def prepare_keys():
    f = open('C:\\Facultate\\facultate-an-3\\SCA\\tema1\\MerchantKey.pem', 'r')
    merchant_key = RSA.import_key(f.read())
    f.close()
    f = open('C:\\Facultate\\facultate-an-3\\SCA\\tema1\\key.pem', 'r')
    client_key = RSA.import_key(f.read())
    f.close()
    f = open('C:\\Facultate\\facultate-an-3\\SCA\\PaymentGateway\\PaymentGatewayKey.pem', 'r')
    pg_key = RSA.import_key(f.read())
    f.close()
    return merchant_key, client_key, pg_key


def preparing_text():
    key = RSA.generate(2048)
    with open("PaymentGatewayKey.pem", "wb") as file:
        file.write(key.exportKey('PEM'))
    file.close()


def sign_rsa(message, key):
    hash = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
    signature = pow(hash, key.d, key.n)
    return signature


def verify_sign_rsa(message, signature, key):
    hash = int.from_bytes(sha512(message.encode()).digest(), byteorder='big')
    hash_signature = pow(signature, key.e, key.n)
    return hash == hash_signature


def encrypt(message, key):
    # encrypt AES key,
    aes_key = get_random_bytes(16)
    aes_encrypted_key = PKCS1_OAEP.new(key).encrypt(aes_key)

    # encrypt message
    aes_cipher = AES.new(aes_key, mode=AES.MODE_ECB)
    cryptotext = aes_cipher.encrypt(pad(message.encode(), 16))

    return cryptotext, aes_encrypted_key


def decrypt(message, key, aes_encrypted_key):
    aes_key = PKCS1_OAEP.new(key).decrypt(aes_encrypted_key)
    aes_cipher = AES.new(aes_key, mode=AES.MODE_ECB)
    decrypted = unpad(aes_cipher.decrypt(message), 16)
    return decrypted


def from_bytes_to_dictionary(dict):
    dict = dict.decode('utf-8')
    dict = ast.literal_eval(dict)
    return dict
