import ast
import json
import pickle
import socket
from random import randrange

from Crypto.PublicKey import RSA

import Util
from Util import encrypt
from Util import decrypt


def get_keys():
    f = open('MerchantKey.pem', 'r')
    rsa_key_m = RSA.import_key(f.read())
    f.close()
    f = open('key.pem', 'r')
    rsa_key = RSA.import_key(f.read())
    f.close()
    return rsa_key, rsa_key_m


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65433  # The port used by the server

merchant_key, client_key, pg_key = Util.prepare_keys()


def Client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        crypto_text, aes = encrypt(str(client_key), merchant_key)
        tuple = {"crypto_text": crypto_text, "aes": aes}
        print(len(str(tuple).encode('utf-8')))
        s.send(str(tuple).encode('utf-8'))
        # Pasul 2
        signature_data = s.recv(8000)
        print(signature_data)
        signature_data = signature_data.decode('utf-8')
        signature_data = ast.literal_eval(signature_data)
        signature_text = signature_data["criptotext"]
        aes_signature = signature_data["aes"]
        signature_tuple = decrypt(signature_text, client_key, aes_signature)
        signature_tuple = json.loads(signature_tuple.decode('utf-8'))
        sid, signature_sid = signature_tuple["sid"], signature_tuple["signature_sid"]
        print(signature_sid)
        value = Util.verify_sign_rsa(str(sid).encode('utf-8'), signature_sid, merchant_key)
        if value:
            print('Merge')
        # Pasul 3
        ccode = randrange(1000, 9999)
        nc = randrange(1, 1000)
        payment_info = {"card_number": '12345', "card_expiration": '12/25', "ccode": ccode, "sid": sid, "amount": 100,
                        "pubkc": client_key, "nc": nc, "M": 'Magazin'}
        tuple = {"order_description": 'blabla', "sid": sid, "amount": 80, "nc": nc}
        payment_order = {"order_description": 'blabla', "sid": sid, "amount": 80, "nc": nc,
                         "signature_client": Util.sign_rsa(str(tuple).encode('utf-8'), client_key)}
        pm = {"pi": payment_info, "sig_pi": Util.sign_rsa(str(payment_info).encode('utf-8'), client_key)}
        criptotext, aes = encrypt(str(pm), pg_key)
        tuple_pm = {"criptotext_pm": criptotext, "aes": aes}
        payment_tuple = {"tuple_pm": tuple_pm, "po": payment_order}
        criptotext, aes = encrypt(str(payment_tuple), merchant_key)
        payment_to_merchant = {"criptotext_m": criptotext, "aes": aes}
        s.send(str(payment_to_merchant).encode('utf-8'))


Client()
