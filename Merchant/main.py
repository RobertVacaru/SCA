import ast
import base64
import json
import pickle
import socket

from Crypto.PublicKey import RSA
import Util

HOST = "127.0.0.1"
PORT = 65433
HOST_PG = "127.0.1.1"
PORT_PG = 65434

merchant_key, client_key, pg_key = Util.prepare_keys()


def Merchant():
    sid = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            sid += 1
            print(f"Connected by {addr}")
            while True:
                tuple = conn.recv(18000)
                if not tuple:
                    break

                #         Pasul 1
                print(len(tuple))
                tuple = Util.from_bytes_to_dictionary(tuple)
                pubkc = tuple["crypto_text"]
                aes = tuple["aes"]
                msg_recv = Util.decrypt(pubkc, merchant_key, aes)
                #          Pasul2
                signature_sid = Util.sign_rsa(str(sid), merchant_key)
                signature_tuple = {"sid": sid, "signature_sid": signature_sid}
                criptotext, aes = Util.encrypt(json.dumps(signature_tuple), client_key)
                encrypted_signature_tuple = {"criptotext": criptotext, "aes": aes}
                encrypted_signature_tuple = str(encrypted_signature_tuple).encode('utf-8')
                conn.sendall(encrypted_signature_tuple)
                # Pasul 3
                payment_from_client = conn.recv(100000)
                payment_from_client = Util.from_bytes_to_dictionary(payment_from_client)
                payment_m = payment_from_client["criptotext_m"]
                aes = payment_from_client["aes"]
                payment_tuple = Util.decrypt(payment_m, merchant_key, aes)
                payment_tuple = Util.from_bytes_to_dictionary(payment_tuple)
                tuple_pm = payment_tuple["tuple_pm"]
                payment_order = payment_tuple["po"]
                print(tuple_pm)
                #   Pasul 4
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sck:
                    sck.connect((HOST_PG, PORT_PG))
                    # sck.sendall(str(tuple_pm).encode('utf-8'))
                    amount = payment_order["amount"]
                    tuple_to_sign = {"sid": sid, "pubkc": pubkc, "amount": amount}
                    message_to_pg = {"pm": tuple_pm, "sign": Util.sign_rsa(str(tuple_to_sign), merchant_key)}
                    cryptotext, aes = Util.encrypt(str(message_to_pg), pg_key)
                    message_to_pg = {"cryptotext": cryptotext, "aes": aes}
                    sck.sendall(str(message_to_pg).encode('utf-8'))


Merchant()
