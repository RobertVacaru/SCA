import ast
import codecs
import json
import socket
import Util

HOST_PG = "127.0.1.1"
PORT_PG = 65434
merchant_key, client_key, pg_key = Util.prepare_keys()


def unpack_pm(pm):
    pm_cryptotext = Util.decrypt(pm["criptotext_pm"], client_key, pm["aes"])
    pm_cryptotext = Util.from_bytes_to_dictionary(pm_cryptotext)
    pi = pm_cryptotext["pi"]
    sign_pi = pm_cryptotext["sig_pi"]
    return pi, sign_pi


def eval_code(code):
    parsed = ast.parse(code, mode='eval')
    fixed = ast.fix_missing_locations(parsed)
    compiled = compile(fixed, '<string>', 'eval')
    return compiled


def split(string):
    s = string.replace("{", "").replace("}", "").split(",")

    dictionary = {}

    for i in s:
        dictionary[i.split(":")[0].strip('\'').replace("\"", "")] = i.split(":")[1].strip('"\'')
    return dictionary


def PaymentGateway():
    response = 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST_PG, PORT_PG))
        s.listen()
        conn, addr = s.accept()
        with conn:
            while True:
                # Pasul 4
                message = conn.recv(30000)
                message = Util.from_bytes_to_dictionary(message)
                tuple_pm = message["cryptotext"]
                aes = message["aes"]
                tuple_pm = Util.decrypt(tuple_pm, pg_key, aes)
                tuple_pm = Util.from_bytes_to_dictionary(tuple_pm)
                pm = tuple_pm["pm"]
                sign_tuple = tuple_pm["sign"]
                c = pm["criptotext_pm"]
                aes = pm["aes"]
                pm = Util.decrypt(c, pg_key, aes)
                print(ast.literal_eval(pm.decode()))
                # pm_cryptotext = Util.from_bytes_to_dictionary(pm_cryptotext)
                # pi = pm_cryptotext["pi"]
                # sign_pi = pm_cryptotext["sig_pi"]
                # if Util.verify_sign_rsa(pi, sign_pi, client_key):
                # continue
                # else:
                # response = 0
            # print(pm)
            # break


PaymentGateway()
