import pyDH
import threading

global sock_to_streamid
sock_to_streamid = {}

global streamid_to_sock
streamid_to_sock = {}

shared_key = ''


def set_shared_key(key):
    global shared_key
    shared_key = key[0:32]
    print(f"{threading.get_ident()} Shared key {shared_key}")


def get_shared_key():
    return shared_key


global dh_client
dh_client = pyDH.DiffieHellman()


def get_dh_client():
    return dh_client


global circuit_id_to_sharedkey
circuit_id_to_sharedkey = {}

def add_to_circuit_id(key, value):
    circuit_id_to_sharedkey[key] = value

'''
def get_dict(key):
    return circuit_id_to_sharedkey.get(key)
'''


def banner():
    print(
        """ 

         _____       _               _   _      _                      _
        |  _  |     (_)             | \ | |    | |                    | |
        | | | |_ __  _  ___  _ __   |  \| | ___| |___      _____  _ __| | __
        | | | | '_ \| |/ _ \| '_ \  | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
        \ \_/ / | | | | (_) | | | | | |\  |  __/ |_ \ V  V / (_) | |  |   <
         \___/|_| |_|_|\___/|_| |_| \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\ 


         """)

