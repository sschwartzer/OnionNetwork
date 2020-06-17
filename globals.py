import pyDH
global dictionary
dictionary = {}

global dh_client
dh_client = pyDH.DiffieHellman()


def get_dh_client():
    return dh_client


def add(key, value):
    dictionary[key] = value


def get_dict(key):
    return dictionary.get(key)





