import threading
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ENCRYPT_DISABLED = True
CYPHER_BLOCK_SIZE_BYTES = 32


class Enc(object):
    def __init__(self, key):
        self.lock = threading.Lock()
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, msg):
        if ENCRYPT_DISABLED:
            return msg
        self.lock.acquire()
        try:
            # using AES cipher, EBC mode
            # print(f"Original {msg}\n encrypt msg {(pad(msg, CYPHER_BLOCK_SIZE_BYTES))}")
            return self.cipher.encrypt(pad(msg, CYPHER_BLOCK_SIZE_BYTES))
        finally:
            self.lock.release()

    def decrypt(self, msg):
        if ENCRYPT_DISABLED:
            return msg
        self.lock.acquire()
        decrypted = b''
        cleartext = b''
        # using AES cipher, EBC mode
        try:
            decrypted = self.cipher.decrypt(msg)
            cleartext = unpad(decrypted, CYPHER_BLOCK_SIZE_BYTES)
            if len(msg) == 1024:
                print("AAAAAAA success!")
        except:
            print(f"{threading.get_ident()} AAAAAAAAAA key {self.key}, len {len(msg)}, msg {msg}")
        finally:
            self.lock.release()
            return cleartext

'''
class Enc(object):
    def __init__(self, key):
        self.lock = threading.Lock()
        self.key = key
        self.cipher = ChaCha20.new(key=key, nonce=get_random_bytes(12))

    def encrypt(self, msg):
        if ENCRYPT_DISABLED:
            return msg
        self.lock.acquire()
        try:
            ciphertext = self.cipher.encrypt(msg)
            result = self.cipher.nonce + ciphertext
            return result

        finally:
            self.lock.release()

    def decrypt(self, msg):
        if ENCRYPT_DISABLED:
            return msg
        self.lock.acquire()
        try:
            # nonce = msg[0:12]
            plaintext = self.cipher.decrypt(msg[12:])
            return plaintext
        except:
            print(f"{threading.get_ident()} AAAAAAAAAA key {self.key}, len {len(msg)}, msg {msg}")
        finally:
            self.lock.release()
'''