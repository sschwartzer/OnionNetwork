from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ENCRYPT_DISABLED = True


def encrypt(key, msg):
    if ENCRYPT_DISABLED:
        return msg;
    # using AES cipher, EBC mode
    cipher = AES.new(key, AES.MODE_ECB)
    print(f"\nencrypt msg size {len(pad(msg, CYPHER_BLOCK_SIZE_BYTES))}")
    return cipher.encrypt(pad(msg, CYPHER_BLOCK_SIZE_BYTES))


def decrypt(key, msg):
    if ENCRYPT_DISABLED:
        return msg
    # using AES cipher, EBC mode
    decipher = AES.new(key, AES.MODE_ECB)
    print(f"\n in decrypt, msg zise {len(msg)}")
    return unpad(decipher.decrypt(msg), CYPHER_BLOCK_SIZE_BYTES)
