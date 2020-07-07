import socket
import pyDH
import traceback

from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
import globals
import protocol
from Crypto.Cipher import AES

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
KEY = b'58d84966532dc1ecde0616a689943f1b6ce4597105c75135c4ad2a8a23d7384d'[0:32] #256 bit
BLOCK_SIZE = 32

def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def encrypt(key, msg):
    # using AES cipher, EBC mode
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(msg, BLOCK_SIZE))


def decrypt(key, decrypted_msg):
    # using AES cipher, EBC mode
    decipher = AES.new(key, AES.MODE_ECB)
    return unpad(decipher.decrypt(decrypted_msg), BLOCK_SIZE)

def main():
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    (client_socket, client_address) = server_socket.accept()
    print(len(KEY))
    while True:

        data = client_socket.recv(1024)
        print(f"decrypting the data {data}")
        decrypted = decrypt(KEY, data)
        print(f"the decrypted data is {decrypted}")
        if decrypted == ("exit".lower()).encode():
            client_socket.send("exiting...".encode())
            client_socket.close()
            server_socket.close()
            break

        """        
        # figuring out what is  the packet
        circId, server_pubkey = protocol.cell_general_packet_parsing(data)
        if circId == 0 or server_pubkey == 0:
            error("connection failed")
            break
        print(f"circID: {circId}")
        print(f"we got a shared key! {globals.get_dict(circId)}")
        """
        sending_data = input()
        #sending_data = sending_data.encode()

        print("encrypting...")
        encrypted = encrypt(KEY, sending_data)
        print(f"the encrypted data {encrypted}")
        client_socket.sendall(encrypted)

        """
        if sending_data == "CREATED":
            packet = protocol.created_generating(circId, server_pubkey)
            #print(f"CREATED packet: {packet}")
            client_socket.sendall(packet)
        else:
            client_socket.send(sending_data.encode())
        """


if __name__ == '__main__':
    main()
