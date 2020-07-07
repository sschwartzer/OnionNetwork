import socket
from uuid import uuid4

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import globals
import pyDH
from Crypto.Util.number import long_to_bytes
import protocol
import traceback
BLOCK_SIZE = 32 #bytes
SERVER_HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
SERVER_PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

KEY = b'58d84966532dc1ecde0616a689943f1b6ce4597105c75135c4ad2a8a23d7384d'[0:32]

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

    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    #circId = uuid4().bytes  # UUIDS generated number -random 16 bytes number
    #dh = globals.get_dh_client()   # create an instance of DH

    while True:
        sending_data = input()
        #sending_data = sending_data.encode()
        #sending_data = sending_data.encode()
        """ 
            if sending_data == "CREATE":
            print(f"the real circID is {circId}")
            packet = protocol.create_generating(circId, dh)
        """
        print("encrypting...")
        encrypted_data = encrypt(KEY, sending_data)
        print(f"encrypted data {encrypted_data}")
        client_socket.sendall(encrypted_data)
        print("the packet has been sent!")
        received_data = client_socket.recv(1024)
        print(f" a recieved packet {received_data}")
        print("decrypting...")
        decrypted = decrypt(KEY, received_data)
        print(f"the deccrypted data is {decrypted}")
        if received_data == "exiting...".encode():
            client_socket.close()
            break
        """
        else:
            client_socket.sendall(sending_data.encode())

        received_data = client_socket.recv(1024)
        #print(f" a recieved packet {received_data}")
        if received_data == "exiting...".encode():
            client_socket.close()
            break
        else:   # received a packet
            c, s = protocol.cell_general_packet_parsing(received_data)
            print(f"we got a shared key! {globals.get_dict(circId)}")

        """


if __name__ == '__main__':
    main()
