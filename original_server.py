import socket
import pyDH
import traceback
from Crypto.Util.number import long_to_bytes

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()

"""
def key_exchange(client_socket):
    d2 = pyDH.DiffieHellman()
    d2_pubkey = d2.gen_public_key()  # an integer
    try:
        # trying to send the generated public key, and to recive the d2 public key in order
        # to finish the key exchange
        d1_pubkey = int.from_bytes(client_socket.recv(1024), "big")  # big endian?
        client_socket.sendall(long_to_bytes(d2_pubkey))  # convert interger to bytes
    except socket.error as err:
        error("key exchange failed", err)
    d2_sharedkey = d2.gen_shared_key(d1_pubkey)  # this is the secret symmetrical key
    return d2_sharedkey

"""
def main():
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    (client_socket, client_address) = server_socket.accept()

    while True:
        data = client_socket.recv(1024).decode()
        print(data)
        if data == "exit".lower():
            client_socket.send("exiting...".encode())
            client_socket.close()
            server_socket.close()
            break
        client_socket.send(input().encode())
        """
            # if data == "exchange":
            
            #first generate the public key
            (public_key, d1) = generate_pubkey()
            client_pubkey = int.from_bytes(client_socket.recv(1024), "big")  # big endian?
            client_socket.sendall(long_to_bytes(public_key))  # convert interger to bytes
            #second part
            shared_key = generate_shared_key(client_pubkey, d1)
            print("shared key: {0}".format(shared_key))
            continue
        '''
        """
        #if data == "exchange":
"""
            key = key_exchange(client_socket)
            print("shared key: {0}".format(key))
            continue
 
        """


if __name__ == '__main__':
    main()
