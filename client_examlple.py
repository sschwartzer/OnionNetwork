import socket
import pyDH
from Crypto.Util.number import long_to_bytes
import protocol
import traceback

SERVER_HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
SERVER_PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()

def key_exchange(client_socket):
    d1 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    print("did the first part of handshake {0}\n".format(d1_pubkey))

    try:
        # trying to send the generated public key, and to receive the d2 public key in order
        # to finish the key exchange
        client_socket.send("exchange".encode())
        print("sending the pk\t{0}\n".format(d1_pubkey))
        client_socket.sendall(long_to_bytes(d1_pubkey))
        d2_pubkey = int.from_bytes(client_socket.recv(1024), "big")  # big endian
        print("got the other pk\t{0}\n".format(d2_pubkey))

    except socket.error as err:
        error("key exchange failed", err)

    d1_sharedkey = d1.gen_shared_key(d2_pubkey)  # this is the secret symmetrical key
    return d1_sharedkey


def main():
    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    while True:
        sending_data = input()

        if sending_data == "exchange":
            """
            #first generate the public key
            (public_key, d2) = generate_pubkey()
            client_socket.sendall("exchange".encode())

            #second part
            client_socket.sendall(long_to_bytes(public_key)) #sending....
            server_pubkey = int.from_bytes(client_socket.recv(1024), "big")  # big endian?
            shared_key = generate_shared_key(server_pubkey, d2)
            print("shared key: {0}".format(shared_key))
            continue


        """
            """
        if sending_data == "exchange":
            key = key_exchange(client_socket)
            print("shared key: {0}".format(key))
            continue
                    """

        client_socket.send(sending_data.encode())
        received_data = client_socket.recv(1024).decode()
        if received_data == "exiting...":
            client_socket.close()
            break
        print(received_data)


if __name__ == '__main__':
    main()
