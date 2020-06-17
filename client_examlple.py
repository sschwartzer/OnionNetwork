import socket
from uuid import uuid4
import globals
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


def main():

    client_socket = socket.socket()
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    circId = uuid4().bytes  # UUIDS generated number -random 16 bytes number
    dh = globals.get_dh_client()   # create an instance of DH

    while True:
        sending_data = input()
        if sending_data == "CREATE":
            print(f"the real circID is {circId}")
            packet = protocol.create_generating(circId, dh)
            client_socket.sendall(packet)
            print("the packet has been sent!")
        else:
            client_socket.sendall(sending_data.encode())

        received_data = client_socket.recv(1024)
        print(f" a recieved packet {received_data}")
        if received_data == "exiting...".encode():
            client_socket.close()
            break
        else:   # received a packet
            c, s = protocol.cell_general_packet_parsing(received_data)
            print(f"we got a shared key! {globals.get_dict(circId)}")



if __name__ == '__main__':
    main()
