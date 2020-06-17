import socket
import pyDH
import traceback
from Crypto.Util.number import long_to_bytes
import globals
import protocol

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def main():
    server_socket = socket.socket()
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    (client_socket, client_address) = server_socket.accept()

    while True:

        data = client_socket.recv(1024)

        if data == ("exit".lower()).encode():
            client_socket.send("exiting...".encode())
            client_socket.close()
            server_socket.close()
            break

        # figuring out what is  the packet
        circId, server_pubkey = protocol.cell_general_packet_parsing(data)
        if circId == 0 or server_pubkey == 0:
            error("connection failed")
            break
        print(f"circID: {circId}")
        sending_data = input()
        if sending_data == "CREATED":
            packet = protocol.created_generating(circId, server_pubkey)
            print(f"CREATED packet: {packet}")
            client_socket.sendall(packet)
        else:
            client_socket.send(sending_data.encode())



if __name__ == '__main__':
    main()
