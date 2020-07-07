# -*- coding: utf-8 -*-
import socks
from uuid import uuid4
import protocol
import globals
import threading
import pyDH

"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
from protocol import error
import sys
import argparse

#
# Configuration
#
# clients side:
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
BIND_ADDR = '0.0.0.0'
PROXY_PORT = 9050

# Parameter to bind a socket to a device, using SO_BINDTODEVICE
# Only root can set this option
# If the name is an empty string or None, the interface is chosen when
# a routing decision is made
# OUTGOING_INTERFACE = "eth0"
OUTGOING_INTERFACE = ""

OR1_HOST = '127.0.0.1'
OR1_PORT = 9054

#
# SOCKS5 Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'


class ExitStatus:
    """ Manage exit status """

    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def get_params():
    """ command line flags """
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--proxy_mode", help="Proxy mode", action="store_true")
    parser.add_argument("port", help="listening port", type=check_port)
    args = parser.parse_args()

    if args.proxy_mode:
        print("Running as a PROXY")
        return True, args.port
    else:
        print("Running as an ONION ROUTER")
        return False, args.port


def check_port(value):
    ivalue = int(value)
    if ivalue < 1024 or ivalue > 65535:
        raise argparse.ArgumentTypeError("%s is an invalid port number" % value)
    return ivalue


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


def proxy_loop(client_socket, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([client_socket, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    client_socket.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def connection(client_socket):
    """ Function run by a thread """
    client_data = client_socket.recv(BUFSIZE)
    print(f"{threading.get_ident()} Received from client: {client_data}")

    socket_to_or = create_socket()
    proxy_shared_key_negotiation(socket_to_or)

    print(f"{threading.get_ident()} Sending client's data to OR: {client_data}")

    socket_to_or.sendall(client_data)
    print(f"{threading.get_ident()} Entering Proxy loop")
    proxy_loop(client_socket, socket_to_or)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock, port):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f'Bind {port}')
        sock.bind((BIND_ADDR, port))


    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def discover_or():
    return OR1_HOST, OR1_PORT


def proxy_shared_key_negotiation(socket_to_or):
    print(f"{threading.get_ident()} Generating shared key...")
    or1_ip, or1_port = discover_or()
    socket_to_or.connect((or1_ip, or1_port))  # the port is the "next stop" port, not the listening one
    circ_id = uuid4().bytes  # UUIDS generated number -random 16 bytes number
    dh = globals.get_dh_client()  # create an instance of DH
    # sending first CREATE packet
    print(f"{threading.get_ident()} Generating a CREATE packet")
    packet = protocol.create_generating(circ_id, dh)
    socket_to_or.sendall(packet)

    # waiting to receive CONNECTED packet
    received_data = socket_to_or.recv(BUFSIZE)
    protocol.cell_general_packet_parsing(received_data)
    print(f"{threading.get_ident()} Successfully generated a shared key")
    globals.set_shared_key(bytes(globals.circuit_id_to_sharedkey[circ_id], encoding='utf8'))


def main():
    """ Main function """
    banner()
    global proxy_flag
    proxy_flag, listening_port = get_params()  # if TRUE then - proxy, else OR mode
    print(f"starting with parmeters: is_proxy_mode: {proxy_flag}, listening port {listening_port}")
    new_socket = create_socket()
    bind_port(new_socket, listening_port)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)

    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            src_socket, _ = new_socket.accept()  # browser's client socket
            src_socket.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)

        recv_thread = Thread(target=connection, args=(src_socket,))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()