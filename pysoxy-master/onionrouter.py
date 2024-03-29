# -*- coding: utf-8 -*-

import protocol
import globals
import threading

"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack
# System
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
from protocol import error
from encryption import Enc
import sys
import argparse

#
# Configuration
#
# clients side:
MAX_THREADS = 200
BUFSIZE = 4096
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


def or_loop(socket_src, socket_dst, encryptor):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
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
                    # socket from DST - needed to be sent to proxy
                    # needed to be encrypted

                    # print(f"{threading.get_ident()}, encrypting with key {key}")
                    encrypted_data = encryptor.encrypt(data)
                    print(f"encrypted data len {len(encrypted_data)}")
                    #print(f"{threading.get_ident()}, key {encryptor.key}, original {data}\nencrypted msg {encrypted_data}")
                    socket_src.send(encrypted_data)
                else:
                    # socket from proxy - needed to be sent to DST
                    # needed to be decrypted
                    print(f"{threading.get_ident()}, decrypting with key {encryptor.key}")
                    decrypted_data = encryptor.decrypt(data)
                    # print(f"{threading.get_ident()}, key {key}, encrypted {data}\ndecrypted msg {decrypted_data}")

                    socket_dst.send(decrypted_data)
        except ConnectionAbortedError:
            return
        except ConnectionResetError:
            return
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


def request_client(wrapper, encryptor):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        encrypted_request = wrapper.recv(BUFSIZE)
        s5_request = encryptor.decrypt(encrypted_request)
    except ConnectionAbortedError:
        return
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        # error()
        return False
    # Check VER, CMD and RSV
    print(f"{threading.get_ident()} Received SOCKS packet {s5_request}")

    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        # TODO understands the line below:
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        """
           the address field contains a fully-qualified domain name.  The first
            octet of the address field contains the number of octets of name that
            follow, there is no terminating NUL octet.
        """
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False

    # trying to translate the ip to url
    try:
        print(f"dst ip address: {dst_addr}, dst url: {socket.gethostbyaddr(dst_addr)[0]}, dst port: {dst_port}")
    except:
        print(f"dst ip address: {dst_addr}, dst port: {dst_port}")

    return (dst_addr, dst_port)


def request(wrapper, encryptor):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper, encryptor)
    if not dst:
        return False
    # TODO HERE:
    # relay_generating()///

    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    print(f"{threading.get_ident()} Connecting to Web target {dst}")
    # proxy tries to establish connection with the destination
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'  # X'01' general SOCKS server failure
    else:
        rep = b'\x00'  # X'00' succeeded
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        encrypted_reply = encryptor.encrypt(reply)
        wrapper.sendall(encrypted_reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':  # X'00' succeeded
        print(f"{threading.get_ident()} Entering loop with key {encryptor.key}")
        or_loop(wrapper, socket_dst, encryptor)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper, encryptor):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # | VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        encrypted_data = wrapper.recv(BUFSIZE)
        identification_packet = encryptor.decrypt(encrypted_data)

    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_NOAUTH):
            return M_NOAUTH  # X'00' NO AUTHENTICATION REQUIRED
    return M_NOTAVAILABLE  # X'FF' NO ACCEPTABLE METHODS


def subnegotiation(wrapper, encryptor):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper, encryptor)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        encrypted_reply = encryptor.encrypt(reply)
        wrapper.sendall(encrypted_reply)
        print(f"{threading.get_ident()} Subnegotiation complete, returning response {reply}")
    except socket.error:
        error()
        return False
    return True


def connection(proxy_socket):
    """ Function run by a thread """
    shared_key = connection_or(proxy_socket)
    encryptor = Enc(shared_key)
    if subnegotiation(proxy_socket, encryptor):
        request(proxy_socket, encryptor)


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


def connection_or(proxy_socket):
    data = proxy_socket.recv(BUFSIZE)
    # figuring out what is  the packet
    print(f"{threading.get_ident()} Received First request: {data}")
    circ_id, server_pubkey, key = protocol.cell_general_packet_parsing(data)

    if circ_id == 0 or server_pubkey == 0:
        error(f"{threading.get_ident()} ERROR Connection failed from {proxy_socket}")
        return

    print(f"{threading.get_ident()} Generating shared key...")
    packet = protocol.created_generating(circ_id, server_pubkey)
    proxy_socket.sendall(packet)
    print(f"{threading.get_ident()} Sent a CREATED packet")
    #globals.set_shared_key(bytes(globals.circuit_id_to_sharedkey[circ_id], encoding='utf8'))
    #key = bytes(globals.circuit_id_to_sharedkey[circ_id], encoding='utf8')[0:32]
    return key

def main():
    """ Main function """
    globals.banner()
    global proxy_flag
    proxy_flag, listening_port = get_params()  # if TRUE then - proxy, else OR mode
    print(f"starting with parameters: is_proxy_mode: {proxy_flag}, listening port {listening_port}")
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
