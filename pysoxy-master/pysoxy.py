# -*- coding: utf-8 -*-
import socks
from uuid import uuid4
import protocol
import globals
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
# Constants
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
        print("proxy mode is turned on")
        return True, args.port
    else:
        print("onion router mode is turned on")
        return False, args.port


def check_port(value):
    ivalue = int(value)
    if ivalue < 1024 or ivalue > 65535:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


def logo():
    print(
        """ 
          
         _____       _               _   _      _                      _
        |  _  |     (_)             | \ | |    | |                    | |
        | | | |_ __  _  ___  _ __   |  \| | ___| |___      _____  _ __| | __
        | | | | '_ \| |/ _ \| '_ \  | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
        \ \_/ / | | | | (_) | | | | | |\  |  __/ |_ \ V  V / (_) | |  |   <
         \___/|_| |_|_|\___/|_| |_| \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\ 
         
         
         """)


""" p"""


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
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
                try:
                    data = sock.recv(BUFSIZE)
                    if not data:
                        return
                except ConnectionAbortedError:
                    print("An established connection was aborted by the software in your host machine")
                    pass
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    try:
                        socket_dst.send(data)
                    except ConnectionAbortedError:
                        print("An established connection was aborted by the software in your host machine")
                        pass
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


def request_client(wrapper):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
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


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper)
    # TODO HERE:
    # relay_generating()///

    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'

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
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':  # X'00' succeeded
        proxy_loop(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # | VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
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


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message
    """
    method = subnegotiation_client(wrapper)
    # Server Method selection message
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    return True


def connection(client_socket):
    """ Function run by a thread """
    if not proxy_flag:
        #server_socket.listen(1)
        #try:
         #   (client_socket, client_address) = server_socket.accept()
        #except socket.error:
         #   error()
        data = client_socket.recv(1024)
        # figuring out what is  the packet
        circId, server_pubkey = protocol.cell_general_packet_parsing(data)
        if circId == 0 or server_pubkey == 0:
            error("connection failed")
            return
        packet = protocol.created_generating(circId, server_pubkey)
        print("generated a CREATED packet")
        client_socket.sendall(packet)
        print(f"successfully generated a shared key for circID: {circId},\nthe key: {globals.get_dict(circId)}")
        print("the packet has been sent")

    if subnegotiation(client_socket):
        request(client_socket)



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


# build a hop - CREATE / CREATED protocol functions
def proxy_shared_key_negoteation(client_socket):
    client_socket.connect((OR1_HOST, OR1_PORT))  # the port is the "next stop" port, not the listening one
    print("the proxy client is connected")
    circId = uuid4().bytes  # UUIDS generated number -random 16 bytes number
    dh = globals.get_dh_client()  # create an instance of DH
    # sending first CREATE packet
    print("generating a CREATE packet")
    packet = protocol.create_generating(circId, dh)
    client_socket.sendall(packet)
    print("the packet has been sent")

    received_data = client_socket.recv(1024)
    c, s = protocol.cell_general_packet_parsing(received_data)
    print(f"successfully generated a shared key for circID: {circId}, the pk is {globals.get_dict(circId)}")
"""
    else:

        server_socket.listen(1)
        try:
            (client_socket, client_address) = server_socket.accept()
        except socket.error:
            error()
        data = client_socket.recv(1024)
        # figuring out what is  the packet
        circId, server_pubkey = protocol.cell_general_packet_parsing(data)
        if circId == 0 or server_pubkey == 0:
            error("connection failed")
            return
        packet = protocol.created_generating(circId, server_pubkey)
        print("generated a CREATED packet")
        client_socket.sendall(packet)
        print(f"successfully generated a shared key for circID: {circId},\nthe key: {globals.get_dict(circId)}")
        print("the packet has been sent")

"""
def main():
    """ Main function """
    logo()
    global proxy_flag
    proxy_flag, listening_port = get_params()  # if TRUE then - proxy, else OR mode
    print(f"starting with parameters: is_proxy_mode: {proxy_flag}, listening port {listening_port}")
    new_socket = create_socket()
    bind_port(new_socket, listening_port)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)

    proxy_client = create_socket()
    if proxy_flag:
        # proxy does key exchange in Main Thread
        proxy_shared_key_negoteation(proxy_client)
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
