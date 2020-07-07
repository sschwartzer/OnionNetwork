# pysoxy-master
# Latest version

# -*- coding: utf-8 -*-

from uuid import uuid4
import protocol
import globals
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
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
BUFSIZE = 4096
TIMEOUT_SOCKET = 5
BIND_ADDR = '0.0.0.0'
PROXY_PORT = 9050
DATA_PREFIX = b'\xff'
PROTO_PREFIX = b'\xfe'
CYPHER_BLOCK_SIZE_BYTES = 32
ENCRYPT_DISABLED = True
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


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def or_loop(socket_src):
    """ Wait for network activity """
    all_target_sockets = [socket_src]
    while not EXIT.get_status():
        try:
            if globals.sock_to_streamid.keys():
                all_target_sockets.extend(list(globals.sock_to_streamid.keys()))
                # print(f"XXX Got {len(all_target_sockets)} sockets:\n {all_target_sockets}")
            reader, _, _ = select.select(all_target_sockets, [], [], 1)
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
                if sock is socket_src:
                    # sock is from proxy
                    print(f"Received data from PROXY, size {len(data)}")
                    # passing the data to dst
                    decrypted_data = decrypt(globals.get_shared_key(), data)
                    flag, stream_id, updated_data = unwrap_data(decrypted_data)
                    print(f"YYY decrypted: {decrypted_data}\n updated: {updated_data}")
                    init_rq_to_target = is_init_to_dst_required(flag)

                    # if true, this it a part of SOCKS5 negotiation
                    # need to open connection to the requested destination, and return SOCKS5 ack
                    if init_rq_to_target:
                        if stream_id in globals.streamid_to_sock:   # should be NONE
                            print(f"WARNING: found existing stream_id {stream_id} on the new connection!!!")

                        # try reach the dst - create dst_socket, add to dictionary
                        # send response to proxy
                        print(f"HANDLING data: {updated_data}")
                        handle_socks_rq_by_or(updated_data, sock, stream_id)
                        #recv_thread = Thread(target=handle_socks_rq_by_or, args=(updated_data, sock, stream_id))
                        #recv_thread.start()
                    else:
                        # send data to the existing socket (find it in the dictionary)
                        if stream_id not in globals.streamid_to_sock:   # should be not-null
                            print(f"ERROR: NOT found existing socket for {stream_id} on the existing connection!!!")
                            continue

                        socket_dst = globals.streamid_to_sock[stream_id]
                        sent_bytes = socket_dst.send(updated_data)
                        if sent_bytes == len(updated_data):
                            print(f"Data sent successfully")
                        else:
                            print(f"WARNING: Sent {sent_bytes} of the {len(updated_data)} required")
                else:
                    # sock is from dst
                    print(f"Received data from DST, size {len(data)}")
                    # passing the data to src - proxy

                    if sock not in globals.sock_to_streamid:
                        print(f"ERROR: NOT found stream_id {stream_id} on the existing connection!!! sock: {sock}")
                        continue

                    stream_id = globals.sock_to_streamid[sock]
                    encrypted_data = encrypt(globals.get_shared_key(), wrap_data(False, stream_id, data))
                    print(f"Encrypted data len {len(encrypted_data)}")

                    sent_bytes = socket_src.send(encrypted_data)
                    if sent_bytes == len(encrypted_data):
                        print(f"Data sent successfully")
                    else:
                        print(f"WARNING: Sent {sent_bytes} of the {len(encrypted_data)} required")

        except socket.error as err:
            error("Loop failed", err)
            return


def proxy_loop(socket_src, socket_dst):  # socket_src  - browser's server; socket_dst - or1's client
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
                    # the sock socket from the destination; thus, needs to be decrypted
                    decrypted_data = decrypt(globals.get_shared_key(), data)
                    _, stream_id, prefixless = unwrap_data(decrypted_data)
                    #print(f"{threading.get_ident()} Received data from OR. data: {prefixless}")
                    #print(f"{threading.get_ident()} CHECK {socket_src} STREAM {stream_id}")
                    print(f"LOOP STREAM: {stream_id} BROWSER_SOCKET: {socket_src}")

                    target_sock = globals.streamid_to_sock[stream_id]
                    sent_sz = target_sock.send(prefixless)
                    #sent_sz = socket_src.send(prefixless)
                    if sent_sz == len(prefixless):
                        print(f"{threading.get_ident()} Successfully sent data to client")
                    else:
                        print(f"{threading.get_ident()} WARNING: sent {sent_sz} bytes of total {len(prefixless)}")

                else:
                    # the sock socket from the source; thus, needs to be encrypted
                    #TODO: CHECK ME!!!
                    proxy_rq = extract_dst_data(sock)
                    if proxy_rq:
                        print(f"ZZZ reached here with proxy request: {proxy_rq}")
                        stream_id = uuid4().bytes
                        globals.sock_to_streamid[sock] = stream_id
                        globals.streamid_to_sock[stream_id] = sock # needed????
                        rq = wrap_data(True, stream_id, proxy_rq)
                    else:
                        if sock not in globals.sock_to_streamid:
                            print(f"ERROR: NOT found stream_id {stream_id} on the existing connection!!! sock: {sock}")
                            continue
                        stream_id = globals.sock_to_streamid[sock]
                        rq = wrap_data(False, stream_id, data)

                    print(f"{threading.get_ident()} Received data from client, stream_id {stream_id}, encrypting...")
                    encrypted_data = encrypt(globals.get_shared_key(), rq)

                    sent_sz = socket_dst.send(encrypted_data)
                    if sent_sz == len(encrypted_data):
                        print(f"{threading.get_ident()} Successfully sent data to OR")
                    else:
                        print(f"{threading.get_ident()} WARNING: sent {sent_sz} bytes of total {len(encrypted_data)}")
        except socket.error as err:
            print(f"SOCK: {sock}")
            error("Loop failed", err)
            return



def is_init_to_dst_required(flag):
    # returns a tuple- first part is the updated data, second part is a flag whether
    # should build a response packet to browser or not
    #if flag == int.from_bytes(DATA_PREFIX, "big"):
    if flag == DATA_PREFIX:
        print(f"Received DATA packet: {flag}....")
        return False
    #elif flag == int.from_bytes(PROTO_PREFIX, "big"):
    elif flag == PROTO_PREFIX:
        print(f"Received SOCKS5 packet: {flag}....")
        # there's no prefix - the browser is waiting for a reply
        return True
    else:
        print(f"ERROR: {flag}")


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


def extract_dst_data(wrapper):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
        if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
        ):
            #print(f"ERROR: Received unexpected data from browser: {s5_request}, socket{wrapper}")
            return
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    return s5_request


def dst_packet_parsing(s5_request):
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:8])
        # TODO understands the line below:
        dst_port = unpack('>H', s5_request[8:10])[0]
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


def handle_socks_rq_by_or(rq, or_server_socket, stream_id):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = dst_packet_parsing(rq)
    print(f"Got the final dst {dst}")
    '''
    # TODO HERE:
    # relay_generating()///
    '''

    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'

    # tries to establish connection with the destination
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'  # X'01' general SOCKS server failure
    else:
        rep = b'\x00'  # X'00' succeeded
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    encrypted_reply = encrypt(globals.get_shared_key(), wrap_data(True, stream_id, reply))
    try:
        or_server_socket.send(encrypted_reply)
        print(f"Client's SOCKS5 reply was sent {reply}")
    except socket.error:
        #if or_server_socket != 0:
        #    or_server_socket.close()
        return
    if rep == b'\x00':  # X'00' succeeded
        # id succeeded, add to dict
        globals.streamid_to_sock[stream_id] = socket_dst
        globals.sock_to_streamid[socket_dst] = stream_id
#    if or_server_socket != 0:
#        or_server_socket.close()

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


def connection(proxy_server_socket, proxy_client_socket):
    """ Function run by a thread """
    print(f"Thread num {threading.get_ident()}, socket: {proxy_server_socket}")
    if proxy_flag:
        connection_proxy(proxy_server_socket, proxy_client_socket)
        # return s5_request
    else:
        connection_or(proxy_server_socket)


def connection_or(or1_server_socket):
    data = or1_server_socket.recv(BUFSIZE)
    # figuring out what is  the packet
    print("Received First request")
    circId, server_pubkey = protocol.cell_general_packet_parsing(data)

    if circId == 0 or server_pubkey == 0:
        error(f"ERROR Connection failed from {or1_server_socket}")
        return

    print("Generating shared key...")
    packet = protocol.created_generating(circId, server_pubkey)
    or1_server_socket.sendall(packet)
    print("Sent a CREATED packet")
    globals.set_shared_key(bytes(globals.circuit_id_to_sharedkey[circId], encoding='utf8'))

    # waiting for Proxy to send us the actual connect request with target
    rq_encrypted = or1_server_socket.recv(BUFSIZE)
    rq = decrypt(globals.get_shared_key(), rq_encrypted)
    print(f"Received request: {rq}")

    #_, stream_id, unwrapped = unwrap_data(rq)
    #handle_socks_rq_by_or(unwrapped, or1_server_socket, stream_id)

    or_loop(or1_server_socket)

'''
    should_enter_or_loop, socket_dst, dst = handle_socks_rq_by_or(rq, or1_server_socket)
    if should_enter_or_loop:
        print("Entering OR loop")
        or_loop(or1_server_socket, socket_dst, dst)
'''


def connection_proxy(proxy_server_socket, proxy_client_socket):
    if subnegotiation(proxy_server_socket):
        stream_id = uuid4().bytes
        globals.sock_to_streamid[proxy_server_socket] = stream_id
        globals.streamid_to_sock[stream_id] = proxy_server_socket # needed ?????
        #print(f"PROXY STREAM: {stream_id} BROWSER_SOCKET: {proxy_server_socket}")
        # waiting for "client request details" (SOCKS5 request from browser)
        s5_request = extract_dst_data(proxy_server_socket)
        #s5_request = proxy_server_socket.recv(BUFSIZE)
        if not s5_request:
            print("ERROR, bad data received")

        rq = wrap_data(True, stream_id, s5_request)
        encrypted_rq = encrypt(globals.get_shared_key(), rq)

        print(f"{threading.get_ident()} sending the request {rq}, to OR {proxy_client_socket}")
        proxy_client_socket.sendall(encrypted_rq)

        proxy_loop(proxy_server_socket, proxy_client_socket)
    else:
        print("ERROR, not SOCKS5 protocol")


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


def proxy_shared_key_negotiation(client_socket):
    print("Generating shared key...")
    or1_ip, or1_port = discover_or()
    client_socket.connect((or1_ip, or1_port))  # the port is the "next stop" port, not the listening one
    circId = uuid4().bytes  # UUIDS generated number -random 16 bytes number
    dh = globals.get_dh_client()  # create an instance of DH
    # sending first CREATE packet
    print("Generating a CREATE packet")
    packet = protocol.create_generating(circId, dh)
    client_socket.sendall(packet)

    # waiting to receive CONNECTED packet
    received_data = client_socket.recv(BUFSIZE)
    protocol.cell_general_packet_parsing(received_data)
    print("Successfully generated a shared key")
    globals.set_shared_key(bytes(globals.circuit_id_to_sharedkey[circId], encoding='utf8'))

    return client_socket


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

def wrap_data(is_socks5, stream_id, msg):
    if is_socks5:
        return PROTO_PREFIX + stream_id + msg
    else:
        return DATA_PREFIX + stream_id + msg

def unwrap_data(msg):
    # 1 byte - FLAG (PROTO / DATA)
    # next 16 bytes - streamID
    # last - data
    return msg[0:1],msg[1:17],msg[17:]


def main():
    """ Main function """
    banner()
    global proxy_flag
    proxy_flag, listening_port = get_params()  # if TRUE then - proxy, else OR mode
    print(f"Starting with parameters: is_proxy_mode: {proxy_flag}, listening port {listening_port}")
    new_socket = create_socket()
    bind_port(new_socket, listening_port)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)

    proxy_client = create_socket()
    if proxy_flag:
        # proxy does key exchange in Main Thread
        proxy_shared_key_negotiation(proxy_client)
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            proxy_server_socket, _ = new_socket.accept()  # browser's client socket
            proxy_server_socket.setblocking(1)  # if or - src.socket IS OR1 SERVER
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)

        recv_thread = Thread(target=connection, args=(proxy_server_socket, proxy_client,))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
