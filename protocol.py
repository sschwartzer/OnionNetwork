import traceback
import pyDH
from Crypto.Util.number import long_to_bytes
import globals
import threading

CREATE = 1
CREATED = 2


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print(f"{threading.get_ident()} {msg} - Code: {str(err[0])}, Message: {err[1]}")
    else:
        traceback.print_exc()


def cell_general_packet_parsing(packet):  # dictionary
    """
    generating the Cell packet by the protocol

      +-------+-----+-------+---------+
      |CircID | CMD |  LEN  | Payload |
      +-------+-----+-------+---------+
    """
    circID = packet[0:16]  # 16 bytes
    cmd = int.from_bytes(packet[16:17], "big")  # 1 byte

    len = int.from_bytes(packet[17:21], "big")  # 4 bytes
    payload = packet[21:21+ len + 1]
    if cmd == CREATE:  # create function
        print(f"{threading.get_ident()} Received CREATE packet")
        server_pubkey, shared_key = create_parsing(payload)
        globals.add_to_circuit_id(circID, shared_key)
        return circID, server_pubkey

    elif cmd == CREATED:  # created function
        print(f"{threading.get_ident()} Received CREATED packet")
        shared_key = created_parsing(payload)  # shared key
        globals.add_to_circuit_id(circID, shared_key)
        return 0, 0


def create_generating(circID, dh):
    """
    generating a create packet by the protocol

      +-------+-----+-------+---------+
      |CircID | CMD |  LEN  | HDATA   |
      +-------+-----+-------+---------+
    """
    # assuming the circID is BINARY
    cmd = b'\x01'  # 1 - CREATE command
    try:
        dh_pubkey = dh.gen_public_key()  # a long
    except error:
        error(f"{threading.get_ident()} Generating public key failed")
        return
    print(f"{threading.get_ident()} Generated a public key")
    hdata = long_to_bytes(dh_pubkey)
    dlen = (len(hdata)).to_bytes(4, byteorder='big')
    packet = circID + cmd + dlen + hdata
    return packet


def create_parsing(hdata):
    """
    the function parses the packet in the format of the protocol
      +-------+
      | HDATA |
      +-------+
    """
    # first generate the first part of DH handshake
    dh_server = get_dh_server_reference()

    try:
        server_pubkey = dh_server.gen_public_key()
    except error:
        error("Generating public key failed")
        return
    # hdata is a byte encoded client's public key
    client_pubkey = int.from_bytes(hdata, "big")
    try:
        shared_key = dh_server.gen_shared_key(client_pubkey)
    except error:
        error("Generating public key failed")
        return
    return server_pubkey, shared_key


def get_dh_server_reference():
    return pyDH.DiffieHellman()
    # somehow


def created_generating(circID, server_pubkey):
    # assuming the circID is in BINARY
    """
    generating a created packet by the protocol

      +-------+-----+-------+---------+
      |CircID | CMD |  LEN  | HDATA   |
      +-------+-----+-------+---------+
    """
    cmd = b'\x02'  # created is command 2
    hdata = long_to_bytes(server_pubkey)
    dlen = (len(hdata)).to_bytes(4, byteorder='big')
    packet = circID + cmd + dlen + hdata
    return packet


def created_parsing(hdata):
    """
    the function parses the packet in the format of the protocol
      +-------+
      | HDATA |
      +-------+
    """
    dh = globals.get_dh_client()
    # hdata is a byte encoded server's public key
    server_pubkey = int.from_bytes(hdata, "big")
    try:
        shared_key = dh.gen_shared_key(server_pubkey)

    except error:
        error("Generating public key failed")
        return
    return shared_key

