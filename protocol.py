import traceback

def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def Create(htype, hdata, wrapper):
    # format:
    #       HTYPE     (Client Handshake Type)     [2 bytes]
    #        HLEN      (Client Handshake Data Len) [2 bytes]
    #        HDATA     (Client Handshake Data)     [HLEN bytes]
    # +----+-----+-------+----+
    # |HTYPE | HLEN |  HDATA  |
    # +----+-----+-------+----+
    HTYPE = htype
    HLEN = len(hdata)
    HDATA = hdata
    reply = HTYPE + HLEN + HDATA
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return

