import pyDH
import threading

global sock_to_streamid
sock_to_streamid = {}

global streamid_to_sock
streamid_to_sock = {}


global dh_client
dh_client = pyDH.DiffieHellman()


def get_dh_client():
    return dh_client



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

