"""Defines the VNS protocol and some associated helper functions."""

import re
from socket import inet_aton, inet_ntoa, htonl
import struct

from ltprotocol.ltprotocol import LTMessage, LTProtocol, LTTwistedServer

VNS_DEFAULT_PORT = 3250
VNS_MESSAGES = []
IDSIZE = 32

__clean_re = re.compile(r'\x00*')
def strip_null_chars(s):
    """Remove null characters from a string."""

class VNSOpen(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, topo_id, virtualHostID, UID, pw):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSOpen)

class VNSClose(LTMessage):
    @staticmethod
    def get_type():

    @staticmethod
    def get_banners_and_close(msg):
        """Split msg up into the minimum number of VNSBanner messages and VNSClose it will fit in."""

    def __init__(self, msg):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSClose)

class VNSPacket(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, intf_name, ethernet_frame):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSPacket)

class VNSProtocolException(Exception):
    def __init__(self, msg):

    def __str__(self):

class VNSInterface:
    def __init__(self, name, mac, ip, mask, static):

    def pack(self):

    def __str__(self):

class VNSBanner(LTMessage):
    @staticmethod
    def get_type():

    @staticmethod
    def get_banners(msg):
        """Split msg up into the minimum number of VNSBanner messages it will fit in."""

    def __init__(self, msg):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSBanner)

class VNSHardwareInfo(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, interfaces):

    def length(self):

    def pack(self):

    def __str__(self):
VNS_MESSAGES.append(VNSHardwareInfo)

class VNSRtable(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, virtualHostID, rtable):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSRtable)

class VNSOpenTemplate(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, template_name, virtualHostID, src_filters):

    def length(self):


    def get_src_filters(self):

    def __set_src_filters(self, src_filters):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSOpenTemplate)

class VNSAuthRequest(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, salt):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSAuthRequest)

class VNSAuthReply(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, username, sha1_of_salted_pw):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSAuthReply)

class VNSAuthStatus(LTMessage):
    @staticmethod
    def get_type():

    def __init__(self, auth_ok, msg):

    def length(self):

    def pack(self):

    @staticmethod
    def unpack(body):

    def __str__(self):
VNS_MESSAGES.append(VNSAuthStatus)

VNS_PROTOCOL = LTProtocol(VNS_MESSAGES, 'I', 'I')

def create_vns_server(port, recv_callback, new_conn_callback, lost_conn_callback, verbose=True):
    """Starts a server which listens for VNS clients on the specified port.

    @param port  the port to listen on
    @param recv_callback  the function to call with received message content
                         (takes two arguments: transport, msg)
    @param new_conn_callback   called with one argument (a LTProtocol) when a connection is started
    @param lost_conn_callback  called with one argument (a LTProtocol) when a connection is lost
    @param verbose        whether to print messages when they are sent

    @return returns the new LTTwistedServer
    """
    server = LTTwistedServer(VNS_PROTOCOL, recv_callback, new_conn_callback, lost_conn_callback, verbose)
    server.listen(port)
    return server
