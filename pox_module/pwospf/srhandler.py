from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.recoco import Timer
from pox.lib.packet import ethernet
import time

import threading
import asyncore
import collections
import logging
import socket

# Required for VNS
import sys
import os
from twisted.python import threadable
from threading import Thread

from twisted.internet import reactor
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSOpenTemplate, VNSBanner
from VNSProtocol import VNSRtable, VNSAuthRequest, VNSAuthReply, VNSAuthStatus, VNSInterface, VNSHardwareInfo

log = core.getLogger()

class SRServerListener(EventMixin):
  ''' TCP Server to handle connection to SR '''
  def __init__ (self, address=('127.0.0.1', 8888)):
    return

  def broadcast(self, message):
    log.debug('Broadcasting message: %s', message)

  def send_to_vhost(self, message, vhost):
    log.debug('Unicast message to %s: %s', vhost, message)

  def _handle_SRPacketIn(self, event):
    log.debug("SRServerListener catch SRPacketIn event, port=%d, pkt=%r, vhost=%s" % (event.port, event.pkt, event.vhost))

  def _handle_RouterInfo(self, event):
    log.debug("SRServerListener catch RouterInfo even for vhost=%s, info=%s, rtable=%s", event.vhost, event.info, event.rtable)
    

  def _handle_recv_msg(self, conn, vns_msg):
      log.debug('unexpected VNS message received: %s' % vns_msg)

  def _handle_auth_reply(self, conn):

  def _handle_new_client(self, conn):
    log.debug('Accepted client at %s' % conn.transport.getPeer().host)
    print
    return

  def _handle_client_disconnected(self, conn):
    log.info("disconnected")
    return

  def _handle_open_msg(self, conn, vns_msg):
    # client wants to connect to some topology.
    log.debug("open-msg: %s, vhost:%s" % (vns_msg.topo_id, vns_msg.vhost))
    return

  def _handle_close_msg(self, conn):
    conn.send("Goodbyte!") # spelling mistake intended...
    conn.transport.loseConnection()
    return

  def _handle_packet_msg(self, conn, vns_msg):
    log.debug('VNS Packet msg: %s' % vns_msg)
    log.debug("packet-out %s: %r" % (out_intf, pkt))
    log.debug('SRServerHandler raise packet out event')

  def _handle_open_template_msg(conn, vns_msg):

class SRPacketOut(Event):
  '''Event to raise upon receiving a packet back from SR'''

  def __init__(self, packet, port, vhost):
    Event.__init__(self)
    self.pkt = packet
    self.port = port
    self.vhost = vhost

class pwospf_srhandler(EventMixin):
  _eventMixin_events = set([SRPacketOut])

  def __init__(self):

  def _handle_GoingDownEvent (self, event):
    log.debug("Shutting down SRServer")
    del self.server


def launch (transparent=False):
  """
  Starts the SR handler application.
  """
  core.registerNew(pwospf_srhandler)
