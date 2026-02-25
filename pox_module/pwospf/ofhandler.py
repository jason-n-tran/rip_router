# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
import pox.lib.packet.icmp as icmp
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
from pox.lib.addresses import IPAddr, EthAddr


import time
import code
import os
import struct
import sys

log = core.getLogger()
FLOOD_DELAY = 5
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}
RTABLE = {}
VHOST_RTABLE = {}
VHOST_HW = {}

#Topology is fixed 
#sw0-eth1:server1-eth0 sw0-eth2:server2-eth0 sw0-eth3:client

class RouterInfo(Event):
  '''Event to raise upon the information about an openflow router is ready'''

  def __init__(self, info, rtable, vhost):
    Event.__init__(self)
    self.info = info
    self.rtable = rtable
    self.vhost = vhost


class OFHandler (EventMixin):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

  def _handle_PortStatus (self, event):
    

  def _handle_SRPacketOut(self, event):
	
class SRPacketIn(Event):
  '''Event to raise upon a receive a packet_in from openflow'''

  def __init__(self, packet, port, vhost):
    Event.__init__(self)
    self.pkt = packet
    self.port = port
    self.vhost = vhost

class pwospf_ofhandler (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  _eventMixin_events = set([SRPacketIn, RouterInfo])

  def __init__ (self, transparent):
    EventMixin.__init__(self)
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    OFHandler(event.connection, self.transparent)



def get_ip_setting():
  return 0



def launch (transparent=False):
  """
  Starts an L2 learning switch.
  """
