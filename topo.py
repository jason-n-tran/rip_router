#!/usr/bin/python

"""
Start up the topology for PWOSPF
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class Topology( Topo ):
    "Topology"
    
    def __init__( self, *args, **kwargs ):


class Controller( Controller ):
    "Controller for Multiple IP Bridge"

    def __init__( self, name, inNamespace=False, command='controller',
                 cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                 port=6633, **params ):
        """command: controller command name
           cargs: controller command arguments
           cdir: director to cd to before running controller
           ip: IP address for controller
           port: port for controller to listen at
           params: other params passed to Node.__init__()"""

    def start( self ):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""

    def stop( self ):
        "Stop controller."


def startsshd( host ):
    "Start sshd on host"


def stopsshd():
    "Stop *all* sshd processes with a custom banner"


def starthttp( host ):
    "Start simple Python web server on hosts"


def stophttp():
    "Stop simple Python web servers"
    
def set_default_route(host):

def get_ip_setting():

def net():
    stophttp()
    "Create a simple network"
    starthttp( server1 )
    starthttp( server2 )
    CLI( net )
    stophttp()
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    net()

