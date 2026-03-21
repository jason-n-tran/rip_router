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
import argparse
import time, json

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

parser = argparse.ArgumentParser()
parser.add_argument('-t', metavar='test', type=int, default=None, help='test cases')
parser.add_argument('-d', metavar='debug', type=int, default=0, help='debug')
args = parser.parse_args()


class Topology( Topo ):
    "Topology"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        server1 = self.addHost( 'server1' )
        server2 = self.addHost( 'server2' )
        vhost1 = self.addSwitch( 'vhost1', protocols = ['OpenFlow10'])
        vhost2 = self.addSwitch( 'vhost2', protocols = ['OpenFlow10'])
        vhost3 = self.addSwitch( 'vhost3', protocols = ['OpenFlow10'])
        client = self.addHost('client')

        self.addLink(client, vhost1)
        self.addLink(vhost2, vhost1)
        self.addLink(vhost3, vhost1)
        self.addLink(server1, vhost2)
        self.addLink(server2, vhost3)
        self.addLink(vhost3, vhost2)


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
        Controller.__init__( self, name, ip=ip, port=port, **params)

    def start( self ):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""
        pathCheck( self.command )
        cout = '/tmp/' + self.name + '.log'
        if self.cdir is not None:
            self.cmd( 'cd ' + self.cdir )
        self.cmd( self.command, self.cargs % self.port, '>&', cout, '&' )

    def stop( self ):
        "Stop controller."
        self.cmd( 'kill %' + self.command )
        self.terminate()


def startsshd( host ):
    "Start sshd on host"
    stopsshd()
    info( '*** Starting sshd\n' )
    name, intf, ip = host.name, host.defaultIntf(), host.IP()
    banner = '/tmp/%s.banner' % name
    host.cmd( 'echo "Welcome to %s at %s" >  %s' % ( name, ip, banner ) )
    host.cmd( '/usr/sbin/sshd -o "Banner %s"' % banner, '-o "UseDNS no"' )
    info( '***', host.name, 'is running sshd on', intf, 'at', ip, '\n' )


def stopsshd():
    "Stop *all* sshd processes with a custom banner"
    info( '*** Shutting down stale sshd/Banner processes ',
          quietRun( "pkill -9 -f Banner" ), '\n' )


def starthttp( host ):
    "Start simple Python web server on hosts"
    info( '*** Starting SimpleHTTPServer on host', host, '\n' )
    host.cmd( 'cd ./http_%s/; nohup python2.7 ./webserver.py &' % (host.name) )


def stophttp():
    "Stop simple Python web servers"
    info( '*** Shutting down stale SimpleHTTPServers', 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n' )    
    info( '*** Shutting down stale webservers', 
          quietRun( "pkill -9 -f webserver.py" ), '\n' )    
    
def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['vhost2-eth2']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['vhost3-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['vhost1-eth1']
    print host.name, routerip
    #host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    #ips = IP_SETTING[host.name].split(".") 
    #host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def get_ip_setting():
    if (not os.path.isfile(IPCONFIG_FILE)):
        return -1
    f = open(IPCONFIG_FILE, 'r')
    for line in f:
        if( len(line.split()) == 0):
          break
        name, ip = line.split()
        print name, ip
        IP_SETTING[name] = ip
    return 0

def output_info(information):
    info("-------------%s-------------\n" % information)

def check_correctness(passed, testcase, testcases_scores, records):
    max_score = testcases_scores[testcase-1]
    if passed:
        score = max_score
        output_info("Test Case %d: Passed (%.1f/%.1f)" % (testcase, score, max_score))
        records[testcase-1] = 1
    else:
        score = 0
        output_info("Test Case %d: Failed (0/%.1f)" % (testcase, max_score))
        records[testcase-1] = 0
    return score

def send_command_and_check(node, node_name, command, expected_result):
    info(">>>>>>>>>>>>>>>>Sending command: %s %s<<<<<<<<<<<<<<<\n" % (node_name.lower(), command))
    return_info = node.cmd(command)
    info(return_info+"\n")
    return_info = return_info.lower()
    if expected_result in return_info:
        return True
    else:
        return False

def check_traceroute(node, node_name, ip, hop):
    info(">>>>>>>>>>>>>>>>Sending command: %s traceroute %s<<<<<<<<<<<<<<<\n" % (node_name.lower(), ip))
    return_info = node.cmd("traceroute -I -n %s" % ip)
    info(return_info+"\n")

    return_info = str.strip(return_info)
    listx = return_info.split("\n")
    count = 0
    for i in range(1, len(listx)):
        item = str.strip(listx[i]).split(" ")
        if item[0].isdigit():
            count = max(count, int(item[0]))
    if count == hop:
        return True
    else:
        return False


def test_each_testcase(testcase, parameter, ip_list):
    node = parameter[0][0]
    node_ip = parameter[0][1]
    node_name = parameter[0][2]
    ping_list = parameter[1]
    traceroute_info = parameter[2]
    
    for i in range(len(ip_list)):
        target_ip = ip_list[i]
        if target_ip == node_ip:
            continue
        if ping_list[i] == 0:
            expected_result = 'destination net unreachable'
        else:
            expected_result = '1 received'
        if not send_command_and_check(node, node_name, "ping -c 1 %s" % target_ip, expected_result):
            return False
    if len(traceroute_info) == 0:
        return True
    return check_traceroute(node, node_name, traceroute_info[0], traceroute_info[1])

def run_tests(net):
    ip_dict = {
        '10.0.1.1': 'vhost1-eth1',
        '10.0.2.1': 'vhost1-eth2',
        '10.0.3.1': 'vhost1-eth3',
        '10.0.1.100': 'client',
        '10.0.2.2': 'vhost2-eth1',
        '192.168.2.2': 'vhost2-eth2',
        '192.168.3.1': 'vhost2-eth3',
        '192.168.2.200': 'server1',
        '10.0.3.2': 'vhost3-eth1',
        '172.24.3.2': 'vhost3-eth2',
        '192.168.3.2': 'vhost3-eth3',
        '172.24.3.30': 'server2'
    }
    ip_list = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.1.100', '10.0.2.2', '192.168.2.2', '192.168.3.1', '192.168.2.200', '10.0.3.2', '172.24.3.2', '192.168.3.2', '172.24.3.30']
    records = [-1]*15
    testcases_scores = [0.5, 0.5, 0.5, 1, 0.5, 0.5, 1, 1, 1, 0.5, 0.5, 0.5, 1, 0.5, 0.5]

    client = [net.get('client'), '10.0.1.100', 'Client']
    server1 = [net.get('server1'), '192.168.2.200', 'Server1']
    server2 = [net.get('server2'), '172.24.3.30', 'Server2']
    vhost1 = net.get("vhost1")
    vhost2 = net.get("vhost2")
    vhost3 = net.get("vhost3")
    node_infos = [client, server1, server2]
    node_names = ['Client', 'Server1', 'Server2']

    parameters = [
        [client,  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('192.168.2.200', 3)],
        [server1, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('172.24.3.30', 3)],
        [server2, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('10.0.1.100', 3)],
        [client,  [1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1], ('192.168.2.200', 4)],
        [server1, [1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1], ('172.24.3.30', 3)],
        [server2, [1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1], ('10.0.1.100', 3)],
        [client,  [1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1], ('172.24.3.30', 3)],
        [server1, [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0], ()],
        [server2, [1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1], ('10.0.1.100', 3)],
        [client,  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('192.168.2.200', 3)],
        [server1, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('172.24.3.30', 3)],
        [server2, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('10.0.1.100', 3)],
        [server1, [0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], ('172.24.3.30', 3)],
        [server2, [0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1], ('10.0.3.1', 2)],
        [client,  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], ('192.168.2.200', 3)]
    ]

    '''client tshark -i client-eth0 -w ./pcap_files/client.pcap &
    server1 tshark -i server1-eth0 -w ../pcap_files/server1.pcap &
    server2 tshark -i server2-eth0 -w ../pcap_files/server2.pcap &
    vhost1 tshark -i vhost1-eth1 -i vhost1-eth2 -i vhost1-eth3 -w ./pcap_files/vhost1.pcap &
    vhost2 tshark -i vhost2-eth1 -i vhost2-eth2 -i vhost2-eth3 -w ./pcap_files/vhost2.pcap &
    vhost3 tshark -i vhost3-eth1 -i vhost3-eth2 -i vhost3-eth3 -w ./pcap_files/vhost3.pcap &'''

    if args.d == 1:
        client[0].cmd("tshark -i client-eth0 -w ./pcap_files/client.pcap &")
        server2[0].cmd("tshark -i server2-eth0 -w ../pcap_files/server2.pcap &")
        server1[0].cmd("tshark -i server1-eth0 -w ../pcap_files/server1.pcap &")
        vhost1.cmd("tshark -i vhost1-eth1 -i vhost1-eth2 -i vhost1-eth3 -w ./pcap_files/vhost1.pcap &")
        vhost2.cmd("tshark -i vhost2-eth1 -i vhost2-eth2 -i vhost2-eth3 -w ./pcap_files/vhost2.pcap &")
        vhost3.cmd("tshark -i vhost3-eth1 -i vhost3-eth2 -i vhost3-eth3 -w ./pcap_files/vhost3.pcap &")
        time.sleep(10)
    info( '>>>>>>>>>>Wait 30s for routing table converging<<<<<<<<<<\n')
    time.sleep(30)

    total_scores = 0
    if args.t is not None:
        testcases = [args.t]
        max_score = testcases_scores[args.t-1]
        if args.t in [4, 5, 6]:
            info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth2 down <<<<<<<<<<<<<<<\n")
            info( '>>>>>>>>>>Wait 20s for routing table converging<<<<<<<<<<\n')
            vhost1.cmd("ifconfig vhost1-eth2 down")
            time.sleep(20)
        elif args.t in [7, 8, 9]:
            info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth2 down <<<<<<<<<<<<<<<\n")
            info(">>>>>>>>>>>>>>>>Sending command: vhost2 ifconfig vhost2-eth3 down <<<<<<<<<<<<<<<\n")
            info( '>>>>>>>>>>Wait 20s for routing table converging<<<<<<<<<<\n')
            vhost1.cmd("ifconfig vhost1-eth2 down")
            vhost2.cmd("ifconfig vhost2-eth3 down")
            time.sleep(20)
        elif args.t in [13, 14]:
            info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth1 down <<<<<<<<<<<<<<<\n")
            info( '>>>>>>>>>>Wait 20s for routing table converging<<<<<<<<<<\n')
            vhost1.cmd("ifconfig vhost1-eth1 down")
            time.sleep(20)
        testcase = testcases[0]
        passed = test_each_testcase(testcase, parameters[testcase-1], ip_list)
        total_scores += check_correctness(passed, testcase, testcases_scores, records)
    else:
        testcases = range(1, 16)
        max_score = 10.0
        for testcase in testcases:
            passed = test_each_testcase(testcase, parameters[testcase-1], ip_list)
            total_scores += check_correctness(passed, testcase, testcases_scores, records)
            
            if testcase in [3, 6, 9, 12, 14]:
                if testcase == 3:
                    info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth2 down <<<<<<<<<<<<<<<\n")
                    vhost1.cmd("ifconfig vhost1-eth2 down")
                elif testcase == 6:
                    info(">>>>>>>>>>>>>>>>Sending command: vhost2 ifconfig vhost2-eth3 down <<<<<<<<<<<<<<<\n")
                    vhost2.cmd("ifconfig vhost2-eth3 down")
                elif testcase == 9:
                    info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth2 up <<<<<<<<<<<<<<<\n")
                    info(">>>>>>>>>>>>>>>>Sending command: vhost2 ifconfig vhost2-eth3 up <<<<<<<<<<<<<<<\n")
                    vhost1.cmd("ifconfig vhost1-eth2 up")
                    vhost2.cmd("ifconfig vhost2-eth3 up")
                elif testcase == 12:
                    info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth1 down <<<<<<<<<<<<<<<\n")
                    vhost1.cmd("ifconfig vhost1-eth1 down")
                else:
                    info(">>>>>>>>>>>>>>>>Sending command: vhost1 ifconfig vhost1-eth1 up <<<<<<<<<<<<<<<\n")
                    vhost1.cmd("ifconfig vhost1-eth1 up")
                info( '>>>>>>>>>>Wait 20s for routing table converging<<<<<<<<<<\n')
                time.sleep(20)

    output_info("All Test Cases Finished")
    output_info("Total Score: %.1f/%.1f" % (total_scores, max_score))
    for i in range(len(records)):
        if records[i] != -1:
            if records[i] == 1:
                passed = "PASSED"
            else:
                passed = "FAILED"
            info("Test Case:%d %s\n" % (i+1, passed))

    output = open("results.json", "w")
    res = {
        "score": total_scores,
        "stdout_visibility": "visible",
    }
    output.write(json.dumps(res))
    output.close()

    if args.d == 1:
        os.system("chmod 777 ./pcap_files/*")


def net():
    stophttp()
    "Create a simple network"
    r = get_ip_setting()
    if r == -1:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    else:
        info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)

    topo = Topology()
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController)
    net.start()
    server1, server2, client = net.get( 'server1', 'server2', 'client')
    s1intf = server1.defaultIntf()
    s1intf.setIP('%s/24' % IP_SETTING['server1'])
    s2intf = server2.defaultIntf()
    s2intf.setIP('%s/24' % IP_SETTING['server2'])
    clintf = client.defaultIntf()
    clintf.setIP('%s/24' % IP_SETTING['client'])


    #cmd = ['ifconfig', "eth1"]
    #process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    #hwaddr = Popen(["grep", "HWaddr"], stdin=process.stdout, stdout=PIPE)
    #eth1_hw = hwaddr.communicate()[0]
    #info( '*** setting mac address of sw0-eth3 the same as eth1 (%s)\n' % eth1_hw.split()[4])
    #router.intf('sw0-eth3').setMAC(eth1_hw.split()[4])
    
   
    #for host in server1, server2, client:
    for host in server1, server2, client:
        set_default_route(host)
    starthttp( server1 )
    starthttp( server2 )
    #run_tests(net)
    CLI(net)
    stophttp()
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    net()

