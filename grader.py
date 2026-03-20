# -*- coding: utf-8 -*-
import json
import os
import time
import sys
import subprocess
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-t', metavar='test', type=int, default=None, help='test cases', choices=range(1, 16))
parser.add_argument('-d', metavar='debug', type=int, default=0, help='debug', choices=range(0, 2))
args = parser.parse_args()

path = './router/sr'
if __name__ == '__main__':
    if not os.path.exists(path):
        print("File not exist: %s" % path)
    else:
        with open(os.devnull, 'w') as devnull:
            pox_proc = subprocess.Popen("./pox/pox.py pwospf.ofhandler pwospf.srhandler".split(), stdout=devnull, stderr=devnull)
            time.sleep(10)
            if args.t is None:
                command = "sudo python2 ./testcases.py -d %d" % args.d
            else:
                command = "sudo python2 ./testcases.py -t %d -d %d"  % (args.t, args.d)
            mininet_proc = subprocess.Popen(command.split(), stdout=sys.stdout, stderr=sys.stdout)
            time.sleep(15)
            sr_proc1 = subprocess.Popen(("%s -t 300 -s 127.0.0.1 -p 8888 -v vhost1" % path).split(), stdout=devnull, stderr=devnull)
            sr_proc2 = subprocess.Popen(("%s -t 300 -s 127.0.0.1 -p 8888 -v vhost2" % path).split(), stdout=devnull, stderr=devnull)
            sr_proc3 = subprocess.Popen(("%s -t 300 -s 127.0.0.1 -p 8888 -v vhost3" % path).split(), stdout=devnull, stderr=devnull)
            mininet_proc.communicate()
            sr_proc1.kill()
            sr_proc2.kill()
            sr_proc3.kill()
            pox_proc.kill()

            infile = open("results.json", "r")
            result = infile.read()
            infile.close()

            print(result)
