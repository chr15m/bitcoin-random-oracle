import fileinput
import sys
import time
import urllib2
import json
import contextlib

import halfnode.bitcoinnode
from halfnode.bitcoinnode import SHA256

class DummyFile(object):
    def write(self, x): pass

class BitcoinRandomOracle(halfnode.bitcoinnode.BitcoinNode):
    def __init__(self, pretty, seed, host, port):
        # ugh - supress module print statements
        self._real_stdout = sys.stdout
        self._dummy_stdout = DummyFile()
        sys.stdout = self._dummy_stdout
        # invoke original module
        halfnode.bitcoinnode.BitcoinNode.__init__(self, host, port)
        self.hashstate = seed
        self.pretty = pretty
    
    def got_message(self, message):
        if message.command == "tx":
            sys.stdout = self._real_stdout
            # print dir(message.tx)
            # print message.tx.serialize()
            # print dir(message)
            entropy = SHA256.new(SHA256.new(message.tx.serialize() + self.hashstate).digest())
            if self.pretty:
                print entropy.hexdigest()
            else:
                print entropy.digest(),
            sys.stdout.flush()
            sys.stdout = self._dummy_stdout
        halfnode.bitcoinnode.BitcoinNode.got_message(self, message)

if len(sys.argv) > 1:
    if "--pretty" in sys.argv:
        pretty = True
        sys.argv.remove("--pretty")
    else:
        pretty = False
    
    hostport = sys.argv[1].split(":")
    state = len(sys.argv) > 2 and sys.argv[2] or ""
    
    node = BitcoinRandomOracle(pretty, state, hostport[0], int(hostport[1]))
    node.start()
    
    try:
        while 1:
            time.sleep(0.1)
    except:
        pass
    
    node.stop()
else:
    print "Usage: ", sys.argv[0], "IP:PORT", "[SEED]", "--pretty"
    print
    print "Please supply the IP and port of a Bitcoin node to connect to."
    print "If you supply a seed it will be used as the initial hash state."
    print "--pretty will print pretty lines of hex."
    print
    print "Fetching the 'leaderboard' list of available nodes from Bitnodes for you in 3 seconds..."
    time.sleep(3)
    response = urllib2.urlopen("https://bitnodes.21.co/api/v1/nodes/leaderboard/")
    nodes = json.loads(response.read())
    for n in nodes.get("results"):
        print n.get("node")

