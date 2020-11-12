#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

class part1_topo(Topo):
    
    def build(self):
        #Creates the custom topo
        #pass
        #Creates Hosts and Switches 
        switch1 = self.addSwitch('switch1')
        host1 = self.addHost('host1')
        host2 = self.addHost('host2')
        host3 = self.addHost('host3')
        host4 = self.addHost('host4')
        self.addLink(host1,switchname)
        self.addLink(host2,switchname)
        self.addLink(host3,switchname)
        self.addLink(host4,switchname)
        
topos = {'part1' : part1_topo}

if __name__ == '__main__':
    t = part1_topo()
    net = Mininet (topo=t)
    net.start()
    CLI(net)
    net.stop()
