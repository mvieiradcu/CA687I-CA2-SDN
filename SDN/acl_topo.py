from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.cli import CLI

class acl_topology(Topo):
    def build(self):
        # Add hosts

        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Add switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(s1, s2)


def run():
    topo = acl_topology()
    net = Mininet(topo=topo, controller=None)

    # Add Ryu controller
    ryu_ctrl = net.addController('ryu_ctrl', controller=RemoteController,
                                 ip='127.0.0.1', port=6653, )

    # Start network
    net.start()

    h2 = net.get('h2')
    h2.cmd('echo "Hello, from Host!" > index.html')
    h2.cmd('nohup python3 -m http.server 80 &')

    h3 = net.get('h3')
    h3.cmd('echo "Hello, from Host!" > index.html')
    h3.cmd('nohup python3 -m http.server 80 &')

    h4 = net.get('h4')
    h4.cmd('echo "Hello, from Host!" > index.html')
    h4.cmd('nohup python3 -m http.server 80 &')

    # Start Ryu controller
    ryu_ctrl.start()

    # Set switch to use Ryu controller
    for sw in net.switches:
        sw.start([ryu_ctrl])

    # Test network connectivity
    # net.pingAll()

    CLI(net)

    # Stop network
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
