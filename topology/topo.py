#!/usr/bin/env python3
"""
Mininet topology for the Dynamic SDN Firewall.

    h1 10.0.0.1 (admin)    --+
    h2 10.0.0.2            --+
    h3 10.0.0.3            --+-- s1 ===10 Mbit/s=== srv 10.0.0.100  (TCP server :8080, :2222)
    h4 10.0.0.4 (attacker) --+

 * s1 is an Open vSwitch controlled by the POX firewall (127.0.0.1:6633,
   OpenFlow 1.0).  failMode=secure: without the controller, new flows are
   not forwarded (the firewall fails closed).
 * The server's link is limited to 10 Mbit/s, so a flood visibly hurts the
   normal clients - that is the "network impact" we measure.
 * The security logger runs on the VM itself (127.0.0.1:9999), next to POX.

Run (controller and logger already started), from the project folder:
    sudo python3 topology/topo.py            normal mininet> prompt
    sudo python3 topology/topo.py --demo     guided demo: press Enter per step
    sudo python3 topology/topo.py --demo --from e   resume the guide at step e
    sudo python3 topology/topo.py --demo --auto     runs every step by itself
Easiest of all:  bash scripts/demo.sh   (all three terminals on one screen)
Add --userspace if setup.sh told you to.
"""

import argparse
import os
import subprocess
import sys
import time
from functools import partial

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        for i in range(1, 5):
            self.addLink(self.addHost("h%d" % i, ip="10.0.0.%d/24" % i), s1)
        srv = self.addHost("srv", ip="10.0.0.100/24")
        self.addLink(srv, s1, bw=10)                  # the bottleneck link


def build_network(userspace=False):
    switch = partial(OVSSwitch, protocols="OpenFlow10", failMode="secure",
                     datapath="user" if userspace else "kernel")
    controller = partial(RemoteController, ip="127.0.0.1", port=6633)
    net = Mininet(topo=FirewallTopo(), switch=switch, controller=controller,
                  link=TCLink, autoSetMacs=True)
    net.start()
    for host in net.hosts:
        host.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1")   # less noise
        if userspace:
            # OVS userspace mode does not fix TCP checksums left to the NIC
            host.cmd("ethtool -K %s tx off rx off >/dev/null 2>&1" % host.defaultIntf())
    print("*** Waiting for the switch to connect to the controller")
    for _ in range(40):
        if all(sw.connected() for sw in net.switches):
            break
        time.sleep(0.5)
    else:
        print("*** WARNING: switch not connected - is the controller running?")
    return net


def start_server(net, logfile, python="python3"):
    srv = net.get("srv")
    proc = srv.popen([python, "-u", os.path.join(ROOT, "app", "server.py")],
                     stdout=open(logfile, "a"), stderr=subprocess.STDOUT, cwd=ROOT)
    for _ in range(50):                                  # wait until it listens
        if "LISTEN" in srv.cmd("ss -Hltn 'sport = :8080'"):
            break
        time.sleep(0.2)
    return proc


def give_back(path):
    """Files written under sudo belong to root; give them back to the user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and os.path.exists(path):
        subprocess.call(["chown", "-R", "%s:%s" % (uid, gid), path])


def main():
    ap = argparse.ArgumentParser(description="Dynamic SDN Firewall topology")
    ap.add_argument("--demo", action="store_true", help="guided demo (press Enter per step)")
    ap.add_argument("--from", dest="start", default="a", help="start the guided demo at this step")
    ap.add_argument("--auto", action="store_true", help="demo runs by itself (no Enter needed)")
    ap.add_argument("--pause", type=float, default=6, help="--auto: seconds to talk after each step")
    ap.add_argument("--userspace", action="store_true", help="OVS userspace datapath")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("Mininet needs root:  sudo python3 topology/topo.py")
    os.chdir(ROOT)                          # Mininet hosts start in this folder
    os.makedirs("logs", exist_ok=True)
    setLogLevel("info")
    net = build_network(userspace=args.userspace)
    server = start_server(net, os.path.join(ROOT, "logs", "server.txt"))
    try:
        net.pingAll()
        if args.demo:
            sys.path.insert(0, ROOT)
            from topology.demo import run_demo
            run_demo(net, ROOT, args.start.lower(), auto=args.auto, pause=args.pause)
        else:
            print(open(os.path.join(ROOT, "docs", "cli_help.txt")).read())
        CLI(net)
    finally:
        server.terminate()
        net.stop()
        give_back(os.path.join(ROOT, "logs"))


if __name__ == "__main__":
    main()
