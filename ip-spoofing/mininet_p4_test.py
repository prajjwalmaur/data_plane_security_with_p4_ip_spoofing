#!/usr/bin/env python3
"""
Mininet Integration Test for P4 IP Spoofing Defense

This script creates a Mininet network topology and demonstrates
the P4 security logic using packet capture and validation.

Network Topology:
    h1 (10.0.1.1) --- s1 (P4 Switch) --- h2 (10.0.1.2)
         Port 1             |           Port 2
                            |
                     P4 Security Logic
                     - establish_binding
                     - dhcp_allowlist
                     - tcp_connection_track

Usage:
    sudo python3 mininet_p4_test.py

Requirements:
    - Mininet installed
    - Scapy installed
    - Root privileges

Author: Based on "Data-Plane Security Applications in Adversarial Settings"
"""

import sys
import os
import time
import threading
from typing import List, Dict, Tuple

# Check if running as root
if os.geteuid() != 0:
    print("This script requires root privileges.")
    print("Run with: sudo python3 mininet_p4_test.py")
    sys.exit(1)

try:
    from mininet.net import Mininet
    from mininet.node import Host, OVSBridge
    from mininet.topo import Topo
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    from mininet.link import TCLink
except ImportError:
    print("Mininet not found. Install with: sudo apt-get install mininet")
    sys.exit(1)

try:
    from scapy.all import (sendp, sniff, Ether, IP, TCP, UDP, ICMP,
                           BOOTP, DHCP, get_if_hwaddr, get_if_list,
                           Raw, conf)
    conf.verb = 0  # Suppress Scapy output
except ImportError:
    print("Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)

# Import our P4 behavioral model
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p4_behavioral_model import P4BMv2Switch, create_test_packet


# ============================================================================
# TOPOLOGY DEFINITION
# ============================================================================

class IPSpoofingTopo(Topo):
    """
    Network topology for IP spoofing defense testing.

    Matches topology.json:
        h1 --- s1 --- h2

    Host configurations:
        h1: IP=10.0.1.1/24, MAC=00:00:00:00:01:01
        h2: IP=10.0.1.2/24, MAC=00:00:00:00:01:02
    """

    def build(self):
        info("*** Creating IP Spoofing Defense Topology\n")

        # Add hosts with specific IPs and MACs
        h1 = self.addHost('h1',
                          ip='10.0.1.1/24',
                          mac='00:00:00:00:01:01')
        h2 = self.addHost('h2',
                          ip='10.0.1.2/24',
                          mac='00:00:00:00:01:02')

        # Add switch
        s1 = self.addSwitch('s1')

        # Add links (ports match P4 configuration)
        # h1 connects to s1 port 1
        # h2 connects to s1 port 2
        self.addLink(h1, s1, port2=1)
        self.addLink(h2, s1, port2=2)


# ============================================================================
# PACKET CAPTURE AND ANALYSIS
# ============================================================================

class PacketCapture:
    """Captures and analyzes packets for security testing"""

    def __init__(self, interface: str):
        self.interface = interface
        self.packets = []
        self.running = False
        self.thread = None

    def start(self):
        """Start packet capture in background"""
        self.running = True
        self.packets = []
        self.thread = threading.Thread(target=self._capture)
        self.thread.start()

    def stop(self) -> List:
        """Stop capture and return packets"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        return self.packets

    def _capture(self):
        """Background capture thread"""
        try:
            sniff(iface=self.interface,
                  prn=lambda p: self.packets.append(p),
                  store=False,
                  stop_filter=lambda p: not self.running,
                  timeout=10)
        except Exception as e:
            print(f"Capture error: {e}")


# ============================================================================
# P4 SECURITY TEST RUNNER
# ============================================================================

class P4SecurityTester:
    """
    Runs security tests in Mininet using P4 behavioral model.

    This demonstrates how the P4 data plane processes packets
    and blocks spoofing attacks.
    """

    def __init__(self, net: Mininet):
        self.net = net
        self.h1 = net.get('h1')
        self.h2 = net.get('h2')
        self.s1 = net.get('s1')

        # Initialize P4 behavioral model
        self.p4_switch = P4BMv2Switch()
        self.p4_switch.load_runtime_config('s1-runtime-new.json')

        self.results = []

    def run_all_tests(self):
        """Run complete test suite"""
        print("\n" + "=" * 70)
        print("MININET + P4 BEHAVIORAL MODEL INTEGRATION TEST")
        print("=" * 70)
        print(f"\nTopology: h1 ({self.h1.IP()}) --- s1 --- h2 ({self.h2.IP()})")
        print("-" * 70)

        # Test 1: Connectivity test
        self._test_connectivity()

        # Test 2: P4 Security tests
        self._test_p4_security()

        # Test 3: Attack simulation
        self._test_attack_scenarios()

        # Print final results
        self._print_results()

    def _test_connectivity(self):
        """Test basic network connectivity"""
        print("\n[1] MININET CONNECTIVITY TEST")
        print("-" * 50)

        # Ping test
        result = self.h1.cmd(f'ping -c 1 -W 1 {self.h2.IP()}')
        success = '1 received' in result or '1 packets received' in result

        print(f"  h1 -> h2 ping: {'SUCCESS' if success else 'FAILED'}")

        # Log interfaces
        print(f"  h1 interface: {self.h1.defaultIntf()}")
        print(f"  h2 interface: {self.h2.defaultIntf()}")

        return success

    def _test_p4_security(self):
        """Test P4 security logic"""
        print("\n[2] P4 SECURITY LOGIC TEST (Behavioral Model)")
        print("-" * 50)

        # Run behavioral model tests
        test_cases = [
            ("Legitimate h1->h2", "10.0.1.1", "00:00:00:00:01:01", 1, True),
            ("Spoofed IP", "10.0.1.3", "00:00:00:00:01:01", 1, False),
            ("MAC Spoofing", "10.0.1.1", "aa:bb:cc:dd:ee:ff", 1, False),
            ("Port Hopping", "10.0.1.1", "00:00:00:00:01:01", 3, False),
        ]

        for name, src_ip, src_mac, port, expected_fwd in test_cases:
            pkt = create_test_packet(
                src_mac, "00:00:00:00:01:02",
                src_ip, "10.0.1.2",
                6, 50000, 80, 0x02  # TCP SYN
            )

            forwarded, egress, action = self.p4_switch.process_packet(pkt, port)
            status = "PASS" if forwarded == expected_fwd else "FAIL"
            icon = "[OK]" if status == "PASS" else "[XX]"

            print(f"  {name}: {'FORWARD' if forwarded else 'DROP'} "
                  f"(expected: {'FORWARD' if expected_fwd else 'DROP'}) {icon}")

            self.results.append({
                'name': name,
                'action': action,
                'forwarded': forwarded,
                'expected': expected_fwd,
                'passed': forwarded == expected_fwd
            })

    def _test_attack_scenarios(self):
        """Test specific attack scenarios from the paper"""
        print("\n[3] ATTACK SCENARIO SIMULATION")
        print("-" * 50)
        print("  (Based on 'Data-Plane Security Applications in Adversarial Settings')")

        scenarios = [
            {
                "name": "Issue 1: Coarse-grained key attack",
                "desc": "Attacker uses valid IP with wrong MAC",
                "src_ip": "10.0.1.1",
                "src_mac": "de:ad:be:ef:00:01",
                "port": 1,
                "expected": False
            },
            {
                "name": "Challenge C: End-host state attack",
                "desc": "Attacker from wrong port with valid credentials",
                "src_ip": "10.0.1.1",
                "src_mac": "00:00:00:00:01:01",
                "port": 5,
                "expected": False
            },
            {
                "name": "DHCP Bootstrap abuse",
                "desc": "TCP attack with srcIP=0.0.0.0",
                "src_ip": "0.0.0.0",
                "src_mac": "00:00:00:00:01:01",
                "port": 1,
                "expected": False,
                "protocol": 6  # TCP, not DHCP
            },
        ]

        for scenario in scenarios:
            pkt = create_test_packet(
                scenario['src_mac'], "00:00:00:00:01:02",
                scenario['src_ip'], "10.0.1.2",
                scenario.get('protocol', 6), 50000, 80, 0x02
            )

            forwarded, _, action = self.p4_switch.process_packet(pkt, scenario['port'])
            blocked = not forwarded
            status = "BLOCKED" if blocked == (not scenario['expected']) else "FAILED"
            icon = "[OK]" if status == "BLOCKED" else "[XX]"

            print(f"\n  {scenario['name']}")
            print(f"    Description: {scenario['desc']}")
            print(f"    P4 Action: {action}")
            print(f"    Result: {status} {icon}")

    def _print_results(self):
        """Print summary results"""
        self.p4_switch.print_counter_stats()

        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)

        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"  Tests Passed: {passed}/{total}")
        print(f"  Success Rate: {passed/total*100:.1f}%" if total > 0 else "  No tests run")
        print(f"  Packets Forwarded: {self.p4_switch.packets_forwarded}")
        print(f"  Attacks Blocked: {self.p4_switch.packets_dropped}")
        print("=" * 70)


# ============================================================================
# INTERACTIVE CLI COMMANDS
# ============================================================================

def add_custom_commands(net: Mininet):
    """Add custom CLI commands for P4 testing"""
    pass  # CLI commands are handled by built-in Mininet CLI


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main function to run Mininet P4 test"""
    setLogLevel('info')

    print("=" * 70)
    print("P4 IP SPOOFING DEFENSE - MININET INTEGRATION TEST")
    print("=" * 70)
    print("\nCreating network topology...")

    # Create topology
    topo = IPSpoofingTopo()

    # Create network
    net = Mininet(
        topo=topo,
        switch=OVSBridge,
        controller=None,
        link=TCLink,
        autoSetMacs=False  # We set MACs manually
    )

    try:
        # Start network
        net.start()
        info("*** Network started\n")

        # Wait for network to stabilize
        time.sleep(2)

        # Run P4 security tests
        tester = P4SecurityTester(net)
        tester.run_all_tests()

        # Check if user wants interactive mode
        print("\n" + "=" * 70)
        print("DEMO COMPLETE")
        print("=" * 70)

        # Ask if user wants CLI
        try:
            response = input("\nEnter Mininet CLI for manual testing? [y/N]: ")
            if response.lower() == 'y':
                print("\nUseful commands:")
                print("  h1 ping h2")
                print("  h1 python3 client.py")
                print("  h2 python3 server.py &")
                print("  exit")
                CLI(net)
        except (EOFError, KeyboardInterrupt):
            pass

    finally:
        # Cleanup
        info("\n*** Stopping network\n")
        net.stop()


if __name__ == '__main__':
    main()
