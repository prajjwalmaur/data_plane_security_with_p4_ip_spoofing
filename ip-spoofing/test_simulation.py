#!/usr/bin/env python3
"""
IP Spoofing Defense - Security Logic Simulation

This script simulates the P4 data-plane security logic WITHOUT requiring actual P4 hardware.
It demonstrates the security mechanisms implemented in ip-spoofing-defense.p4

Based on: "Data-Plane Security Applications in Adversarial Settings"
          by Wang, Mittal, and Rexford (Princeton University)

Usage: python3 test_simulation.py
"""

import sys
from dataclasses import dataclass
from typing import Optional, Dict, Tuple, List
from enum import Enum
import json

# ============================================================================
# CONSTANTS (matching P4 implementation)
# ============================================================================

PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67

TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
TCP_FLAG_RST = 0x04
TCP_FLAG_FIN = 0x01


# ============================================================================
# DATA STRUCTURES
# ============================================================================

class Decision(Enum):
    FORWARD = "FORWARD"
    DROP = "DROP"


@dataclass
class Packet:
    """Simulates a network packet"""
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    protocol: int  # TCP=6, UDP=17, ICMP=1
    src_port: int
    dst_port: int
    tcp_flags: int = 0
    ingress_port: int = 1
    description: str = ""

    def is_dhcp(self) -> bool:
        """Check if packet is DHCP traffic"""
        return (self.protocol == PROTOCOL_UDP and
                self.src_port == DHCP_CLIENT_PORT and
                self.dst_port == DHCP_SERVER_PORT)

    def is_tcp_syn(self) -> bool:
        return (self.protocol == PROTOCOL_TCP and
                (self.tcp_flags & TCP_FLAG_SYN) != 0 and
                (self.tcp_flags & TCP_FLAG_ACK) == 0)

    def is_tcp_synack(self) -> bool:
        return (self.protocol == PROTOCOL_TCP and
                (self.tcp_flags & TCP_FLAG_SYN) != 0 and
                (self.tcp_flags & TCP_FLAG_ACK) != 0)

    def is_tcp_ack(self) -> bool:
        return (self.protocol == PROTOCOL_TCP and
                (self.tcp_flags & TCP_FLAG_ACK) != 0)


@dataclass
class SecurityCounters:
    """Security statistics counters (matching P4 implementation)"""
    legitimate_established: int = 0    # [0]
    dhcp_bootstrap: int = 0             # [1]
    spoofed_dropped: int = 0            # [2]
    unbound_non_dhcp: int = 0           # [3]
    tcp_syn: int = 0                    # [4]
    tcp_synack: int = 0                 # [5]
    tcp_ack: int = 0                    # [6]
    rate_limited: int = 0               # [7]
    invalid_protocol: int = 0           # [8]
    checksum_failures: int = 0          # [9]

    def print_stats(self):
        print("\n" + "="*60)
        print("SECURITY COUNTERS (matching P4 counter indices)")
        print("="*60)
        print(f"  [0] Legitimate Established:  {self.legitimate_established}")
        print(f"  [1] DHCP Bootstrap:          {self.dhcp_bootstrap}")
        print(f"  [2] Spoofed/Invalid DROPPED: {self.spoofed_dropped} <-- ATTACKS BLOCKED")
        print(f"  [3] Unbound Non-DHCP:        {self.unbound_non_dhcp} <-- ATTACKS BLOCKED")
        print(f"  [4] TCP SYN:                 {self.tcp_syn}")
        print(f"  [5] TCP SYN-ACK:             {self.tcp_synack}")
        print(f"  [6] TCP ACK:                 {self.tcp_ack}")
        print(f"  [7] Rate Limited:            {self.rate_limited}")
        print(f"  [8] Invalid Protocol:        {self.invalid_protocol}")
        print(f"  [9] Checksum Failures:       {self.checksum_failures}")
        print("="*60)


# ============================================================================
# P4 SECURITY LOGIC SIMULATION
# ============================================================================

class IPSpoofingDefense:
    """
    Simulates the P4 IP Spoofing Defense data-plane logic.

    Implements:
    - Three-factor binding: (srcIP, srcMAC, ingressPort)
    - DHCP bootstrap protection
    - TCP connection tracking
    - Security counters
    """

    def __init__(self):
        self.counters = SecurityCounters()

        # Established client binding table
        # Key: (src_ip, src_mac, ingress_port) -> forward_to_port
        self.establish_binding: Dict[Tuple[str, str, int], int] = {}

        # DHCP client allowlist
        # Key: (src_mac, ingress_port) -> forward_to_port
        self.dhcp_allowlist: Dict[Tuple[str, int], int] = {}

        # TCP connection tracking (for monitoring)
        self.tcp_connections: Dict[Tuple[str, str, int, int], int] = {}

    def load_runtime_config(self, config_path: str):
        """Load bindings from runtime JSON configuration"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            for entry in config.get('table_entries', []):
                if entry.get('default_action'):
                    continue

                table = entry.get('table', '')
                match = entry.get('match', {})
                params = entry.get('action_params', {})

                if 'establish_binding' in table:
                    src_ip = match.get('hdr.ipv4.srcAddr', '')
                    src_mac = match.get('hdr.ethernet.srcAddr', '')
                    port = match.get('standard_metadata.ingress_port', 0)
                    fwd_port = params.get('port', 0)

                    if src_ip and src_mac:
                        self.establish_binding[(src_ip, src_mac, port)] = fwd_port
                        print(f"  Loaded binding: ({src_ip}, {src_mac}, port {port}) -> port {fwd_port}")

                elif 'dhcp_allowlist' in table:
                    src_mac = match.get('hdr.ethernet.srcAddr', '')
                    port = match.get('standard_metadata.ingress_port', 0)
                    fwd_port = params.get('port', 0)

                    if src_mac:
                        self.dhcp_allowlist[(src_mac, port)] = fwd_port
                        print(f"  Loaded DHCP allowlist: ({src_mac}, port {port}) -> port {fwd_port}")

            print(f"\nLoaded {len(self.establish_binding)} binding entries")
            print(f"Loaded {len(self.dhcp_allowlist)} DHCP allowlist entries")

        except FileNotFoundError:
            print(f"Warning: Config file {config_path} not found, using defaults")
        except json.JSONDecodeError:
            print(f"Warning: Invalid JSON in {config_path}")

    def add_binding(self, src_ip: str, src_mac: str, ingress_port: int, egress_port: int):
        """Add established client binding (simulates table entry)"""
        self.establish_binding[(src_ip, src_mac, ingress_port)] = egress_port

    def add_dhcp_allowlist(self, src_mac: str, ingress_port: int, egress_port: int):
        """Add DHCP client allowlist entry"""
        self.dhcp_allowlist[(src_mac, ingress_port)] = egress_port

    def process_packet(self, pkt: Packet) -> Tuple[Decision, str, int]:
        """
        Process packet through P4 security pipeline.

        Returns: (Decision, reason, counter_index)
        """

        # Track TCP statistics
        if pkt.protocol == PROTOCOL_TCP:
            if pkt.is_tcp_syn():
                self.counters.tcp_syn += 1
            elif pkt.is_tcp_synack():
                self.counters.tcp_synack += 1
            elif pkt.is_tcp_ack():
                self.counters.tcp_ack += 1

        # Check if unbound client (srcIP = 0.0.0.0)
        if pkt.src_ip == "0.0.0.0":
            # DHCP Bootstrap Phase
            if pkt.is_dhcp():
                # Check DHCP allowlist
                key = (pkt.src_mac, pkt.ingress_port)
                if key in self.dhcp_allowlist:
                    self.counters.dhcp_bootstrap += 1
                    return Decision.FORWARD, "DHCP bootstrap allowed", 1
                else:
                    self.counters.unbound_non_dhcp += 1
                    return Decision.DROP, "Unknown DHCP client (MAC+port not in allowlist)", 3
            else:
                # Non-DHCP traffic from unbound client
                self.counters.unbound_non_dhcp += 1
                return Decision.DROP, "Non-DHCP traffic from unbound client (srcIP=0.0.0.0)", 3

        else:
            # Established Client Phase
            # Check three-factor binding: (srcIP, srcMAC, ingressPort)
            key = (pkt.src_ip, pkt.src_mac, pkt.ingress_port)

            if key in self.establish_binding:
                self.counters.legitimate_established += 1
                return Decision.FORWARD, "Valid binding (IP+MAC+port match)", 0
            else:
                # Check which factor failed for detailed reporting
                ip_match = any(k[0] == pkt.src_ip for k in self.establish_binding)
                mac_match = any(k[1] == pkt.src_mac for k in self.establish_binding)
                port_match = any(k[2] == pkt.ingress_port for k in self.establish_binding)

                reasons = []
                if not ip_match:
                    reasons.append("unknown IP")
                if not mac_match:
                    reasons.append("unknown MAC")
                if not port_match:
                    reasons.append("unknown port")
                if ip_match and mac_match and not port_match:
                    reasons = ["valid IP+MAC but wrong ingress port"]
                if ip_match and not mac_match:
                    reasons = ["IP exists but MAC mismatch (MAC spoofing attempt)"]

                self.counters.spoofed_dropped += 1
                return Decision.DROP, f"Spoofed packet: {', '.join(reasons)}", 2


# ============================================================================
# TEST CASES
# ============================================================================

def create_test_packets() -> List[Packet]:
    """
    Create test packets matching the paper's attack scenarios
    and the client.py test script.
    """

    packets = [
        # Test 1: Non-DHCP with srcIP=0.0.0.0 (unbound client abuse)
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            protocol=PROTOCOL_TCP,
            src_port=50000,
            dst_port=1234,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=1,
            description="Test 1: Non-DHCP TCP from unbound client (srcIP=0.0.0.0) - SHOULD DROP"
        ),

        # Test 2: Valid DHCP Discover (allowed during bootstrap)
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            protocol=PROTOCOL_UDP,
            src_port=DHCP_CLIENT_PORT,
            dst_port=DHCP_SERVER_PORT,
            ingress_port=1,
            description="Test 2: DHCP Discover from known client - SHOULD FORWARD"
        ),

        # Test 3: DHCP from unknown MAC
        Packet(
            src_mac="aa:bb:cc:dd:ee:ff",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            protocol=PROTOCOL_UDP,
            src_port=DHCP_CLIENT_PORT,
            dst_port=DHCP_SERVER_PORT,
            ingress_port=3,
            description="Test 3: DHCP from unknown MAC/port - SHOULD DROP"
        ),

        # Test 4: Valid established packet (legitimate traffic)
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="00:00:00:00:01:02",
            src_ip="10.0.1.1",
            dst_ip="10.0.1.2",
            protocol=PROTOCOL_TCP,
            src_port=50000,
            dst_port=80,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=1,
            description="Test 4: Valid packet from h1 (IP+MAC+port match) - SHOULD FORWARD"
        ),

        # Test 5: Spoofed IP (IP not in binding table)
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="10.0.1.3",  # Non-existent IP
            dst_ip="10.0.1.2",
            protocol=PROTOCOL_TCP,
            src_port=50000,
            dst_port=1234,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=1,
            description="Test 5: Spoofed IP (10.0.1.3 doesn't exist) - SHOULD DROP"
        ),

        # Test 6: MAC spoofing (valid IP, forged MAC)
        Packet(
            src_mac="00:00:00:00:aa:aa",  # Forged MAC
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="10.0.1.1",  # Valid IP for h1
            dst_ip="10.0.1.2",
            protocol=PROTOCOL_TCP,
            src_port=50000,
            dst_port=1234,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=1,
            description="Test 6: MAC spoofing (valid IP, forged MAC) - SHOULD DROP"
        ),

        # Test 7: Port hopping (valid IP+MAC, wrong port)
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="10.0.1.1",
            dst_ip="10.0.1.2",
            protocol=PROTOCOL_TCP,
            src_port=50000,
            dst_port=1234,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=3,  # Wrong port (should be 1)
            description="Test 7: Port hopping (valid IP+MAC, wrong ingress port) - SHOULD DROP"
        ),

        # Test 8: Valid packet from h2
        Packet(
            src_mac="00:00:00:00:01:02",
            dst_mac="00:00:00:00:01:01",
            src_ip="10.0.1.2",
            dst_ip="10.0.1.1",
            protocol=PROTOCOL_TCP,
            src_port=80,
            dst_port=50000,
            tcp_flags=TCP_FLAG_SYN | TCP_FLAG_ACK,
            ingress_port=2,
            description="Test 8: Valid SYN-ACK response from h2 - SHOULD FORWARD"
        ),

        # Test 9: UDP traffic from valid host
        Packet(
            src_mac="00:00:00:00:01:01",
            dst_mac="00:00:00:00:01:02",
            src_ip="10.0.1.1",
            dst_ip="10.0.1.2",
            protocol=PROTOCOL_UDP,
            src_port=12345,
            dst_port=53,
            ingress_port=1,
            description="Test 9: Valid UDP (DNS) from h1 - SHOULD FORWARD"
        ),

        # Test 10: Completely unknown attacker
        Packet(
            src_mac="de:ad:be:ef:ca:fe",
            dst_mac="00:00:00:00:01:01",
            src_ip="192.168.100.50",
            dst_ip="10.0.1.1",
            protocol=PROTOCOL_TCP,
            src_port=55555,
            dst_port=22,
            tcp_flags=TCP_FLAG_SYN,
            ingress_port=5,
            description="Test 10: Unknown attacker from port 5 - SHOULD DROP"
        ),
    ]

    return packets


def run_tests():
    """Run all test cases and display results"""

    print("="*80)
    print("P4 IP SPOOFING DEFENSE - SIMULATION TEST")
    print("Based on: 'Data-Plane Security Applications in Adversarial Settings'")
    print("          by Wang, Mittal, Rexford (Princeton University)")
    print("="*80)

    # Initialize security module
    defense = IPSpoofingDefense()

    # Load configuration
    print("\n[1] LOADING RUNTIME CONFIGURATION")
    print("-"*50)
    defense.load_runtime_config("s1-runtime-new.json")

    # Also add manual bindings to match the JSON config
    # (in case JSON loading had issues)
    defense.add_binding("10.0.1.1", "00:00:00:00:01:01", 1, 2)
    defense.add_binding("10.0.1.2", "00:00:00:00:01:02", 2, 1)
    defense.add_dhcp_allowlist("00:00:00:00:01:01", 1, 2)
    defense.add_dhcp_allowlist("00:00:00:00:01:02", 2, 1)

    # Create test packets
    packets = create_test_packets()

    print("\n[2] PROCESSING TEST PACKETS")
    print("-"*80)

    results = []
    for i, pkt in enumerate(packets, 1):
        decision, reason, counter_idx = defense.process_packet(pkt)
        results.append((pkt, decision, reason, counter_idx))

        # Determine expected result
        expected = "DROP" if "SHOULD DROP" in pkt.description else "FORWARD"
        status = "PASS" if decision.value == expected else "FAIL"
        status_icon = "[OK]" if status == "PASS" else "[XX]"

        print(f"\nTest {i}: {pkt.description.split('-')[0].strip()}")
        print(f"  Packet: srcIP={pkt.src_ip}, srcMAC={pkt.src_mac}, port={pkt.ingress_port}")
        print(f"  Protocol: {'TCP' if pkt.protocol == PROTOCOL_TCP else 'UDP' if pkt.protocol == PROTOCOL_UDP else 'ICMP'}")
        print(f"  Decision: {decision.value} (counter[{counter_idx}])")
        print(f"  Reason: {reason}")
        print(f"  Result: {status_icon} {status}")

    # Print statistics
    defense.counters.print_stats()

    # Summary
    print("\n[3] TEST SUMMARY")
    print("-"*50)

    passed = 0
    failed = 0
    for pkt, decision, _, _ in results:
        expected = "DROP" if "SHOULD DROP" in pkt.description else "FORWARD"
        if decision.value == expected:
            passed += 1
        else:
            failed += 1

    total = len(results)

    print(f"Total Tests:    {total}")
    print(f"Passed:         {passed}")
    print(f"Failed:         {failed}")
    print(f"Success Rate:   {passed/total*100:.1f}%")

    print("\n[4] SECURITY EFFECTIVENESS")
    print("-"*50)
    print(f"Legitimate packets forwarded:  {defense.counters.legitimate_established + defense.counters.dhcp_bootstrap}")
    print(f"Attack packets blocked:        {defense.counters.spoofed_dropped + defense.counters.unbound_non_dhcp}")

    print("\n[5] PAPER REFERENCE - ATTACK SCENARIOS TESTED")
    print("-"*50)
    print("Issue 1 (Coarse-grained keys): Tests 5-7 verify fine-grained binding")
    print("Issue 2 (DHCP abuse):          Tests 1-3 verify bootstrap protection")
    print("Challenge C (State visibility): TCP flag tracking demonstrated")

    print("\n" + "="*80)
    print("SIMULATION COMPLETE")
    print("="*80)

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
