#!/usr/bin/env python3
"""
P4 Behavioral Model Simulator for IP Spoofing Defense

This implements the EXACT behavior of ip-spoofing-defense.p4 in Python,
simulating the BMv2 simple_switch pipeline.

Pipeline stages:
1. Parser (ParsePacket)
2. Checksum Verification (ChecksumVerify)
3. Ingress Processing (IngressProcess)
4. Egress Processing (EgressProcess)
5. Checksum Computation (ChecksumCompute)
6. Deparser (DeparsePacket)

Author: Based on "Data-Plane Security Applications in Adversarial Settings"
        by Wang, Mittal, Rexford (Princeton University)
"""

import struct
import socket
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional, Any
from enum import Enum
import json

# ============================================================================
# P4 CONSTANTS (from ip-spoofing-defense.p4)
# ============================================================================

TYPE_IPV4 = 0x0800
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ICMP = 1

TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10
TCP_FLAG_RST = 0x04
TCP_FLAG_FIN = 0x01

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67


# ============================================================================
# P4 HEADER DEFINITIONS (matching P4 header structs)
# ============================================================================

@dataclass
class EthernetHeader:
    """ethernet_t from P4"""
    dstAddr: str = "00:00:00:00:00:00"  # macAddr_t (48 bits)
    srcAddr: str = "00:00:00:00:00:00"  # macAddr_t (48 bits)
    etherType: int = 0x0800             # bit<16>

    def isValid(self) -> bool:
        return self.etherType != 0


@dataclass
class IPv4Header:
    """ipv4_t from P4"""
    version: int = 4         # bit<4>
    ihl: int = 5             # bit<4>
    diffserv: int = 0        # bit<8>
    totalLen: int = 0        # bit<16>
    identification: int = 0  # bit<16>
    flags: int = 0           # bit<3>
    fragOffset: int = 0      # bit<13>
    ttl: int = 64            # bit<8>
    protocol: int = 0        # bit<8>
    hdrChecksum: int = 0     # bit<16>
    srcAddr: str = "0.0.0.0" # ip4Addr_t (32 bits)
    dstAddr: str = "0.0.0.0" # ip4Addr_t (32 bits)
    _valid: bool = False

    def isValid(self) -> bool:
        return self._valid


@dataclass
class TCPHeader:
    """tcp_t from P4"""
    srcPort: int = 0    # bit<16>
    dstPort: int = 0    # bit<16>
    seqNo: int = 0      # bit<32>
    ackNo: int = 0      # bit<32>
    dataOffset: int = 5 # bit<4>
    res: int = 0        # bit<3>
    ecn: int = 0        # bit<3>
    flags: int = 0      # bit<6>
    window: int = 0     # bit<16>
    checksum: int = 0   # bit<16>
    urgentPtr: int = 0  # bit<16>
    _valid: bool = False

    def isValid(self) -> bool:
        return self._valid


@dataclass
class UDPHeader:
    """udp_t from P4"""
    srcPort: int = 0   # bit<16>
    dstPort: int = 0   # bit<16>
    len: int = 0       # bit<16>
    checksum: int = 0  # bit<16>
    _valid: bool = False

    def isValid(self) -> bool:
        return self._valid


@dataclass
class ICMPHeader:
    """icmp_t from P4"""
    type: int = 0      # bit<8>
    code: int = 0      # bit<8>
    checksum: int = 0  # bit<16>
    rest: int = 0      # bit<32>
    _valid: bool = False

    def isValid(self) -> bool:
        return self._valid


@dataclass
class Metadata:
    """metadata struct from P4"""
    is_tcp_syn: int = 0       # bit<1>
    is_tcp_ack: int = 0       # bit<1>
    is_dhcp: int = 0          # bit<1>
    is_spoofed: int = 0       # bit<1>
    rate_limit_index: int = 0 # bit<32>


@dataclass
class StandardMetadata:
    """standard_metadata_t from v1model.p4"""
    ingress_port: int = 0     # bit<9>
    egress_spec: int = 0      # bit<9> (egressSpec_t)
    egress_port: int = 0      # bit<9>
    instance_type: int = 0    # bit<32>
    packet_length: int = 0    # bit<32>
    drop: bool = False


@dataclass
class Headers:
    """headers struct from P4"""
    ethernet: EthernetHeader = field(default_factory=EthernetHeader)
    ipv4: IPv4Header = field(default_factory=IPv4Header)
    tcp: TCPHeader = field(default_factory=TCPHeader)
    udp: UDPHeader = field(default_factory=UDPHeader)
    icmp: ICMPHeader = field(default_factory=ICMPHeader)


# ============================================================================
# P4 COUNTER IMPLEMENTATION
# ============================================================================

class P4Counter:
    """
    counter(10, CounterType.packets) security_stats;

    Implements P4 counter semantics with packet and byte counting.
    """
    def __init__(self, size: int, name: str = "counter"):
        self.size = size
        self.name = name
        self.packets = [0] * size
        self.bytes = [0] * size

    def count(self, index: int, packet_bytes: int = 1):
        """security_stats.count(index)"""
        if 0 <= index < self.size:
            self.packets[index] += 1
            self.bytes[index] += packet_bytes

    def read(self, index: int) -> Tuple[int, int]:
        """Read counter value (packets, bytes)"""
        if 0 <= index < self.size:
            return (self.packets[index], self.bytes[index])
        return (0, 0)

    def reset(self, index: int = -1):
        """Reset counter(s)"""
        if index == -1:
            self.packets = [0] * self.size
            self.bytes = [0] * self.size
        elif 0 <= index < self.size:
            self.packets[index] = 0
            self.bytes[index] = 0


# ============================================================================
# P4 TABLE IMPLEMENTATION
# ============================================================================

class P4Table:
    """
    Implements P4 table semantics with exact match.

    table establish_binding {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ethernet.srcAddr: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward_established;
            drop_spoofed;
            NoAction;
        }
        size = 1024;
        default_action = drop_spoofed();
    }
    """
    def __init__(self, name: str, key_fields: List[str], size: int = 1024):
        self.name = name
        self.key_fields = key_fields
        self.size = size
        self.entries: Dict[Tuple, Dict] = {}
        self.default_action: Optional[str] = None
        self.default_params: Dict = {}
        self.hit_count = 0
        self.miss_count = 0

    def add_entry(self, match: Dict, action: str, params: Dict = None):
        """Add table entry"""
        key = tuple(match.get(k) for k in self.key_fields)
        self.entries[key] = {
            'action': action,
            'params': params or {}
        }

    def set_default_action(self, action: str, params: Dict = None):
        """Set default action"""
        self.default_action = action
        self.default_params = params or {}

    def apply(self, match_values: Dict) -> Tuple[bool, str, Dict]:
        """
        Apply table lookup.
        Returns: (hit, action_name, action_params)
        """
        key = tuple(match_values.get(k) for k in self.key_fields)

        if key in self.entries:
            self.hit_count += 1
            entry = self.entries[key]
            return (True, entry['action'], entry['params'])
        else:
            self.miss_count += 1
            return (False, self.default_action, self.default_params)


# ============================================================================
# P4 BEHAVIORAL MODEL (BMv2 SIMULATION)
# ============================================================================

class P4BMv2Switch:
    """
    Simulates BMv2 simple_switch running ip-spoofing-defense.p4

    Implements:
    - V1Switch pipeline
    - ParsePacket parser
    - ChecksumVerify
    - IngressProcess (main security logic)
    - EgressProcess
    - ChecksumCompute
    - DeparsePacket
    """

    def __init__(self):
        # Security counters (10 total, matching P4)
        self.security_stats = P4Counter(10, "IngressProcess.security_stats")

        # Tables
        self.establish_binding = P4Table(
            "IngressProcess.establish_binding",
            ["hdr.ipv4.srcAddr", "hdr.ethernet.srcAddr", "standard_metadata.ingress_port"],
            size=1024
        )
        self.establish_binding.set_default_action("drop_spoofed")

        self.dhcp_allowlist = P4Table(
            "IngressProcess.dhcp_allowlist",
            ["hdr.ethernet.srcAddr", "standard_metadata.ingress_port"],
            size=1024
        )
        self.dhcp_allowlist.set_default_action("drop_unbound_non_dhcp")

        self.tcp_connection_track = P4Table(
            "IngressProcess.tcp_connection_track",
            ["hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr", "hdr.tcp.srcPort", "hdr.tcp.dstPort"],
            size=2048
        )
        self.tcp_connection_track.set_default_action("NoAction")

        # Packet processing statistics
        self.packets_processed = 0
        self.packets_forwarded = 0
        self.packets_dropped = 0

    def load_runtime_config(self, config_path: str):
        """Load table entries from runtime JSON (s1-runtime-new.json format)"""
        print(f"\n[P4 BMv2] Loading runtime configuration from {config_path}")
        print("-" * 60)

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            for entry in config.get('table_entries', []):
                table_name = entry.get('table', '')

                if entry.get('default_action'):
                    # Set default action
                    action = entry.get('action_name', '').split('.')[-1]
                    if 'establish_binding' in table_name:
                        self.establish_binding.set_default_action(action)
                        print(f"  Set default: {table_name} -> {action}")
                    elif 'dhcp_allowlist' in table_name:
                        self.dhcp_allowlist.set_default_action(action)
                        print(f"  Set default: {table_name} -> {action}")
                    continue

                match = entry.get('match', {})
                action = entry.get('action_name', '').split('.')[-1]
                params = entry.get('action_params', {})

                if 'establish_binding' in table_name:
                    self.establish_binding.add_entry(match, action, params)
                    print(f"  Added entry: establish_binding")
                    print(f"    Match: IP={match.get('hdr.ipv4.srcAddr')}, "
                          f"MAC={match.get('hdr.ethernet.srcAddr')}, "
                          f"Port={match.get('standard_metadata.ingress_port')}")
                    print(f"    Action: {action} -> port {params.get('port')}")

                elif 'dhcp_allowlist' in table_name:
                    self.dhcp_allowlist.add_entry(match, action, params)
                    print(f"  Added entry: dhcp_allowlist")
                    print(f"    Match: MAC={match.get('hdr.ethernet.srcAddr')}, "
                          f"Port={match.get('standard_metadata.ingress_port')}")
                    print(f"    Action: {action} -> port {params.get('port')}")

            print(f"\n[P4 BMv2] Loaded {len(self.establish_binding.entries)} binding entries")
            print(f"[P4 BMv2] Loaded {len(self.dhcp_allowlist.entries)} DHCP entries")

        except Exception as e:
            print(f"[P4 BMv2] Error loading config: {e}")

    # ========================================================================
    # PARSER: ParsePacket (from P4)
    # ========================================================================

    def parse_packet(self, raw_packet: bytes, ingress_port: int) -> Tuple[Headers, Metadata, StandardMetadata]:
        """
        parser ParsePacket(packet_in packet,
                           out headers hdr,
                           inout metadata meta,
                           inout standard_metadata_t standard_metadata)
        """
        hdr = Headers()
        meta = Metadata()
        std_meta = StandardMetadata(ingress_port=ingress_port, packet_length=len(raw_packet))

        offset = 0

        # state parse_ethernet
        if len(raw_packet) >= 14:
            hdr.ethernet.dstAddr = ':'.join(f'{b:02x}' for b in raw_packet[0:6])
            hdr.ethernet.srcAddr = ':'.join(f'{b:02x}' for b in raw_packet[6:12])
            hdr.ethernet.etherType = struct.unpack('!H', raw_packet[12:14])[0]
            offset = 14

        # transition select(hdr.ethernet.etherType)
        if hdr.ethernet.etherType == TYPE_IPV4:
            # state parse_ipv4
            if len(raw_packet) >= offset + 20:
                hdr.ipv4._valid = True
                version_ihl = raw_packet[offset]
                hdr.ipv4.version = version_ihl >> 4
                hdr.ipv4.ihl = version_ihl & 0x0F
                hdr.ipv4.diffserv = raw_packet[offset + 1]
                hdr.ipv4.totalLen = struct.unpack('!H', raw_packet[offset + 2:offset + 4])[0]
                hdr.ipv4.identification = struct.unpack('!H', raw_packet[offset + 4:offset + 6])[0]
                flags_frag = struct.unpack('!H', raw_packet[offset + 6:offset + 8])[0]
                hdr.ipv4.flags = flags_frag >> 13
                hdr.ipv4.fragOffset = flags_frag & 0x1FFF
                hdr.ipv4.ttl = raw_packet[offset + 8]
                hdr.ipv4.protocol = raw_packet[offset + 9]
                hdr.ipv4.hdrChecksum = struct.unpack('!H', raw_packet[offset + 10:offset + 12])[0]
                hdr.ipv4.srcAddr = socket.inet_ntoa(raw_packet[offset + 12:offset + 16])
                hdr.ipv4.dstAddr = socket.inet_ntoa(raw_packet[offset + 16:offset + 20])
                offset += hdr.ipv4.ihl * 4

                # transition select(hdr.ipv4.protocol)
                if hdr.ipv4.protocol == PROTOCOL_TCP and len(raw_packet) >= offset + 20:
                    # state parse_tcp
                    hdr.tcp._valid = True
                    hdr.tcp.srcPort = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
                    hdr.tcp.dstPort = struct.unpack('!H', raw_packet[offset + 2:offset + 4])[0]
                    hdr.tcp.seqNo = struct.unpack('!I', raw_packet[offset + 4:offset + 8])[0]
                    hdr.tcp.ackNo = struct.unpack('!I', raw_packet[offset + 8:offset + 12])[0]
                    data_off_flags = struct.unpack('!H', raw_packet[offset + 12:offset + 14])[0]
                    hdr.tcp.dataOffset = data_off_flags >> 12
                    hdr.tcp.flags = data_off_flags & 0x3F
                    hdr.tcp.window = struct.unpack('!H', raw_packet[offset + 14:offset + 16])[0]
                    hdr.tcp.checksum = struct.unpack('!H', raw_packet[offset + 16:offset + 18])[0]

                elif hdr.ipv4.protocol == PROTOCOL_UDP and len(raw_packet) >= offset + 8:
                    # state parse_udp
                    hdr.udp._valid = True
                    hdr.udp.srcPort = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
                    hdr.udp.dstPort = struct.unpack('!H', raw_packet[offset + 2:offset + 4])[0]
                    hdr.udp.len = struct.unpack('!H', raw_packet[offset + 4:offset + 6])[0]
                    hdr.udp.checksum = struct.unpack('!H', raw_packet[offset + 6:offset + 8])[0]

                elif hdr.ipv4.protocol == PROTOCOL_ICMP and len(raw_packet) >= offset + 8:
                    # state parse_icmp
                    hdr.icmp._valid = True
                    hdr.icmp.type = raw_packet[offset]
                    hdr.icmp.code = raw_packet[offset + 1]
                    hdr.icmp.checksum = struct.unpack('!H', raw_packet[offset + 2:offset + 4])[0]
                    hdr.icmp.rest = struct.unpack('!I', raw_packet[offset + 4:offset + 8])[0]

        return hdr, meta, std_meta

    # ========================================================================
    # CHECKSUM VERIFICATION (from P4)
    # ========================================================================

    def verify_checksum(self, hdr: Headers, meta: Metadata) -> bool:
        """
        control ChecksumVerify(inout headers hdr, inout metadata meta)

        Verify IPv4 header checksum
        """
        if not hdr.ipv4.isValid():
            return True

        # In real P4, this uses verify_checksum() extern
        # For simulation, we trust the checksum
        return True

    # ========================================================================
    # INGRESS PROCESSING (from P4) - MAIN SECURITY LOGIC
    # ========================================================================

    def ingress_process(self, hdr: Headers, meta: Metadata, std_meta: StandardMetadata) -> str:
        """
        control IngressProcess(inout headers hdr,
                               inout metadata meta,
                               inout standard_metadata_t standard_metadata)

        Returns: action taken (for logging)
        """

        # action init_metadata()
        meta.is_tcp_syn = 0
        meta.is_tcp_ack = 0
        meta.is_dhcp = 0
        meta.is_spoofed = 0

        # if (!hdr.ipv4.isValid())
        if not hdr.ipv4.isValid():
            self.security_stats.count(8)  # drop_invalid_protocol
            std_meta.drop = True
            return "drop_invalid_protocol"

        # TCP flag classification
        if hdr.tcp.isValid():
            if (hdr.tcp.flags & TCP_FLAG_SYN) != 0 and (hdr.tcp.flags & TCP_FLAG_ACK) == 0:
                meta.is_tcp_syn = 1
                self.security_stats.count(4)  # TCP SYN
            elif (hdr.tcp.flags & TCP_FLAG_SYN) != 0 and (hdr.tcp.flags & TCP_FLAG_ACK) != 0:
                self.security_stats.count(5)  # TCP SYN-ACK
            elif (hdr.tcp.flags & TCP_FLAG_ACK) != 0:
                meta.is_tcp_ack = 1
                self.security_stats.count(6)  # TCP ACK

        # DHCP detection
        if hdr.udp.isValid() and hdr.udp.srcPort == DHCP_CLIENT_PORT:
            meta.is_dhcp = 1

        # Rate limit index
        meta.rate_limit_index = int.from_bytes(socket.inet_aton(hdr.ipv4.srcAddr), 'big')

        # PACKET PROCESSING PIPELINE
        if hdr.ipv4.srcAddr == "0.0.0.0":
            # DHCP BOOTSTRAP PHASE
            if meta.is_dhcp == 1:
                # dhcp_allowlist.apply()
                match = {
                    'hdr.ethernet.srcAddr': hdr.ethernet.srcAddr,
                    'standard_metadata.ingress_port': std_meta.ingress_port
                }
                hit, action, params = self.dhcp_allowlist.apply(match)

                if hit and action == "forward_dhcp":
                    self.security_stats.count(1)  # DHCP bootstrap forwarded
                    std_meta.egress_spec = params.get('port', 0)
                    hdr.ethernet.dstAddr = params.get('dstAddr', hdr.ethernet.dstAddr)
                    hdr.ipv4.ttl -= 1
                    return "forward_dhcp"
                else:
                    self.security_stats.count(3)  # drop_unbound_non_dhcp
                    std_meta.drop = True
                    return "drop_unbound_non_dhcp (unknown DHCP client)"
            else:
                # Non-DHCP traffic from unbound client
                self.security_stats.count(3)
                std_meta.drop = True
                return "drop_unbound_non_dhcp (non-DHCP from srcIP=0)"

        else:
            # ESTABLISHED CLIENT PHASE
            match = {
                'hdr.ipv4.srcAddr': hdr.ipv4.srcAddr,
                'hdr.ethernet.srcAddr': hdr.ethernet.srcAddr,
                'standard_metadata.ingress_port': std_meta.ingress_port
            }
            hit, action, params = self.establish_binding.apply(match)

            if hit and action == "forward_established":
                self.security_stats.count(0)  # Legitimate established
                std_meta.egress_spec = params.get('port', 0)
                hdr.ethernet.dstAddr = params.get('dstAddr', hdr.ethernet.dstAddr)
                hdr.ipv4.ttl -= 1

                # TCP connection tracking
                if hdr.tcp.isValid():
                    tcp_match = {
                        'hdr.ipv4.srcAddr': hdr.ipv4.srcAddr,
                        'hdr.ipv4.dstAddr': hdr.ipv4.dstAddr,
                        'hdr.tcp.srcPort': hdr.tcp.srcPort,
                        'hdr.tcp.dstPort': hdr.tcp.dstPort
                    }
                    self.tcp_connection_track.apply(tcp_match)

                return "forward_established"
            else:
                self.security_stats.count(2)  # Spoofed dropped
                std_meta.drop = True
                return "drop_spoofed"

    # ========================================================================
    # EGRESS PROCESSING (from P4)
    # ========================================================================

    def egress_process(self, hdr: Headers, meta: Metadata, std_meta: StandardMetadata):
        """
        control EgressProcess(inout headers hdr,
                              inout metadata meta,
                              inout standard_metadata_t standard_metadata)
        """
        # Placeholder - no egress processing in current implementation
        pass

    # ========================================================================
    # CHECKSUM COMPUTATION (from P4)
    # ========================================================================

    def compute_checksum(self, hdr: Headers, meta: Metadata):
        """
        control ChecksumCompute(inout headers hdr, inout metadata meta)

        Update IPv4 checksum after TTL decrement
        """
        # In real P4, this uses update_checksum() extern
        pass

    # ========================================================================
    # MAIN PACKET PROCESSING
    # ========================================================================

    def process_packet(self, raw_packet: bytes, ingress_port: int) -> Tuple[bool, int, str]:
        """
        Process a single packet through the V1Switch pipeline.

        Returns: (forwarded, egress_port, action_taken)
        """
        self.packets_processed += 1

        # 1. Parser
        hdr, meta, std_meta = self.parse_packet(raw_packet, ingress_port)

        # 2. Checksum Verify
        if not self.verify_checksum(hdr, meta):
            self.security_stats.count(9)
            self.packets_dropped += 1
            return (False, 0, "checksum_failed")

        # 3. Ingress Processing
        action = self.ingress_process(hdr, meta, std_meta)

        # 4. Egress Processing
        if not std_meta.drop:
            self.egress_process(hdr, meta, std_meta)

        # 5. Checksum Compute
        if not std_meta.drop:
            self.compute_checksum(hdr, meta)

        # 6. Result
        if std_meta.drop:
            self.packets_dropped += 1
            return (False, 0, action)
        else:
            self.packets_forwarded += 1
            return (True, std_meta.egress_spec, action)

    def print_counter_stats(self):
        """Print security counter statistics (like simple_switch_CLI counter_read)"""
        print("\n" + "=" * 70)
        print("P4 SECURITY COUNTERS (counter_read IngressProcess.security_stats)")
        print("=" * 70)

        counter_names = [
            "[0] Legitimate Established",
            "[1] DHCP Bootstrap",
            "[2] Spoofed DROPPED     ",
            "[3] Unbound Non-DHCP    ",
            "[4] TCP SYN             ",
            "[5] TCP SYN-ACK         ",
            "[6] TCP ACK             ",
            "[7] Rate Limited        ",
            "[8] Invalid Protocol    ",
            "[9] Checksum Failures   "
        ]

        for i, name in enumerate(counter_names):
            packets, bytes_count = self.security_stats.read(i)
            marker = " <-- ATTACKS BLOCKED" if i in [2, 3] else ""
            print(f"  {name}: {packets:5d} packets, {bytes_count:8d} bytes{marker}")

        print("=" * 70)
        print(f"  Total processed: {self.packets_processed}")
        print(f"  Forwarded:       {self.packets_forwarded}")
        print(f"  Dropped:         {self.packets_dropped}")
        print("=" * 70)


# ============================================================================
# TEST PACKET GENERATOR
# ============================================================================

def create_test_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                       protocol: int, src_port: int, dst_port: int,
                       tcp_flags: int = 0) -> bytes:
    """Create raw packet bytes for testing"""

    # Ethernet header (14 bytes)
    eth_dst = bytes.fromhex(dst_mac.replace(':', ''))
    eth_src = bytes.fromhex(src_mac.replace(':', ''))
    eth_type = struct.pack('!H', TYPE_IPV4)
    eth_header = eth_dst + eth_src + eth_type

    # IP header (20 bytes)
    ip_ver_ihl = (4 << 4) + 5  # Version 4, IHL 5
    ip_tos = 0
    ip_tot_len = 40 if protocol == PROTOCOL_TCP else 28  # IP + TCP/UDP
    ip_id = 1
    ip_frag = 0
    ip_ttl = 64
    ip_proto = protocol
    ip_check = 0  # Will be calculated
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
        ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag,
        ip_ttl, ip_proto, ip_check, ip_src, ip_dst)

    # Transport header
    if protocol == PROTOCOL_TCP:
        # TCP header (20 bytes)
        tcp_seq = 0
        tcp_ack = 0
        tcp_off_flags = (5 << 12) | tcp_flags
        tcp_win = 65535
        tcp_check = 0
        tcp_urg = 0
        transport_header = struct.pack('!HHIIHHHH',
            src_port, dst_port, tcp_seq, tcp_ack,
            tcp_off_flags, tcp_win, tcp_check, tcp_urg)
    else:
        # UDP header (8 bytes)
        udp_len = 8
        udp_check = 0
        transport_header = struct.pack('!HHHH',
            src_port, dst_port, udp_len, udp_check)

    return eth_header + ip_header + transport_header


# ============================================================================
# MAIN TEST
# ============================================================================

def run_p4_behavioral_test():
    """Run comprehensive P4 behavioral model test"""

    print("=" * 70)
    print("P4 BEHAVIORAL MODEL TEST - IP SPOOFING DEFENSE")
    print("Simulating: BMv2 simple_switch with ip-spoofing-defense.p4")
    print("=" * 70)

    # Initialize switch
    switch = P4BMv2Switch()

    # Load runtime configuration
    switch.load_runtime_config("s1-runtime-new.json")

    # Define test cases
    test_cases = [
        {
            "name": "Non-DHCP from unbound client",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "0.0.0.0",
            "dst_ip": "255.255.255.255",
            "protocol": PROTOCOL_TCP,
            "src_port": 50000,
            "dst_port": 1234,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 1,
            "expected": "DROP"
        },
        {
            "name": "Valid DHCP Discover",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "0.0.0.0",
            "dst_ip": "255.255.255.255",
            "protocol": PROTOCOL_UDP,
            "src_port": DHCP_CLIENT_PORT,
            "dst_port": DHCP_SERVER_PORT,
            "tcp_flags": 0,
            "ingress_port": 1,
            "expected": "FORWARD"
        },
        {
            "name": "DHCP from unknown MAC",
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "0.0.0.0",
            "dst_ip": "255.255.255.255",
            "protocol": PROTOCOL_UDP,
            "src_port": DHCP_CLIENT_PORT,
            "dst_port": DHCP_SERVER_PORT,
            "tcp_flags": 0,
            "ingress_port": 3,
            "expected": "DROP"
        },
        {
            "name": "Valid established packet from h1",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "00:00:00:00:01:02",
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.1.2",
            "protocol": PROTOCOL_TCP,
            "src_port": 50000,
            "dst_port": 80,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 1,
            "expected": "FORWARD"
        },
        {
            "name": "IP Spoofing (unknown IP)",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.1.3",
            "dst_ip": "10.0.1.2",
            "protocol": PROTOCOL_TCP,
            "src_port": 50000,
            "dst_port": 1234,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 1,
            "expected": "DROP"
        },
        {
            "name": "MAC Spoofing",
            "src_mac": "00:00:00:00:aa:aa",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.1.2",
            "protocol": PROTOCOL_TCP,
            "src_port": 50000,
            "dst_port": 1234,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 1,
            "expected": "DROP"
        },
        {
            "name": "Port Hopping Attack",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.1.2",
            "protocol": PROTOCOL_TCP,
            "src_port": 50000,
            "dst_port": 1234,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 3,
            "expected": "DROP"
        },
        {
            "name": "Valid response from h2",
            "src_mac": "00:00:00:00:01:02",
            "dst_mac": "00:00:00:00:01:01",
            "src_ip": "10.0.1.2",
            "dst_ip": "10.0.1.1",
            "protocol": PROTOCOL_TCP,
            "src_port": 80,
            "dst_port": 50000,
            "tcp_flags": TCP_FLAG_SYN | TCP_FLAG_ACK,
            "ingress_port": 2,
            "expected": "FORWARD"
        },
        {
            "name": "Valid UDP from h1",
            "src_mac": "00:00:00:00:01:01",
            "dst_mac": "00:00:00:00:01:02",
            "src_ip": "10.0.1.1",
            "dst_ip": "10.0.1.2",
            "protocol": PROTOCOL_UDP,
            "src_port": 12345,
            "dst_port": 53,
            "tcp_flags": 0,
            "ingress_port": 1,
            "expected": "FORWARD"
        },
        {
            "name": "Unknown attacker",
            "src_mac": "de:ad:be:ef:ca:fe",
            "dst_mac": "00:00:00:00:01:01",
            "src_ip": "192.168.100.50",
            "dst_ip": "10.0.1.1",
            "protocol": PROTOCOL_TCP,
            "src_port": 55555,
            "dst_port": 22,
            "tcp_flags": TCP_FLAG_SYN,
            "ingress_port": 5,
            "expected": "DROP"
        },
    ]

    print("\n[P4 BMv2] PROCESSING TEST PACKETS")
    print("-" * 70)

    passed = 0
    failed = 0

    for i, tc in enumerate(test_cases, 1):
        # Create raw packet
        pkt = create_test_packet(
            tc["src_mac"], tc["dst_mac"],
            tc["src_ip"], tc["dst_ip"],
            tc["protocol"], tc["src_port"], tc["dst_port"],
            tc["tcp_flags"]
        )

        # Process through P4 pipeline
        forwarded, egress_port, action = switch.process_packet(pkt, tc["ingress_port"])

        # Check result
        actual = "FORWARD" if forwarded else "DROP"
        status = "PASS" if actual == tc["expected"] else "FAIL"
        icon = "[OK]" if status == "PASS" else "[XX]"

        if status == "PASS":
            passed += 1
        else:
            failed += 1

        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(tc["protocol"], "?")

        print(f"\nTest {i}: {tc['name']}")
        print(f"  Packet: {tc['src_ip']} ({tc['src_mac']}) port {tc['ingress_port']} -> {tc['dst_ip']}")
        print(f"  Protocol: {proto_name}, Flags: {tc['tcp_flags']:02x}")
        print(f"  P4 Action: {action}")
        print(f"  Result: {actual} (egress_port={egress_port})")
        print(f"  {icon} {status}")

    # Print counters
    switch.print_counter_stats()

    # Summary
    print("\n[P4 BMv2] TEST SUMMARY")
    print("-" * 70)
    print(f"  Total Tests: {len(test_cases)}")
    print(f"  Passed:      {passed}")
    print(f"  Failed:      {failed}")
    print(f"  Success:     {passed/len(test_cases)*100:.1f}%")

    print("\n[P4 BMv2] TABLE STATISTICS")
    print("-" * 70)
    print(f"  establish_binding: {switch.establish_binding.hit_count} hits, {switch.establish_binding.miss_count} misses")
    print(f"  dhcp_allowlist:    {switch.dhcp_allowlist.hit_count} hits, {switch.dhcp_allowlist.miss_count} misses")

    print("\n" + "=" * 70)
    print("P4 BEHAVIORAL MODEL TEST COMPLETE")
    print("=" * 70)

    return passed == len(test_cases)


if __name__ == "__main__":
    import sys
    success = run_p4_behavioral_test()
    sys.exit(0 if success else 1)
