# Data Plane Security with P4: IP Spoofing Defense

A P4 implementation of IP spoofing defense mechanisms based on the research paper **"Data-Plane Security Applications in Adversarial Settings"** by Wang, Mittal, and Rexford (Princeton University).

## Overview

This project implements a security-hardened IP source guard in P4 that defends against IP spoofing attacks using **multi-factor binding authentication** at the data plane level.

### Key Features

✅ **Multi-Factor Binding**: Validates (source IP, source MAC, ingress port) tuple
✅ **Protocol Support**: IPv4, TCP, UDP, ICMP
✅ **TCP State Tracking**: Monitors TCP flags and connection state
✅ **DHCP Bootstrap Protection**: Secure handling of unbound clients
✅ **Security Monitoring**: 10 counters for attack visibility
✅ **Checksum Verification**: IPv4 header validation

## Files

```
├── ip-spoofing-defense.p4       # Enhanced P4 implementation (recommended)
├── ip-source-guard.p4           # Original basic implementation
├── s1-runtime-new.json          # Runtime config for enhanced version
├── s1-runtime.json              # Runtime config for basic version
├── topology.json                # Network topology definition
├── client.py                    # Packet sender for testing
├── server.py                    # Packet receiver for testing
├── SECURITY_ANALYSIS.md         # Detailed security analysis
└── IMPLEMENTATION_NOTES.md      # Implementation notes
```

## P4 Program Architecture

### Enhanced Version (ip-spoofing-defense.p4)

**Parser Pipeline**:
```
Ethernet → IPv4 → TCP/UDP/ICMP
```

**Ingress Processing**:
1. Initialize metadata (TCP flags, DHCP detection)
2. Classify packet type
3. Check rate limits
4. Validate binding:
   - If srcIP == 0.0.0.0: Check DHCP allowlist
   - Else: Check established binding table (IP+MAC+port)
5. Track TCP connections
6. Forward or drop with counter updates

**Tables**:
- `establish_binding`: (srcIP, srcMAC, ingressPort) → forward/drop
- `dhcp_allowlist`: (srcMAC, ingressPort) → forward/drop
- `tcp_connection_track`: (srcIP, dstIP, srcPort, dstPort) → monitor

**Counters** (10 total):
- [0] Legitimate established packets
- [1] DHCP bootstrap packets
- [2] Spoofed/invalid packets **← ATTACKS BLOCKED**
- [3] Unbound non-DHCP packets
- [4-6] TCP SYN/SYN-ACK/ACK
- [7] Rate limited packets
- [8] Invalid protocol packets
- [9] Checksum failures

## Compilation

### Requirements
- P4 compiler (p4c)
- BMv2 switch (simple_switch) or hardware P4 switch
- Mininet (for testing)

### Compile P4 Program

```bash
# Compile to BMv2 JSON
p4c --target bmv2 --arch v1model \
    -o build/ip-spoofing-defense.json \
    ip-spoofing-defense.p4

# Generate P4Info (for P4Runtime)
p4c --target bmv2 --arch v1model \
    --p4runtime-files build/ip-spoofing-defense.p4info \
    ip-spoofing-defense.p4
```

## Deployment

### Option 1: BMv2 Simple Switch

```bash
# Start switch with 2 ports
sudo simple_switch \
    -i 0@veth0 -i 1@veth2 \
    --log-console --log-level debug \
    build/ip-spoofing-defense.json

# Load runtime configuration
simple_switch_CLI < s1-runtime-new.json
```

### Option 2: Mininet Integration

```bash
# Start topology
sudo python3 -c "
from mininet.net import Mininet
from mininet.topo import Topo

class IPSpoofingTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=P4Switch, sw_path='simple_switch',
                            json_path='build/ip-spoofing-defense.json')
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:01:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:01:02')
        self.addLink(h1, s1, port1=0, port2=1)
        self.addLink(h2, s1, port1=0, port2=2)

net = Mininet(topo=IPSpoofingTopo())
net.start()
net['s1'].cmd('simple_switch_CLI < s1-runtime-new.json')
CLI(net)
"
```

## Testing

### 1. Start Packet Receiver (Host h2)
```bash
sudo python3 server.py
```

### 2. Send Test Packets (Host h1)
```bash
sudo python3 client.py
```

### 3. Monitor Security Counters
```bash
# Open switch CLI
simple_switch_CLI

# Read counters
counter_read IngressProcess.security_stats 0   # Legitimate
counter_read IngressProcess.security_stats 2   # Spoofed (attacks)
counter_read IngressProcess.security_stats 3   # Unbound non-DHCP
```

## Expected Results

The client.py script sends 6 test packets:

| Packet | Description | Expected Result |
|--------|-------------|-----------------|
| 1 | srcIP=0.0.0.0, TCP (non-DHCP) | **DROPPED** (counter[3]++) |
| 2 | srcIP=0.0.0.0, DHCP Discover | **FORWARDED** (counter[1]++) |
| 3 | Valid IP, DHCP Request | **FORWARDED** (counter[0/1]++) |
| 4 | Valid IP+MAC+port, TCP | **FORWARDED** (counter[0]++) |
| 5 | Spoofed IP (10.0.1.3) | **DROPPED** (counter[2]++) |
| 6 | Valid IP, forged MAC | **DROPPED** (counter[2]++) |

**Security Effectiveness**:
- Legitimate packets: 3/6 forwarded ✅
- Attack packets: 3/6 blocked ✅

## Security Features

### 1. Multi-Factor Binding
Traditional IP source guards only check source IP. This implementation checks:
- Source IP address
- Source MAC address
- Ingress port

All three must match for packet forwarding.

### 2. DHCP Bootstrap Protection
During DHCP phase (srcIP = 0.0.0.0):
- Only permits known (MAC, port) combinations
- Only allows DHCP protocol (UDP 68→67)
- Drops all other traffic

### 3. TCP Connection Awareness
- Tracks TCP flags (SYN, ACK, RST, FIN)
- Enables SYN flood detection
- Foundation for stateful firewall

### 4. Rate Limiting Framework
- Per-source packet rate limiting
- Token bucket approximation
- Protects against flood attacks

## Runtime Configuration

The `s1-runtime-new.json` file configures:

**Established Client Bindings**:
```json
{
  "table": "IngressProcess.establish_binding",
  "match": {
    "hdr.ipv4.srcAddr": "10.0.1.1",
    "hdr.ethernet.srcAddr": "00:00:00:00:01:01",
    "standard_metadata.ingress_port": 1
  },
  "action_name": "IngressProcess.forward_established"
}
```

**DHCP Client Allowlist**:
```json
{
  "table": "IngressProcess.dhcp_allowlist",
  "match": {
    "hdr.ethernet.srcAddr": "00:00:00:00:01:01",
    "standard_metadata.ingress_port": 1
  },
  "action_name": "IngressProcess.forward_dhcp"
}
```

## Attack Scenarios Prevented

1. **Simple IP Spoofing**: Attacker forges source IP → Dropped (no matching binding)
2. **MAC Spoofing**: Attacker forges MAC with valid IP → Dropped (MAC mismatch)
3. **Port Hopping**: Attacker moves to different port → Dropped (port mismatch)
4. **DHCP Phase Abuse**: Non-DHCP traffic during bootstrap → Dropped
5. **TCP SYN Flood**: High-rate SYN packets → Rate limited
6. **Reflective Amplification**: Spoofed source for DDoS → Dropped

## Performance Considerations

### Memory Usage
- **establish_binding table**: 1024 entries (configurable)
- **dhcp_allowlist table**: 1024 entries
- **tcp_connection_track table**: 2048 entries
- **Total counters**: 10 × (packet count + byte count)

### Throughput
- **Parser overhead**: +3 headers (IPv4, TCP/UDP, ICMP)
- **Table lookups**: 1-2 per packet (DHCP or established)
- **Expected line-rate**: Yes (on hardware switches)

## Limitations

1. **Static Bindings**: Requires manual configuration (use DHCP snooping for dynamic)
2. **No Cryptographic Auth**: Relies on network-layer identifiers only
3. **Limited TCP State**: Basic flag tracking, not full state machine
4. **Rate Limiting**: Basic implementation, not production-grade
5. **Control Plane**: No integration for dynamic updates

See `SECURITY_ANALYSIS.md` for detailed limitation analysis.

## Research Foundation

This implementation addresses key vulnerabilities from the paper:

- **Issue 1 (Coarse-Grained Keys)**: Uses fine-grained (IP, MAC, port) binding
- **Issue 2 (Missing Validation)**: Implements protocol and checksum checks
- **Challenge C (State Visibility)**: Multi-layer validation and TCP tracking
- **Security Principle**: "Security over Performance" - accepts memory costs for security

## References

1. **Wang, L., Mittal, P., & Rexford, J.** (2021). "Data-Plane Security Applications in Adversarial Settings". Princeton University.

2. **Ferguson, P., & Senie, D.** (2000). "Network Ingress Filtering" (RFC 2827 / BCP 38).

3. **Jin, C., Wang, H., & Shin, K. G.** (2003). "Hop-count filtering: an effective defense against spoofed DDoS traffic". ACM CCS.

4. **P4 Language Specification** v1.2.3 - P4 Language Consortium.

## License

Educational use only. Not production-ready without extensive testing and hardening.

---

**Core Principle**: *In adversarial contexts, security must be prioritized over performance. Fine-grained state tracking and complete protocol implementation are essential for robust network security.*
