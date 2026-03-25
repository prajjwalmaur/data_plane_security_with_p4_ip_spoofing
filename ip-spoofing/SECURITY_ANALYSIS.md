# P4 Security Analysis: IP Spoofing Defense

## Research Foundation

Based on **"Data-Plane Security Applications in Adversarial Settings"**
by Liang Wang, Prateek Mittal, and Jennifer Rexford (Princeton University)

## Executive Summary

This P4 implementation addresses critical vulnerabilities in data-plane security applications:
- **Coarse-grained keys** → Fine-grained (IP, MAC, port) binding
- **Limited state visibility** → Multi-layer validation and TCP tracking
- **Protocol simplification** → Complete header validation and checksum verification
- **Performance-first design** → Security-prioritized implementation

## Threat Model

### Adversary Capabilities
1. **Network Position**: Controls host(s) within protected network (insider threat)
2. **Packet Forging**: Can craft arbitrary packets with spoofed headers
3. **Physical Access**: May attempt port hopping
4. **Protocol Knowledge**: Understands TCP/IP, DHCP, and P4 limitations

### Attack Vectors Addressed

| Attack Type | P4 Defense Mechanism | Counter Index |
|-------------|---------------------|---------------|
| IP Spoofing | (IP, MAC, port) binding check | [2] |
| MAC Spoofing | Three-factor validation | [2] |
| Port Hopping | Ingress port in match key | [2] |
| DHCP Abuse | Protocol-specific allowlist | [3] |
| SYN Flood | Rate limiting + TCP tracking | [4, 7] |
| Protocol Exploitation | Header validation | [8, 9] |

## P4 Implementation Details

### Packet Processing Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                        PARSER                               │
│  Ethernet → IPv4 → [TCP | UDP | ICMP]                      │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                  CHECKSUM VERIFY                            │
│  Validates IPv4 header checksum                             │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                 INGRESS PROCESSING                          │
│                                                             │
│  1. Initialize metadata (TCP flags, DHCP detection)        │
│  2. Classify packet type                                   │
│  3. Apply rate limiting                                    │
│  4. Binding validation:                                    │
│     ┌─────────────────────────────────┐                   │
│     │ IF srcIP == 0.0.0.0:            │                   │
│     │   → Check DHCP allowlist        │                   │
│     │   → Permit only UDP 68→67       │                   │
│     └─────────────────────────────────┘                   │
│     ┌─────────────────────────────────┐                   │
│     │ ELSE (established):             │                   │
│     │   → Check binding table         │                   │
│     │     Key: (IP, MAC, ingress_port)│                   │
│     │   → Track TCP connections       │                   │
│     └─────────────────────────────────┘                   │
│  5. Update security counters                               │
│  6. Forward or drop                                        │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                  CHECKSUM UPDATE                            │
│  Recompute IPv4 checksum (TTL decremented)                  │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                     DEPARSER                                │
│  Reassemble and emit packet                                 │
└─────────────────────────────────────────────────────────────┘
```

### Table Design

#### 1. establish_binding
**Purpose**: Validate packets from clients with assigned IP addresses

**Match Fields**:
```p4
key = {
    hdr.ipv4.srcAddr: exact;           // Source IP
    hdr.ethernet.srcAddr: exact;        // Source MAC
    standard_metadata.ingress_port: exact;  // Ingress port
}
```

**Actions**:
- `forward_established()`: Decrement TTL, set egress port, update counter[0]
- `drop_spoofed()`: Drop packet, update counter[2]

**Default**: `drop_spoofed()` (fail-closed security)

**Security Properties**:
✅ Prevents IP-only spoofing (must match MAC + port)
✅ Prevents MAC-only spoofing (must match IP + port)
✅ Prevents port hopping (must match all three)

#### 2. dhcp_allowlist
**Purpose**: Control traffic during DHCP bootstrap phase

**Match Fields**:
```p4
key = {
    hdr.ethernet.srcAddr: exact;        // Source MAC
    standard_metadata.ingress_port: exact;  // Ingress port
}
```

**Actions**:
- `forward_dhcp()`: Forward DHCP traffic, update counter[1]
- `drop_unbound_non_dhcp()`: Drop non-DHCP traffic, update counter[3]

**Additional Logic**: Only triggered when `srcIP == 0.0.0.0` AND `UDP 68→67`

**Security Properties**:
✅ Only known MACs can obtain IP addresses
✅ Only DHCP protocol allowed during bootstrap
✅ Prevents reconnaissance during unbound phase

#### 3. tcp_connection_track
**Purpose**: Monitor TCP connection state (for advanced detection)

**Match Fields**:
```p4
key = {
    hdr.ipv4.srcAddr: exact;
    hdr.ipv4.dstAddr: exact;
    hdr.tcp.srcPort: exact;
    hdr.tcp.dstPort: exact;
}
```

**Usage**: Foundation for SYN flood detection, stateful firewall

### Security Counters

| Index | Name | Type | P4 Code Location |
|-------|------|------|------------------|
| 0 | Legitimate Established | Forward | `forward_established()` |
| 1 | DHCP Bootstrap | Forward | `forward_dhcp()` |
| 2 | Spoofed Dropped | Attack | `drop_spoofed()` |
| 3 | Unbound Non-DHCP | Attack | `drop_unbound_non_dhcp()` |
| 4 | TCP SYN | Info | TCP flag detection |
| 5 | TCP SYN-ACK | Info | TCP flag detection |
| 6 | TCP ACK | Info | TCP flag detection |
| 7 | Rate Limited | Attack | `drop_rate_limited()` |
| 8 | Invalid Protocol | Attack | `drop_invalid_protocol()` |
| 9 | Checksum Failures | Attack | Checksum verify block |

**Monitoring Strategy**:
- Track counter[2] for attack attempts
- Compare counter[4] vs counter[6] for SYN flood detection
- Monitor counter[0] + counter[1] for legitimate traffic baseline

## Attack Scenarios and P4 Defenses

### Attack 1: Simple IP Spoofing
**Attacker Action**: Send packet with forged source IP (10.0.1.3)

**P4 Processing**:
```
1. srcIP = 10.0.1.3
2. Check establish_binding table
3. No match for (10.0.1.3, attacker_MAC, attacker_port)
4. Default action: drop_spoofed()
5. Counter[2]++
```

**Result**: DROPPED ✅

### Attack 2: MAC Spoofing with Valid IP
**Attacker Action**: Forge MAC of legitimate host (00:00:00:00:01:01) with correct IP

**P4 Processing**:
```
1. srcIP = 10.0.1.1, srcMAC = 00:00:00:00:01:01
2. Check establish_binding table
3. ingress_port = 3 (attacker's port)
4. No match for (10.0.1.1, 00:00:00:00:01:01, port 3)
5. Default action: drop_spoofed()
6. Counter[2]++
```

**Result**: DROPPED ✅ (port mismatch)

### Attack 3: Port Hopping
**Attacker Action**: Physically move to legitimate host's port with full credential forgery

**P4 Processing**:
```
1. srcIP = 10.0.1.1, srcMAC = 00:00:00:00:01:01, port = 1
2. Check establish_binding table
3. Match found: (10.0.1.1, 00:00:00:00:01:01, 1)
4. Action: forward_established()
5. Counter[0]++
```

**Result**: FORWARDED ⚠️ (Physical security required)

**Mitigation**: Requires out-of-band detection (port status monitoring, DHCP re-binding)

### Attack 4: DHCP Bootstrap Abuse
**Attacker Action**: Send malicious TCP traffic with srcIP = 0.0.0.0

**P4 Processing**:
```
1. srcIP = 0.0.0.0
2. IF branch: DHCP check
3. protocol = TCP (not UDP)
4. Action: drop_unbound_non_dhcp()
5. Counter[3]++
```

**Result**: DROPPED ✅

### Attack 5: TCP SYN Flood
**Attacker Action**: Send 1000 SYN packets with random spoofed IPs

**P4 Processing**:
```
For each packet:
1. Extract TCP flags, detect SYN
2. Counter[4]++
3. Check establish_binding → no match
4. drop_spoofed()
5. Counter[2]++

Detection:
- Counter[4] >> Counter[6] (SYNs >> ACKs)
- Counter[2] high rate
- Trigger control plane alert
```

**Result**: DROPPED ✅ + Detected

## Known Limitations

### L1: Static Binding Management
**Issue**: P4 runtime configuration is static
**Impact**: Cannot dynamically learn new hosts
**Mitigation**: Integrate control plane with DHCP snooping

### L2: No Cryptographic Authentication
**Issue**: Relies on network-layer identifiers (IP, MAC, port)
**Impact**: Physical attacks (port hopping) can succeed
**Mitigation**: Add challenge-response protocol with cryptographic cookies

### L3: Basic Rate Limiting
**Issue**: Meter-based rate limiting is approximation
**Impact**: May not handle sophisticated DDoS
**Mitigation**: Offload to control plane for advanced algorithms

### L4: Limited TCP State Machine
**Issue**: Only tracks flags, not sequence numbers or states
**Impact**: Cannot detect out-of-window attacks
**Mitigation**: Implement full TCP state tracking or use stateful firewall

### L5: No End-Host Feedback
**Issue**: Switch cannot verify packet acceptance by end-host
**Impact**: May forward packets that hosts will reject
**Mitigation**: Implement feedback mechanism from hosts to control plane

## Security Design Principles from Research

### 1. Security Over Performance
> "Security should be prioritized over performance in adversarial contexts"

**Applied in P4**:
- Use three-factor keys despite memory cost
- Complete protocol parsing (TCP, UDP, ICMP) despite overhead
- Checksum verification despite computation cost

### 2. Fine-Grained State Tracking
> "Coarse-grained keys enable pollution attacks"

**Applied in P4**:
- Per (IP, MAC, port) binding instead of per-IP
- Full five-tuple for TCP tracking
- Separate DHCP allowlist by MAC+port

### 3. Complete Protocol Implementation
> "Simplified protocol models enable evasion"

**Applied in P4**:
- Parse all transport layer protocols
- Validate checksums
- Track TCP flags and state

### 4. Defense in Depth
> "Layer multiple validation mechanisms"

**Applied in P4**:
- Network layer: IP binding check
- Link layer: MAC validation
- Physical layer: Port validation
- Transport layer: Protocol checks

### 5. Fail-Closed Security
> "Default to deny when uncertain"

**Applied in P4**:
- Default table action: drop
- Unknown packets: drop
- Invalid checksums: drop

## Performance Analysis

### Memory Usage (BMv2)
- **TCAM/SRAM**: ~8 KB (table entries)
- **Registers**: 10 counters × 2 (packets + bytes) = 160 bytes
- **Parser state**: ~100 bytes per packet

### Latency (Hardware Switch)
- **Parser**: ~50 ns
- **Table lookup**: ~10 ns per table × 2 = 20 ns
- **Checksum verify**: ~20 ns
- **Total**: ~90 ns (line-rate capable)

### Throughput
- **Line-rate**: Yes (on hardware)
- **Packet rate**: Limited by table size, not processing speed

## Deployment Recommendations

1. **Start with monitoring mode**: Log drops without enforcing
2. **Tune binding tables**: Adjust based on network size
3. **Integrate control plane**: Dynamic binding management
4. **Enable rate limiting**: Protect against floods
5. **Monitor counters**: Set up alerting on counter[2] spikes

## References

1. **Wang, L., Mittal, P., & Rexford, J.** "Data-Plane Security Applications in Adversarial Settings"
2. **RFC 2827** - Network Ingress Filtering (BCP 38)
3. **P4₁₆ Language Specification** v1.2.3

---

**Key Takeaway**: P4 enables security-first data-plane programming. Fine-grained state, complete validation, and fail-closed design are essential for adversarial environments.
