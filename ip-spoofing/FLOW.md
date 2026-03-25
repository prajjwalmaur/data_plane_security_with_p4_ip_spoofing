# IP Spoofing Defense - System Flow & Architecture

## Research Foundation

**Paper**: "Data-Plane Security Applications in Adversarial Settings"
**Authors**: Wang, Mittal, Rexford (Princeton University)

---

## System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           NETWORK TOPOLOGY                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐│
│   │     Host h1     │         │   P4 Switch s1  │         │     Host h2     ││
│   │                 │         │                 │         │                 ││
│   │ IP: 10.0.1.1    │◄───────►│  Security Logic │◄───────►│ IP: 10.0.1.2    ││
│   │ MAC: 00:..01:01 │  Port 1 │                 │  Port 2 │ MAC: 00:..01:02 ││
│   │                 │         │  - Binding      │         │                 ││
│   │ [client.py]     │         │  - DHCP Check   │         │ [server.py]     ││
│   │                 │         │  - TCP Track    │         │                 ││
│   └─────────────────┘         └─────────────────┘         └─────────────────┘│
│                                       │                                      │
│                                       │                                      │
│                               ┌───────▼───────┐                              │
│                               │   Attacker    │                              │
│                               │   (Various    │                              │
│                               │    ports)     │                              │
│                               └───────────────┘                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## P4 Pipeline Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         P4 PACKET PROCESSING PIPELINE                         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────┐   ┌─────────────┐   ┌─────────────────┐   ┌─────────────────┐  │
│  │ INGRESS │──►│   PARSER    │──►│ CHECKSUM VERIFY │──►│    INGRESS      │  │
│  │  PORT   │   │             │   │                 │   │   PROCESSING    │  │
│  └─────────┘   │ ┌─────────┐ │   │  Validate IPv4  │   │                 │  │
│                │ │Ethernet │ │   │  header checksum│   │  - Init metadata│  │
│                │ └────┬────┘ │   │                 │   │  - Rate limit   │  │
│                │      │      │   │  counter[9]++   │   │  - Binding check│  │
│                │      ▼      │   │  on failure     │   │  - Forward/Drop │  │
│                │ ┌─────────┐ │   │                 │   │                 │  │
│                │ │  IPv4   │ │   └─────────────────┘   └────────┬────────┘  │
│                │ └────┬────┘ │                                  │           │
│                │      │      │                                  ▼           │
│                │      ▼      │   ┌─────────────────┐   ┌─────────────────┐  │
│                │ ┌─────────┐ │   │ CHECKSUM UPDATE │◄──│     EGRESS      │  │
│                │ │TCP/UDP/ │ │   │                 │   │   PROCESSING    │  │
│                │ │  ICMP   │ │   │ Recompute IPv4  │   │                 │  │
│                │ └─────────┘ │   │ checksum (TTL   │   │ (Future: egress │  │
│                │             │   │ decremented)    │   │  filtering)     │  │
│                └─────────────┘   └────────┬────────┘   └─────────────────┘  │
│                                           │                                  │
│                                           ▼                                  │
│                                  ┌─────────────────┐    ┌─────────┐         │
│                                  │    DEPARSER     │───►│ EGRESS  │         │
│                                  │                 │    │  PORT   │         │
│                                  │  Reassemble:    │    └─────────┘         │
│                                  │  Ether+IP+L4    │                        │
│                                  └─────────────────┘                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Ingress Processing Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        INGRESS PROCESSING DECISION TREE                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           ┌─────────────────────┐                            │
│                           │    Packet Arrives   │                            │
│                           │   (from parser)     │                            │
│                           └──────────┬──────────┘                            │
│                                      │                                       │
│                                      ▼                                       │
│                           ┌─────────────────────┐                            │
│                           │  init_metadata()    │                            │
│                           │  - is_tcp_syn = 0   │                            │
│                           │  - is_dhcp = 0      │                            │
│                           │  - is_spoofed = 0   │                            │
│                           └──────────┬──────────┘                            │
│                                      │                                       │
│                                      ▼                                       │
│                           ┌─────────────────────┐                            │
│                           │   IPv4 Valid?       │                            │
│                           └──────────┬──────────┘                            │
│                                      │                                       │
│                            ┌─────────┴─────────┐                             │
│                            │ NO                │ YES                         │
│                            ▼                   ▼                             │
│               ┌─────────────────────┐  ┌─────────────────────┐               │
│               │drop_invalid_protocol│  │  Classify packet    │               │
│               │   counter[8]++      │  │  (TCP flags, DHCP)  │               │
│               │   RETURN            │  │                     │               │
│               └─────────────────────┘  └──────────┬──────────┘               │
│                                                   │                          │
│                                                   ▼                          │
│                                        ┌─────────────────────┐               │
│                                        │  srcIP == 0.0.0.0?  │               │
│                                        └──────────┬──────────┘               │
│                                                   │                          │
│                         ┌─────────────────────────┴────────────────────────┐ │
│                         │ YES (DHCP Bootstrap)    │ NO (Established)       │ │
│                         ▼                         ▼                        │ │
│            ┌─────────────────────┐    ┌─────────────────────────┐          │ │
│            │   is_dhcp == 1?     │    │  establish_binding.apply()│         │ │
│            └──────────┬──────────┘    │                         │          │ │
│                       │               │  Key: (srcIP, srcMAC,   │          │ │
│           ┌───────────┴───────────┐   │        ingress_port)    │          │ │
│           │ YES        │ NO       │   └──────────┬──────────────┘          │ │
│           ▼            ▼          │              │                         │ │
│  ┌─────────────┐ ┌─────────────┐  │   ┌──────────┴──────────┐              │ │
│  │dhcp_allowlist│ │drop_unbound_│ │   │ MATCH    │ NO MATCH │              │ │
│  │   .apply()  │ │ non_dhcp()  │  │   ▼          ▼          │              │ │
│  │             │ │counter[3]++ │  │ forward_   drop_        │              │ │
│  │Key: (srcMAC,│ └─────────────┘  │ established spoofed     │              │ │
│  │   port)     │                  │ counter[0]++ counter[2]++│             │ │
│  └──────┬──────┘                  │                         │              │ │
│         │                         └─────────────────────────┘              │ │
│  ┌──────┴──────┐                                                           │ │
│  │MATCH│NO MATCH                                                           │ │
│  ▼     ▼                                                                   │ │
│ forward drop_                                                              │ │
│ _dhcp  unbound                                                             │ │
│ [1]++  _non_dhcp                                                           │ │
│        [3]++                                                               │ │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Tables Structure

### Table 1: establish_binding

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         ESTABLISH_BINDING TABLE                            │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  PURPOSE: Validate packets from clients with assigned IP addresses        │
│  DEFAULT ACTION: drop_spoofed() → counter[2]++                           │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                          MATCH KEY                                  │ │
│  ├─────────────────┬───────────────────┬─────────────────────────────┤ │
│  │   srcIP (32b)   │   srcMAC (48b)    │   ingress_port (9b)         │ │
│  │     EXACT       │      EXACT        │        EXACT                │ │
│  └────────┬────────┴─────────┬─────────┴──────────────┬──────────────┘ │
│           │                  │                        │                 │
│           └──────────────────┼────────────────────────┘                 │
│                              │                                          │
│                              ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     TABLE ENTRIES                                 │  │
│  ├────────────────┬──────────────────────┬─────────┬────────────────┤  │
│  │     srcIP      │       srcMAC         │  Port   │     Action     │  │
│  ├────────────────┼──────────────────────┼─────────┼────────────────┤  │
│  │   10.0.1.1     │   00:00:00:00:01:01  │    1    │ forward → 2    │  │
│  ├────────────────┼──────────────────────┼─────────┼────────────────┤  │
│  │   10.0.1.2     │   00:00:00:00:01:02  │    2    │ forward → 1    │  │
│  ├────────────────┼──────────────────────┼─────────┼────────────────┤  │
│  │   (default)    │       (any)          │  (any)  │ drop_spoofed   │  │
│  └────────────────┴──────────────────────┴─────────┴────────────────┘  │
│                                                                         │
│  SECURITY: Three-factor authentication prevents:                        │
│    ✗ IP-only spoofing (need correct MAC + port)                        │
│    ✗ MAC spoofing (need correct IP + port)                             │
│    ✗ Port hopping (need correct IP + MAC)                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Table 2: dhcp_allowlist

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          DHCP_ALLOWLIST TABLE                              │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  PURPOSE: Control DHCP bootstrap phase (srcIP = 0.0.0.0)                  │
│  DEFAULT ACTION: drop_unbound_non_dhcp() → counter[3]++                  │
│                                                                           │
│  TRIGGER CONDITIONS:                                                      │
│    1. srcIP == 0.0.0.0 (unbound client)                                  │
│    2. Protocol == UDP                                                     │
│    3. srcPort == 68, dstPort == 67 (DHCP)                                │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────┐             │
│  │                    MATCH KEY                             │             │
│  ├───────────────────────────┬─────────────────────────────┤             │
│  │      srcMAC (48b)         │    ingress_port (9b)        │             │
│  │         EXACT             │         EXACT               │             │
│  └───────────────────────────┴─────────────────────────────┘             │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      TABLE ENTRIES                                   │ │
│  ├──────────────────────┬─────────┬────────────────────────────────────┤ │
│  │       srcMAC         │  Port   │            Action                  │ │
│  ├──────────────────────┼─────────┼────────────────────────────────────┤ │
│  │ 00:00:00:00:01:01    │    1    │ forward_dhcp() → counter[1]++     │ │
│  ├──────────────────────┼─────────┼────────────────────────────────────┤ │
│  │ 00:00:00:00:01:02    │    2    │ forward_dhcp() → counter[1]++     │ │
│  ├──────────────────────┼─────────┼────────────────────────────────────┤ │
│  │     (default)        │  (any)  │ drop_unbound_non_dhcp()           │ │
│  └──────────────────────┴─────────┴────────────────────────────────────┘ │
│                                                                           │
│  SECURITY: Prevents malicious traffic during bootstrap phase              │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Security Counter System

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         SECURITY COUNTERS (10 total)                       │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  INDEX │ NAME                    │ TYPE    │ TRIGGER                     │
│  ──────┼─────────────────────────┼─────────┼──────────────────────────── │
│   [0]  │ Legitimate Established  │ FORWARD │ establish_binding match     │
│   [1]  │ DHCP Bootstrap          │ FORWARD │ dhcp_allowlist match        │
│   [2]  │ Spoofed Dropped         │ ATTACK  │ establish_binding miss      │
│   [3]  │ Unbound Non-DHCP        │ ATTACK  │ Non-DHCP from srcIP=0       │
│   [4]  │ TCP SYN                 │ INFO    │ SYN flag detected           │
│   [5]  │ TCP SYN-ACK             │ INFO    │ SYN+ACK flags detected      │
│   [6]  │ TCP ACK                 │ INFO    │ ACK flag detected           │
│   [7]  │ Rate Limited            │ ATTACK  │ Rate limit exceeded         │
│   [8]  │ Invalid Protocol        │ ATTACK  │ Non-IPv4 packet             │
│   [9]  │ Checksum Failures       │ ATTACK  │ Bad IPv4 checksum           │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                    MONITORING STRATEGY                               │ │
│  ├─────────────────────────────────────────────────────────────────────┤ │
│  │                                                                     │ │
│  │  • counter[2] spike → Active IP spoofing attack                    │ │
│  │  • counter[4] >> counter[6] → SYN flood detection                  │ │
│  │  • counter[3] spike → DHCP phase exploitation attempt              │ │
│  │  • counter[0]/counter[1] ratio → Normal traffic baseline           │ │
│  │                                                                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Attack Scenario Flows

### Scenario 1: IP Spoofing Attack

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ATTACK: IP SPOOFING (Spoofed IP)                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Attacker sends: srcIP=10.0.1.3 (non-existent), srcMAC=attacker_MAC    │
│                                                                         │
│  ┌────────┐     ┌─────────────────────────────────────┐     ┌────────┐ │
│  │Attacker│────►│           P4 Switch                  │     │ Target │ │
│  │        │     │                                     │  ✗  │        │ │
│  │srcIP=  │     │ 1. Parse packet                     │     │        │ │
│  │10.0.1.3│     │ 2. srcIP != 0 → establish_binding   │     │        │ │
│  │        │     │ 3. Lookup: (10.0.1.3, MAC, port)    │     │        │ │
│  └────────┘     │ 4. NO MATCH → drop_spoofed()        │     └────────┘ │
│                 │ 5. counter[2]++                      │                │
│                 │                                     │                │
│                 │           ┌──────────┐              │                │
│                 │           │ DROPPED  │              │                │
│                 │           └──────────┘              │                │
│                 └─────────────────────────────────────┘                │
│                                                                         │
│  RESULT: Attack blocked, counter[2] incremented                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Scenario 2: MAC Spoofing Attack

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ATTACK: MAC SPOOFING (Forged MAC)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Attacker sends: srcIP=10.0.1.1 (valid), srcMAC=forged_MAC             │
│                                                                         │
│  ┌────────┐     ┌─────────────────────────────────────┐                │
│  │Attacker│────►│           P4 Switch                  │                │
│  │        │     │                                     │                │
│  │srcIP=  │     │ 1. Parse packet                     │                │
│  │10.0.1.1│     │ 2. srcIP != 0 → establish_binding   │                │
│  │        │     │ 3. Lookup: (10.0.1.1, forged, 3)    │                │
│  │srcMAC= │     │                                     │                │
│  │forged  │     │    Expected: (10.0.1.1, 01:01, 1)   │                │
│  │        │     │                                     │                │
│  │port=3  │     │ 4. MAC MISMATCH → drop_spoofed()    │                │
│  └────────┘     │ 5. counter[2]++                      │                │
│                 │           ┌──────────┐              │                │
│                 │           │ DROPPED  │              │                │
│                 │           └──────────┘              │                │
│                 └─────────────────────────────────────┘                │
│                                                                         │
│  RESULT: MAC spoofing detected and blocked                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Scenario 3: Legitimate Traffic Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    LEGITIMATE TRAFFIC FLOW                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  h1 sends valid packet to h2                                           │
│                                                                         │
│  ┌────────┐     ┌─────────────────────────────────────┐     ┌────────┐ │
│  │  h1    │────►│           P4 Switch                  │────►│  h2    │ │
│  │        │     │                                     │     │        │ │
│  │srcIP=  │     │ 1. Parse: Ether → IPv4 → TCP        │     │        │ │
│  │10.0.1.1│     │ 2. Verify IPv4 checksum ✓           │     │        │ │
│  │        │     │ 3. srcIP != 0 → establish_binding   │     │        │ │
│  │srcMAC= │     │ 4. Lookup: (10.0.1.1, 01:01, 1)     │     │        │ │
│  │01:01   │     │ 5. MATCH FOUND ✓                    │     │        │ │
│  │        │     │ 6. forward_established(port=2)      │     │        │ │
│  │port=1  │     │ 7. counter[0]++                      │     │        │ │
│  └────────┘     │ 8. Decrement TTL, update checksum   │     └────────┘ │
│                 │ 9. Emit to port 2                    │                │
│                 │           ┌───────────┐             │                │
│                 │           │ FORWARDED │             │                │
│                 │           └───────────┘             │                │
│                 └─────────────────────────────────────┘                │
│                                                                         │
│  RESULT: Packet forwarded, counter[0] incremented                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Paper Issues → Implementation Mapping

```
┌───────────────────────────────────────────────────────────────────────────┐
│             PAPER VULNERABILITIES → P4 IMPLEMENTATION                      │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ISSUE 1: COARSE-GRAINED KEYS                                       │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │                                                                    │  │
│  │  Paper: "Using srcIP only enables pollution attacks"              │  │
│  │                                                                    │  │
│  │  BEFORE (Vulnerable):         AFTER (Our Implementation):        │  │
│  │  ┌─────────────────┐          ┌─────────────────────────┐        │  │
│  │  │ Key: srcIP      │   ──►    │ Key: (srcIP, srcMAC,    │        │  │
│  │  │                 │          │       ingress_port)     │        │  │
│  │  └─────────────────┘          └─────────────────────────┘        │  │
│  │                                                                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ISSUE 2: MISSING PROTOCOL VALIDATION                               │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │                                                                    │  │
│  │  Paper: "Simplified protocol models enable evasion"               │  │
│  │                                                                    │  │
│  │  Implementation:                                                   │  │
│  │  ✓ Full header parsing (Ethernet, IPv4, TCP, UDP, ICMP)          │  │
│  │  ✓ IPv4 checksum verification                                     │  │
│  │  ✓ DHCP protocol enforcement (UDP 68→67)                         │  │
│  │  ✓ TCP flag tracking                                              │  │
│  │                                                                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ CHALLENGE C: LIMITED STATE VISIBILITY                              │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │                                                                    │  │
│  │  Paper: "Switch cannot see if end-host accepts packets"           │  │
│  │                                                                    │  │
│  │  Implementation:                                                   │  │
│  │  ✓ TCP connection tracking (SYN, SYN-ACK, ACK counting)           │  │
│  │  ✓ Multi-layer validation (Network + Link + Physical)            │  │
│  │  ✓ Security counters for anomaly detection                        │  │
│  │                                                                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ SECURITY PRINCIPLE: SECURITY OVER PERFORMANCE                      │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │                                                                    │  │
│  │  Paper: "Security should be prioritized in adversarial contexts"  │  │
│  │                                                                    │  │
│  │  Implementation:                                                   │  │
│  │  ✓ Fail-closed design (default: DROP)                             │  │
│  │  ✓ Complete validation despite memory cost                        │  │
│  │  ✓ Multiple tables for defense-in-depth                           │  │
│  │                                                                    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Test Flow Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          TEST SIMULATION FLOW                              │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   ┌─────────────────┐                                                     │
│   │ test_simulation │                                                     │
│   │     .py         │                                                     │
│   └────────┬────────┘                                                     │
│            │                                                              │
│            ▼                                                              │
│   ┌─────────────────┐                                                     │
│   │ Load Runtime    │     Load from: s1-runtime-new.json                 │
│   │ Configuration   │     - 2 binding entries                            │
│   │                 │     - 2 DHCP allowlist entries                     │
│   └────────┬────────┘                                                     │
│            │                                                              │
│            ▼                                                              │
│   ┌─────────────────┐                                                     │
│   │ Create 10 Test  │     Test packets covering:                         │
│   │ Packets         │     - DHCP phase attacks                           │
│   │                 │     - IP spoofing                                  │
│   │                 │     - MAC spoofing                                 │
│   │                 │     - Port hopping                                 │
│   │                 │     - Legitimate traffic                           │
│   └────────┬────────┘                                                     │
│            │                                                              │
│            ▼                                                              │
│   ┌─────────────────┐                                                     │
│   │ Process Each    │     For each packet:                               │
│   │ Packet          │     1. Extract headers                             │
│   │                 │     2. Apply P4 logic                              │
│   │                 │     3. Update counters                             │
│   │                 │     4. Record decision                             │
│   └────────┬────────┘                                                     │
│            │                                                              │
│            ▼                                                              │
│   ┌─────────────────┐                                                     │
│   │ Compare Results │     Expected vs Actual:                            │
│   │                 │     - 4 FORWARD (legitimate)                       │
│   │                 │     - 6 DROP (attacks)                             │
│   └────────┬────────┘                                                     │
│            │                                                              │
│            ▼                                                              │
│   ┌─────────────────┐                                                     │
│   │ Print Summary   │     - Pass/Fail for each test                      │
│   │                 │     - Counter statistics                           │
│   │                 │     - Security effectiveness                       │
│   └─────────────────┘                                                     │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## File Relationships

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         PROJECT FILE STRUCTURE                             │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │                       P4 IMPLEMENTATION                               ││
│  │                                                                      ││
│  │  ip-spoofing-defense.p4  ◄─────── Main P4 program                   ││
│  │         │                         (Parser, Tables, Actions)          ││
│  │         │                                                            ││
│  │         └─────► build/*.json  ◄─── Compiled P4 (BMv2 target)        ││
│  │                                                                      ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │                      RUNTIME CONFIGURATION                            ││
│  │                                                                      ││
│  │  s1-runtime-new.json  ◄─────── Table entries for switch             ││
│  │         │                       - Binding rules                      ││
│  │         │                       - DHCP allowlist                     ││
│  │         │                                                            ││
│  │  topology.json  ◄───────────── Network topology (h1 ─ s1 ─ h2)     ││
│  │                                                                      ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │                         TESTING SCRIPTS                               ││
│  │                                                                      ││
│  │  test_simulation.py  ◄────────── Python simulation (no P4 hw)       ││
│  │         │                         - Demonstrates security logic      ││
│  │         │                         - 10 test cases                    ││
│  │         │                                                            ││
│  │  client.py  ◄──────────────────── Scapy packet sender               ││
│  │                                    - Sends test packets               ││
│  │                                                                      ││
│  │  server.py  ◄──────────────────── Scapy packet receiver             ││
│  │                                    - Captures forwarded packets       ││
│  │                                                                      ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │                         DOCUMENTATION                                 ││
│  │                                                                      ││
│  │  README.md  ◄──────────────────── Project overview                  ││
│  │  DEMO.md  ◄────────────────────── Demo guide (this doc)             ││
│  │  FLOW.md  ◄────────────────────── Architecture (current doc)        ││
│  │  SECURITY_ANALYSIS.md  ◄───────── Detailed security analysis        ││
│  │  IMPLEMENTATION_NOTES.md  ◄────── Implementation details            ││
│  │                                                                      ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

| Component | File | Purpose |
|-----------|------|---------|
| P4 Logic | `ip-spoofing-defense.p4` | Main security implementation |
| Config | `s1-runtime-new.json` | Table entries/rules |
| Test | `test_simulation.py` | Python simulation |
| Sender | `client.py` | Scapy packet generator |
| Receiver | `server.py` | Packet capture |

---

**Document Version**: 1.0
**Last Updated**: Based on paper implementation
