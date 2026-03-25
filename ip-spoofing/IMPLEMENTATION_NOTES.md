# P4 IP Spoofing Defense Implementation Notes

Research paper: `Data-Plane Security Applications in Adversarial Settings`

## Two P4 Implementations

### 1. ip-source-guard.p4 (Original)
- Basic three-factor binding (IP, MAC, port)
- 4 counters
- UDP-only protocol support
- **Use for**: Understanding base concepts

### 2. ip-spoofing-defense.p4 (Enhanced)
- Three-factor binding + multi-protocol support
- 10 security counters
- TCP/UDP/ICMP support with state tracking
- Rate limiting framework
- **Use for**: Production deployment (with control plane)

## Key P4 Security Features

1. Stronger client identity binding in `ip-source-guard.p4`
- Old behavior: only source IP was validated for established clients.
- New behavior: established traffic is matched on:
  - `hdr.ipv4.srcAddr` (exact)
  - `hdr.ethernet.srcAddr` (exact)
  - `standard_metadata.ingress_port` (exact)

2. Controlled DHCP bootstrap handling
- For unbound clients (`src IP = 0.0.0.0`), only DHCP client packets are considered.
- DHCP forwarding now uses MAC + ingress port allowlisting (`dhcp_client` table).

3. Built-in ingress counters for evaluation
- Counter name: `ingress_stats`
- Index meanings:
  - `0`: established packets forwarded
  - `1`: DHCP bootstrap packets forwarded
  - `2`: spoofed/unknown established packets dropped
  - `3`: non-DHCP packets from unbound clients dropped

4. Runtime rules updated in `s1-runtime.json`
- Updated actions/table names and exact-match keys for hardened policy.

5. Attack traffic update in `client.py`
- Added a packet with legitimate IP but forged source MAC to demonstrate drop under stricter binding.

## Quick validation steps

1. Run your topology as usual.
2. Start packet receiver on host `h2`:
- `python server.py`
3. Send test packets from `h1`:
- `python client.py`
4. Read counter results from switch CLI:
- `counter_read IngressProcess.ingress_stats 0`
- `counter_read IngressProcess.ingress_stats 1`
- `counter_read IngressProcess.ingress_stats 2`
- `counter_read IngressProcess.ingress_stats 3`

Expected trend:
- Counters `0` and `1` increase for legitimate/bootstrapping traffic.
- Counters `2` and `3` increase for spoofed and invalid bootstrap traffic.

## Connection to paper

These changes reduce reliance on coarse-grained keys and improve robustness against simple spoofing/evasion attempts in a programmable data plane.
They do not fully solve end-host state visibility limitations discussed in the paper.
