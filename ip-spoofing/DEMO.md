# Data Plane Security with P4: IP Spoofing Defense - Demo Guide

## Research Paper Implementation Demo

**Paper**: "Data-Plane Security Applications in Adversarial Settings"
**Authors**: Liang Wang, Prateek Mittal, Jennifer Rexford (Princeton University)
**Topic**: Data Plane Security with P4: IP Spoofing

---

## Quick Demo Commands

### Option 1: P4 Behavioral Model (Recommended)

```bash
cd /home/prajjwal/Desktop/ns/ip-spoofing
python3 p4_behavioral_model.py
```

**This simulates the EXACT P4 BMv2 pipeline**: Parser → Checksum → Ingress → Egress → Deparser

### Option 2: Run All Tests

```bash
cd /home/prajjwal/Desktop/ns/ip-spoofing
python3 run_all_tests.py
```

### Option 3: Mininet Integration (requires sudo)

```bash
cd /home/prajjwal/Desktop/ns/ip-spoofing
sudo python3 mininet_p4_test.py
```

**Expected Output**: All 10 tests pass with 100% success rate:
- 4 legitimate packets forwarded
- 6 attack packets blocked

---

## Demo Script for Presentation

### Slide 1: Introduction

> "This project implements IP spoofing defense at the data-plane level using P4 programming. It's based on the research paper 'Data-Plane Security Applications in Adversarial Settings' from Princeton University."

### Slide 2: Problem Statement

> "Traditional IP source guards only check the source IP address. This creates vulnerabilities because an attacker can easily spoof IP addresses. The paper identifies several issues with existing data-plane security applications."

**Key Issues from Paper**:
1. **Coarse-grained keys**: Using only IP address for validation
2. **Limited state visibility**: Switch can't see end-host state
3. **Protocol simplification**: Missing complete validation

### Slide 3: Our Solution - Multi-Factor Binding

> "Our P4 implementation uses THREE-FACTOR binding instead of single IP check."

```
Traditional: srcIP only
Our Solution: (srcIP, srcMAC, ingressPort)
```

**Demo Command**:
```bash
python3 test_simulation.py | grep -A2 "Test 6"
```

**Show**: MAC spoofing attack is blocked because MAC doesn't match the binding.

### Slide 4: Architecture Walkthrough

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Host h1   │────│   Switch    │────│   Host h2   │
│ 10.0.1.1    │     │    s1       │     │ 10.0.1.2    │
│ Port 1      │     │  (P4 Logic) │     │ Port 2      │
└─────────────┘     └─────────────┘     └─────────────┘
```

**Key Tables**:
1. `establish_binding` - Validates (IP, MAC, port) tuple
2. `dhcp_allowlist` - Controls bootstrap phase
3. `tcp_connection_track` - Monitors TCP state

### Slide 5: Live Demo - Attack Scenarios

Run each test scenario and explain:

```bash
python3 test_simulation.py
```

#### Test Results Explained:

| Test | Scenario | Expected | Why |
|------|----------|----------|-----|
| 1 | Non-DHCP from unbound client | DROP | Only DHCP allowed during bootstrap |
| 2 | Valid DHCP Discover | FORWARD | Known MAC+port in allowlist |
| 3 | DHCP from unknown MAC | DROP | Unknown client prevented |
| 4 | Valid established packet | FORWARD | IP+MAC+port all match |
| 5 | Spoofed IP (10.0.1.3) | DROP | IP not in binding table |
| 6 | Valid IP, forged MAC | DROP | MAC mismatch detected |
| 7 | Port hopping attack | DROP | Wrong ingress port |
| 8-9 | Valid bidirectional traffic | FORWARD | All factors match |
| 10 | Unknown attacker | DROP | All factors fail |

### Slide 6: Security Counters

> "The P4 implementation provides visibility into security events through 10 counters."

**Demo**:
```bash
python3 test_simulation.py | grep -A15 "SECURITY COUNTERS"
```

**Key Counters**:
- `[0]` Legitimate packets: Shows normal traffic
- `[2]` Spoofed dropped: **ATTACKS BLOCKED**
- `[4-6]` TCP SYN/ACK: Connection monitoring

### Slide 7: Paper Issues Addressed

| Paper Issue | P4 Implementation |
|-------------|------------------|
| Issue 1: Coarse-grained keys | Fine-grained (IP, MAC, port) binding |
| Issue 2: Missing validation | Protocol and checksum verification |
| Challenge C: State visibility | TCP connection tracking |
| Security Principle | Fail-closed design (default: drop) |

---

## Full P4 Demo (with BMv2 - requires P4 tools)

### Prerequisites

```bash
# Install P4 development tools
sudo apt-get install p4lang-p4c p4lang-bmv2

# Or use P4 VM from p4.org
```

### Step 1: Compile P4 Program

```bash
cd /home/prajjwal/Desktop/ns/ip-spoofing
mkdir -p build

p4c --target bmv2 --arch v1model \
    -o build/ip-spoofing-defense.json \
    ip-spoofing-defense.p4
```

### Step 2: Start BMv2 Switch

Terminal 1:
```bash
sudo simple_switch \
    -i 0@veth0 -i 1@veth2 \
    --log-console --log-level debug \
    build/ip-spoofing-defense.json
```

Terminal 2 (load rules):
```bash
simple_switch_CLI < s1-runtime-new.json
```

### Step 3: Run Test Client

Terminal 3:
```bash
sudo python3 server.py  # On receiving host
```

Terminal 4:
```bash
sudo python3 client.py  # On sending host
```

### Step 4: Monitor Security Counters

```bash
simple_switch_CLI
> counter_read IngressProcess.security_stats 0   # Legitimate
> counter_read IngressProcess.security_stats 2   # Spoofed (attacks)
```

---

## Mininet Full Integration Demo

### Step 1: Start Mininet with P4 Switch

```bash
sudo python3 run_mininet.py  # If Mininet script exists
```

Or manually:

```python
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI

# Create topology
net = Mininet(topo=SingleSwitchTopo(2))
net.start()

# Access hosts
h1 = net.get('h1')
h2 = net.get('h2')

# Run tests
h2.cmd('python3 server.py &')
h1.cmd('python3 client.py')

CLI(net)
```

---

## Demo Checklist

Before presentation:
- [ ] Test simulation runs successfully
- [ ] Understand all 10 test cases
- [ ] Review paper key points
- [ ] Prepare to explain counters

During demo:
- [ ] Show simulation test results
- [ ] Explain three-factor binding
- [ ] Demo attack scenarios (Tests 5-7)
- [ ] Show security counters
- [ ] Map to paper issues

---

## Key Talking Points

### 1. Why P4?
> "P4 allows us to implement security at line-rate in the data plane, processing millions of packets per second without CPU involvement."

### 2. Why Three-Factor Binding?
> "Single IP checking is easily spoofed. By requiring IP + MAC + ingress port, an attacker must compromise all three factors simultaneously."

### 3. DHCP Bootstrap Security
> "During DHCP phase, clients don't have IP addresses. We only allow DHCP protocol (UDP 68→67) from known MAC+port combinations, preventing injection attacks."

### 4. Fail-Closed Design
> "Following the paper's security-first principle, our default action is DROP. Unknown packets are blocked, not forwarded."

### 5. Counters for Visibility
> "Security teams need visibility into attacks. Our 10 counters provide real-time monitoring of legitimate traffic vs attack attempts."

---

## Troubleshooting

### Simulation doesn't run
```bash
pip3 install scapy  # If missing
python3 --version   # Need Python 3.7+
```

### P4 compilation fails
```bash
# Check P4 tools installed
which p4c
which simple_switch

# Common fix
export PATH=$PATH:/usr/local/bin
```

### Mininet issues
```bash
sudo mn -c  # Clean up previous run
```

---

## Files Summary

| File | Purpose |
|------|---------|
| `test_simulation.py` | Python simulation of P4 logic |
| `ip-spoofing-defense.p4` | Main P4 implementation |
| `client.py` | Scapy packet sender |
| `server.py` | Scapy packet receiver |
| `s1-runtime-new.json` | Runtime table entries |
| `topology.json` | Network topology |

---

## Paper Citation

```bibtex
@inproceedings{wang2021dataplane,
  title={Data-Plane Security Applications in Adversarial Settings},
  author={Wang, Liang and Mittal, Prateek and Rexford, Jennifer},
  institution={Princeton University},
  year={2021}
}
```

---

**Demo Duration**: ~15-20 minutes for full presentation
**Quick Demo**: ~5 minutes (simulation only)
