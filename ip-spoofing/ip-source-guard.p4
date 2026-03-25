#include <core.p4>
#include <v1model.p4>

/* Ethernet type value for IPv4 packets. */
const bit<16> TYPE_IPV4 = 0x800;
/* IPv4 protocol value for UDP packets. */
const bit<8> UDP_PROTOCOL = 0x11;

/**********************************************************
********************** H E A D E R S **********************
**********************************************************/

typedef bit<9> egressSpec_t;   /* v1model egress port width. */
typedef bit<48> macAddr_t;     /* Standard MAC address width. */
typedef bit<32> ip4Addr_t;     /* Standard IPv4 address width. */

header ethernet_t {
    macAddr_t dstAddr;          /* L2 destination MAC. */
    macAddr_t srcAddr;          /* L2 source MAC. */
    bit<16> etherType;          /* Next protocol selector. */
}

header ipv4_t {
    bit<4> version;             /* Must be 4 for IPv4. */
    bit<4> ihl;                 /* Header length in 32-bit words. */
    bit<8> diffserv;            /* DSCP + ECN bits. */
    bit<16> totalLen;           /* Total IP packet size. */
    bit<16> identification;     /* Fragment reassembly ID. */
    bit<3> flags;               /* Fragment control flags. */
    bit<13> fragOffset;         /* Fragment offset position. */
    bit<8> ttl;                 /* Hop limit. */
    bit<8> protocol;            /* L4 protocol selector (UDP/TCP/ICMP). */
    bit<16> hdrChecksum;        /* IPv4 header checksum. */
    ip4Addr_t srcAddr;          /* Source IPv4 address. */
    ip4Addr_t dstAddr;          /* Destination IPv4 address. */
}

header udp_t {
    bit<16> srcPort;            /* UDP source port. */
    bit<16> dstPort;            /* UDP destination port. */
    bit<16> len;                /* UDP payload length. */
    bit<16> checksum;           /* UDP checksum (can be zero in IPv4). */
}

struct metadata {
    /* No custom metadata required for this basic variant. */
}

struct headers {
    ethernet_t ethernet;        /* Parsed Ethernet header. */
    ipv4_t ipv4;                /* Parsed IPv4 header. */
    udp_t udp;                  /* Parsed UDP header (if present). */
}

/**********************************************************
*********************** P A R S E R ***********************
**********************************************************/

parser ParsePacket(packet_in packet,
                   out headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;              /* Always parse Ethernet first. */
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);           /* Read Ethernet header fields. */
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;              /* Continue into IPv4 parsing. */
            default: accept;                    /* Non-IPv4 packets stop parsing. */
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);               /* Read IPv4 fixed header fields. */
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL: parse_udp;            /* Parse UDP only if protocol=17. */
            default: accept;                    /* Other L4 protocols are accepted. */
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);                /* Read UDP header fields. */
        transition accept;                      /* Parser complete. */
    }
}

/**********************************************************
******** C H E C K S U M   V E R I F I C A T I O N ********
**********************************************************/

control ChecksumVerify(inout headers hdr, inout metadata meta) {
    apply { }
}

/**********************************************************
*********** I N G R E S S   P R O C E S S I N G ***********
**********************************************************/

control IngressProcess(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {
    /*
     * Counter indexes for quick experiment metrics:
     * 0 -> established client packets forwarded
     * 1 -> DHCP bootstrap packets forwarded
     * 2 -> spoofed/unknown established packets dropped
     * 3 -> non-DHCP packets from unbound clients dropped
     */
    counter(4, CounterType.packets) ingress_stats;  /* Packet counters per security decision. */

    action drop_spoof() {
        ingress_stats.count(2);                     /* Count spoof/invalid established traffic. */
        mark_to_drop(standard_metadata);            /* Drop this packet. */
    }

    action drop_unbound_non_dhcp() {
        ingress_stats.count(3);                     /* Count disallowed bootstrap traffic. */
        mark_to_drop(standard_metadata);            /* Drop this packet. */
    }

    action pkt_fwd_established(macAddr_t dstAddr, egressSpec_t port) {
        ingress_stats.count(0);                     /* Count legitimate established traffic. */
        standard_metadata.egress_spec = port;       /* Select output port. */
        hdr.ethernet.dstAddr = dstAddr;             /* Rewrite destination MAC for next hop. */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;            /* Decrement IP TTL like a router. */
    }

    action pkt_fwd_dhcp(macAddr_t dstAddr, egressSpec_t port) {
        ingress_stats.count(1);                     /* Count allowed DHCP bootstrap traffic. */
        standard_metadata.egress_spec = port;       /* Select output port. */
        hdr.ethernet.dstAddr = dstAddr;             /* Rewrite destination MAC for next hop. */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;            /* Decrement IP TTL like a router. */
    }

    /*
     * Established binding check uses source IP + source MAC + ingress port.
     * This is stricter than source-IP-only matching and raises spoofing cost.
     */
    table estd_client {
        key = {
            hdr.ipv4.srcAddr: exact;                /* Bound source IP. */
            hdr.ethernet.srcAddr: exact;            /* Bound source MAC. */
            standard_metadata.ingress_port: exact;  /* Bound physical ingress port. */
        }
        actions = {
            pkt_fwd_established;                    /* Forward if binding is valid. */
            drop_spoof;                             /* Explicitly drop if policy says so. */
            NoAction;                               /* Optional no-op for control-plane use. */
        }
    }

    /*
     * During DHCP bootstrap (src IP = 0.0.0.0), permit only known client
     * MAC/port pairs and only DHCP client traffic.
     */
    table dhcp_client {
        key = {
            hdr.ethernet.srcAddr: exact;            /* Known client MAC. */
            standard_metadata.ingress_port: exact;  /* Allowed DHCP ingress port. */
        }
        actions = {
            pkt_fwd_dhcp;                           /* Allow approved DHCP bootstrap flow. */
            drop_unbound_non_dhcp;                  /* Reject unknown bootstrap clients. */
            NoAction;                               /* Optional no-op for control-plane use. */
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {                   /* Only enforce policy on IPv4 packets. */
            // If client has already been assigned an IP address
            if (hdr.ipv4.srcAddr != 0) {            /* Established client phase. */
                estd_client.apply();                /* Enforce 3-factor binding policy. */
            }
            else {
                // Allow only DHCP packets without client IP
                if (hdr.udp.isValid() && hdr.udp.srcPort == 68) {  /* DHCP Discover/Request. */
                    dhcp_client.apply();            /* Check bootstrap allowlist. */
                }
                // Drop the non-DHCP packets till client IP is established
                else drop_unbound_non_dhcp();       /* Fail-closed for bootstrap abuse. */
            }
        }
    }
}

/**********************************************************
************ E G R E S S   P R O C E S S I N G ************
**********************************************************/

control EgressProcess(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {
    apply { }
}

/**********************************************************
********* C H E C K S U M   C O M P U T A T I O N *********
**********************************************************/

control ChecksumCompute(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(                             /* Recompute IPv4 checksum after TTL change. */
            hdr.ipv4.isValid(),                     /* Only if IPv4 header exists. */
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,                   /* Output checksum field. */
            HashAlgorithm.csum16);
    }
}

/**********************************************************
******************** D E P A R S E R **********************
**********************************************************/

control DeparsePacket(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);                  /* Emit Ethernet first. */
        packet.emit(hdr.ipv4);                      /* Emit IPv4 if valid. */
        packet.emit(hdr.udp);                       /* Emit UDP if valid. */
    }
}

/**********************************************************
*********************** S W I T C H ***********************
**********************************************************/

V1Switch(
ParsePacket(),        /* Parse incoming packet bytes into headers. */
ChecksumVerify(),     /* Validate incoming checksums (currently no-op). */
IngressProcess(),     /* Apply security and forwarding decisions. */
EgressProcess(),      /* Optional post-routing processing. */
ChecksumCompute(),    /* Recompute checksum after header updates. */
DeparsePacket()       /* Serialize headers back to packet bytes. */
) main;
