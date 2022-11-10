//
// Merge customer ipv6 parser with vendor ipv4-only parser
//
#include "vendor_copy.p4"

const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMP6 = 58;

parser customer_parser(packet_in packet, out headers_t hdr, inout meta_t meta,
                       inout standard_metadata_t standard_metadata) {
    state ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            PROTO_UDP: parse_udp;
            PROTO_ICMP6: icmp6;
            default: accept;
        }
    }
    state icmp6 {
        packet.extract(hdr.icmp6);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}