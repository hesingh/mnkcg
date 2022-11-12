//
// Merge customer ipv6 parser with vendor ipv4-only parser
//
#include "vendor_copy.p4"

parser vendor_parser(packet_in packet, out headers_t hdr, inout meta_t meta,
                     inout standard_metadata_t standard_metadata) override {
    state ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            PROTO_UDP: parse_udp;
            PROTO_ICMP6: icmp6;
            default: accept;
        }
    }
    state parse_ethernet override {
        extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            IPV6: parse_ipv6_state;
            // no need to extract, only switch based
            // on already extracted header
            default: super.parse_ethernet.transition;
        }
    }

}
