#include <v1model.p4> // standard_metadata is define here.
#include "../vendor.p4" // common data structs are defined here.

// GTP message format
header gtpv01_t {
    bit<3>  ver;
    bit<1>  pt;        // Protocol type
    bit<1>  reserved;
    bit<1>  e;         // Extension header flag
    bit<1>  s;         // Sequence number flag
    bit<1>  pn;        // N-PDU number flag
    bit<8>  mesgType;
    bit<16> mesgLen;
    bit<32> teid;      // Tunnel endpoint id
}

header gtpv01_opt_fields_t {
    bit<16> seqnum;
    bit<8>  npdu;
    bit<8>  next_hdr;
    bit<8>  extLen;
    bit<16> contents;
    bit<8>  nextExtHdr;
}


struct cust_headers_t extends headers_t {
     gtpv01_t                 gtpv01_hdr;
     gtpv01_opt_fields_t      gtpv01_opts;
     ipv4_t                   inner_ipv4;
     udp_t                    inner_udp;
}

// new keyword "extends"
parser cust_parser(packet_in packet, out cust_headers_t hdr, inout meta_t meta,
                   inout standard_metadata_t standard_metadata) extends
       vendor_parser(packet_in packet, out headers_t hdr, inout meta_t meta,
                     inout standard_metadata_t standard_metadata) {
    state parse_udp override {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w2152: parse_gtpv01_hdr;
            default: accept;
        }
    }
    state parse_gtpv01_hdr {
        packet.extract(hdr.gtpv01_hdr);
        transition select(hdr.gtpv01_hdr.e) {
            1w0: parse_gtp_payload;
            default: parse_gtpv01_opts;
        }
    }
    state parse_gtp_payload {
        bit<4> version = packet.lookahead<bit<4>>();
        meta.tunnel_metadata.ingress_tunnel_type = (bit<8>)tunnelTypes.GTP;
        transition select(version) {
            4w4: parse_inner_ipv4;
                 default: reject;
        }
    }
    state parse_gtpv01_opts {
        packet.extract(hdr.gtpv01_opts);
        transition parse_gtp_payload;
    }
    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.ihl, hdr.inner_ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x11): parse_inner_udp;
            default: accept;
        }
    }
    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action gtp_strip() {
        hdr.gtpv01_hdr.setInvalid();
        hdr.gtpv01_opts.setInvalid();
    }

    apply {
        gtp_strip();
    }
}

control cust_deparser(packet_out p, in headers_t hdr) extends
        vendor_deparser(packet_out p, in headers_t hdr) {
    apply {
        p.emit(hdr.ethernet);
        p.emit(hdr.inner_ipv4);
        p.emit(hdr.inner_udp);
    }
}

