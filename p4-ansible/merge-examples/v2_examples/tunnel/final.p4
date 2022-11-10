#include <v1model.p4>
#include "../vendor.p4"

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

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    gtpv01_t                 gtpv01_hdr;
    gtpv01_opt_fields_t      gtpv01_opts;
    ipv4_t                   inner_ipv4;
    udp_t                    inner_udp;
}

parser vendor_parser(packet_in packet,
                     out headers_t hdr,
                     inout meta_t meta,
                     inout standard_metadata_t standard_metadata)

{
    const bit<16> ETHERTYPE_IPV4 = 16w0x0800;

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x11): parse_udp;
        }
    }
    state parse_udp {
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
    action set_lb_hashed_index_ipv4() {
        // val32 = crc32(arg); // use lower 20 bits
        hash(meta.meta.lb_hash, HashAlgorithm.crc32, 21w0,
	     { hdr.inner_ipv4.srcAddr+hdr.inner_ipv4.dstAddr }, 21w2^20);
        meta.meta.espec = meta.meta.lb_hash[19:12];
    }
    action set_lb_hashed_index_ipv6() {
	// Tofino only supports up to 64-bit integer.
	// Therefore the hash is first given the lower 64 bits of
	// IPv6 address and then the upper bits.
        hash(meta.meta.lb_hash, HashAlgorithm.crc32, 21w0,
	     { hdr.inner_ipv6.srcAddrLower+hdr.inner_ipv6.dstAddrLower,
	       hdr.inner_ipv6.srcAddrUpper+hdr.inner_ipv6.dstAddrUpper }, 21w2^20);
        meta.meta.espec = meta.meta.lb_hash[19:12];
    }
    action set_lb_hashed_index_outer_ipv4() {
        hash(meta.meta.lb_hash, HashAlgorithm.crc32, 21w0,
	     { hdr.ipv4.srcAddr+hdr.ipv4.dstAddr }, 21w2^20);
        meta.meta.espec = meta.meta.lb_hash[19:12];
    }
    action set_lb_hashed_index_outer_ipv6() {
        hash(meta.meta.lb_hash, HashAlgorithm.crc32, 21w0,
	     { hdr.ipv6.srcAddrLower+hdr.ipv6.dstAddrLower,
	       hdr.ipv6.srcAddrUpper+hdr.ipv6.dstAddrUpper}, 21w2^20);
        meta.meta.espec = meta.meta.lb_hash[19:12];
    }

    action outer_ipv4_strip() {
        hdr.ipv4.setInvalid();
    }
    action outer_udp_strip() {
        hdr.udp.setInvalid();
    }
    action gtp_strip() {
        hdr.gtpv01_hdr.setInvalid();
        hdr.gtpv01_opts.setInvalid();
    }

    action set_egress_spec(bit<16> spec) {
	meta.ingress_metadata.egress_ifindex = spec;
    }

    table lb_tbl {
        key = {
            meta.meta.espec : exact;
        }
        actions = {
            set_egress_spec;
        }
    }
    apply {
	if ((meta.tunnel_metadata.ingress_tunnel_type >= (bit<8>)tunnelTypes.IPVX_IN_IP) &&
	    (meta.tunnel_metadata.ingress_tunnel_type < (bit<8>)tunnelTypes.EOMPLS)) { // IP tunnel
	    outer_ipv4_strip();
	    outer_udp_strip();
	    gtp_strip();
	    if (meta.meta.inner_tunnel_type == LB_TYPE_IPV4) {
		set_lb_hashed_index_ipv4();
            }
            else {
		if (meta.meta.inner_tunnel_type == LB_TYPE_IPV6) {
		    set_lb_hashed_index_ipv6();
		}
            }
	} else {
            if (hdr.ipv4.version == 4) {
		set_lb_hashed_index_outer_ipv4();
	    } else {
		set_lb_hashed_index_outer_ipv6();
	    }
	}
	lb_tbl.apply();
    }
}

control vendor_deparser(packet_out p, in headers_t hdr) {
    apply {
        p.emit(hdr.ethernet);
        p.emit(hdr.ipv4);
        p.emit(hdr.udp);
        p.emit(hdr.inner_ipv4);
        p.emit(hdr.inner_udp);
    }
}

