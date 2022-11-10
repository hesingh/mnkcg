#include <v1model.p4>
#include "../vendor.p4"

header rtp_t {
    bit<2>  version;
    bit<1>  padding;
    bit<1>  extension;
    bit<4>  CSRC_count;
    bit<1>  marker;
    bit<7>  payload_type;
    bit<16> sequence_number;
    bit<32> timestamp;
    bit<32> SSRC;
}


struct metadata {
}

struct headers {
    rtp_t      rtp;
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_rtp;
    }
    state parse_rtp {
        packet.extract(hdr.rtp);
        transition accept;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    direct_counter(CounterType.bytes) my_direct_counter;
    action take_video(bit<32> dst_ip) {
        standard_metadata.egress_spec = 9w1;
        hdr.ipv4.dstAddr = dst_ip;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action take_video_0(bit<32> dst_ip) {
        my_direct_counter.count();
        standard_metadata.egress_spec = 9w1;
        hdr.ipv4.dstAddr = dst_ip;
    }
    action _drop_0() {
        my_direct_counter.count();
        mark_to_drop(standard_metadata);
    }
    table schedule_table {
        actions = {
            take_video_0;
            _drop_0;
        }
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.rtp.timestamp: range;
        }
        size = 16384;
        counters = my_direct_counter;
    }
    apply {
        schedule_table.apply();
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.rtp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

