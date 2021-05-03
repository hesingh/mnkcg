/*
* Copyright 2021, MNK Labs & Consulting
* http://mnkcg.com
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*  li.p4
*/
#include <v1model.p4>
#include "vpp_headers.p4"

struct ingress_metadata_t {
    bit<32> collector;
}

struct metadata {
    ingress_metadata_t imd;
}

struct headers {
    ethernet_header_t ethernet;
    ip4_header_t     ipv4;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr = hdr.ethernet);
        transition select(hdr.ethernet.type) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr = hdr.ipv4);
        transition accept;
    }
    state start {
        transition parse_ethernet;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action on_miss() {}
    action fib_hit (bit<32> collector) {
        meta.imd.collector = collector;
    }
    table ipv4_fib {
        actions = {
            on_miss;
            fib_hit;
        }
        key = {
            hdr.ipv4.src_address         : exact;
        }
        size = 1024;
    }
    apply {
        if (hdr.ipv4.isValid())
            ipv4_fib.apply();
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

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

V1Switch(p = ParserImpl(),
         ig = ingress(),
         vr = verifyChecksum(),
         eg = egress(),
         ck = computeChecksum(),
         dep = DeparserImpl()) main;
