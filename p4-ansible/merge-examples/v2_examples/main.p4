#include <v1model.p4>
#include "vendor.p4"

V1Switch(vendor_parser(),
         vverifyChecksum(),
         vendor_ingress(),
         vendor_egress(),
         vcomputeChecksum(),
         vendor_deparser()) main;
