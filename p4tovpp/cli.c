/*
* Copyright 2020-2021, MNK Labs & Consulting
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
*/

static clib_error_t *
upf_tbl_entry_add_command_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *tbl_name = NULL, *action_name = NULL, *delimiter = NULL;

  // Most C compilers do not support scanf for integer values < 32 bits.
  // For example, C supports %hd and %hhd formats for scanf of 16 and 8 bit
  // integers respectively, but some comiplers do not. This is why we use 32-bit
  // variables to scanf input < 32 bits.

  // Declare 32-bit key fields for unformat
  uint32_t k0field0_32 = 0, k1field2_32 = 0, k1field3_32 = 0, k1field4_32 = 0;
  uint32_t k1field5_32 = 0, k2field2_32 = 0, k2field4_32 = 0, k2field5_32 = 0;

  // Declare 32-bit key fields for unformat
  uint32_t k3field0_32 = 0;
  // Declare 32-bit value fields for unformat
  uint32_t abits_v1a1field0_32 = 0, ig_strip_v1a1field1_32 = 0, outer_desc_v1a1field2_32 = 0, dstPort_v1a1field6_32 = 0;
  uint32_t filt_dir_v1a1field7_32 = 0, reflec_qos_v1a1field8_32 = 0, abits_v1a2field0_32 = 0, ig_strip_v1a2field1_32 = 0;
  uint32_t etherType_v1a2field4_32 = 0, abits_v2a1field0_32 = 0, ig_strip_v2a1field1_32 = 0, outer_desc_v2a1field2_32 = 0;
  uint32_t dstPort_v2a1field6_32 = 0, filt_dir_v2a1field7_32 = 0, reflec_qos_v2a1field8_32 = 0, abits_v2a2field0_32 = 0;
  uint32_t ig_strip_v2a2field1_32 = 0, etherType_v2a2field4_32 = 0;

  // Declare value fields for copying later
  uint8_t abits_v1a1field0;
  uint16_t ig_strip_v1a1field1;
  uint16_t outer_desc_v1a1field2;
  uint32_t teid_v1a1field3;
  uint32_t ip_v1a1field4;
  uint32_t src_ip_v1a1field5;
  uint16_t dstPort_v1a1field6;
  uint8_t filt_dir_v1a1field7;
  uint8_t reflec_qos_v1a1field8;
  uint8_t abits_v1a2field0;
  uint16_t ig_strip_v1a2field1;
  uint8_t srcAddr_v1a2field2[8];
  uint8_t dstAddr_v1a2field3[8];
  uint16_t etherType_v1a2field4;
  uint8_t abits_v2a1field0;
  uint16_t ig_strip_v2a1field1;
  uint16_t outer_desc_v2a1field2;
  uint32_t teid_v2a1field3;
  uint8_t ip6_v2a1field4[16];
  uint8_t src_ip6_v2a1field5[16];
  uint16_t dstPort_v2a1field6;
  uint8_t filt_dir_v2a1field7;
  uint8_t reflec_qos_v2a1field8;
  uint8_t abits_v2a2field0;
  uint16_t ig_strip_v2a2field1;
  uint8_t srcAddr_v2a2field2[8];
  uint8_t dstAddr_v2a2field3[8];
  uint16_t etherType_v2a2field4;
  uint8_t smac_v3a1field0[8];
  uint8_t dmac_v3a1field1[8];

  // Declare tables key and value.
  struct intermediate_upf_filter_0_key key0;
  struct intermediate_upf_filter_0_value val0, *value0;
  struct pkt_filter4_0_key key1;
  struct pkt_filter4_0_value val1, *value1;
  struct pkt_filter6_0_key key2;
  struct pkt_filter6_0_value val2, *value2;
  struct rewrite_mac_0_key key3;
  struct rewrite_mac_0_value val3, *value3;

  // Declare vars used to write a table entry.
  upf_main_t *ump = &upf_main;
  clib_bihash_kv_48_8_t kv;
  clib_memset (&kv, 0, sizeof (kv));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
{
    if (unformat (line_input, "table %s", &tbl_name)) {
      ;
    } else if (unformat (line_input, "action %s", &action_name)) {
      ;
    } else if (unformat (line_input, "k0field0 %u", &k0field0_32)) { // meta._acl_qfi29
      ;
    } else if (unformat (line_input, "k0field1 %u", &key0.field1)) { // meta._acl_outer_info_teid7
      ;
    } else if (unformat (line_input, "k1field0 %U", unformat_ip4_address, &key1.field0)) { // hdr.ipv4.srcAddr
      ;
    } else if (unformat (line_input, "k1field1 %U", unformat_ip4_address, &key1.field1)) { // hdr.ipv4.dstAddr
      ;
    } else if (unformat (line_input, "k1field2 %u", &k1field2_32)) { // hdr.ipv4.protocol
      ;
    } else if (unformat (line_input, "k1field3 %u", &k1field3_32)) { // hdr.ipv4.diffServ
      ;
    } else if (unformat (line_input, "k1field4 %u", &k1field4_32)) { // meta._acl_l4srcPort4
      ;
    } else if (unformat (line_input, "k1field5 %u", &k1field5_32)) { // meta._acl_l4dstPort5
      ;
    } else if (unformat (line_input, "k2field0 %U", unformat_ip6_address, &key2.field0)) { // hdr.ipv6.srcAddr
      ;
    } else if (unformat (line_input, "k2field1 %U", unformat_ip6_address, &key2.field1)) { // hdr.ipv6.dstAddr
      ;
    } else if (unformat (line_input, "k2field2 %u", &k2field2_32)) { // hdr.ipv6.nextHdr
      ;
    } else if (unformat (line_input, "k2field3 %u", &key2.field3)) { // hdr.ipv6.flowLabel
      ;
    } else if (unformat (line_input, "k2field4 %u", &k2field4_32)) { // meta._acl_l4srcPort4
      ;
    } else if (unformat (line_input, "k2field5 %u", &k2field5_32)) { // meta._acl_l4dstPort5
      ;
    } else if (unformat (line_input, "k3field0 %u", &k3field0_32)) { // meta._ig_md_egress_ifindex49
      ;
    } else if (unformat (line_input, "deli %s", &delimiter)) {
      ;
    } else if (unformat (line_input, "v1a1_abits %u", &abits_v1a1field0_32)) { // abits
      ;
    } else if (unformat (line_input, "v1a1_ig_strip %u", &ig_strip_v1a1field1_32)) { // ig_strip
      ;
    } else if (unformat (line_input, "v1a1_outer_desc %u", &outer_desc_v1a1field2_32)) { // outer_desc
      ;
    } else if (unformat (line_input, "v1a1_teid %u", &teid_v1a1field3)) { // teid
      ;
    } else if (unformat (line_input, "v1a1_ip %U", unformat_ip4_address, &ip_v1a1field4)) { // ip
      ;
    } else if (unformat (line_input, "v1a1_src_ip %U", unformat_ip4_address, &src_ip_v1a1field5)) { // src_ip
      ;
    } else if (unformat (line_input, "v1a1_dstPort %u", &dstPort_v1a1field6_32)) { // dstPort
      ;
    } else if (unformat (line_input, "v1a1_filt_dir %u", &filt_dir_v1a1field7_32)) { // filt_dir
      ;
    } else if (unformat (line_input, "v1a1_reflec_qos %u", &reflec_qos_v1a1field8_32)) { // reflec_qos
      ;
    } else if (unformat (line_input, "v1a2_abits %u", &abits_v1a2field0_32)) { // abits
      ;
    } else if (unformat (line_input, "v1a2_ig_strip %u", &ig_strip_v1a2field1_32)) { // ig_strip
      ;
    } else if (unformat (line_input, "v1a2_srcAddr %U", my_unformat_mac_address, &srcAddr_v1a2field2)) { // srcAddr
      ;
    } else if (unformat (line_input, "v1a2_dstAddr %U", my_unformat_mac_address, &dstAddr_v1a2field3)) { // dstAddr
      ;
    } else if (unformat (line_input, "v1a2_etherType %u", &etherType_v1a2field4_32)) { // etherType
      ;
    } else if (unformat (line_input, "v2a1_abits %u", &abits_v2a1field0_32)) { // abits
      ;
    } else if (unformat (line_input, "v2a1_ig_strip %u", &ig_strip_v2a1field1_32)) { // ig_strip
      ;
    } else if (unformat (line_input, "v2a1_outer_desc %u", &outer_desc_v2a1field2_32)) { // outer_desc
      ;
    } else if (unformat (line_input, "v2a1_teid %u", &teid_v2a1field3)) { // teid
      ;
    } else if (unformat (line_input, "v2a1_ip6 %U", unformat_ip6_address, &ip6_v2a1field4)) { // ip6
      ;
    } else if (unformat (line_input, "v2a1_src_ip6 %U", unformat_ip6_address, &src_ip6_v2a1field5)) { // src_ip6
      ;
    } else if (unformat (line_input, "v2a1_dstPort %u", &dstPort_v2a1field6_32)) { // dstPort
      ;
    } else if (unformat (line_input, "v2a1_filt_dir %u", &filt_dir_v2a1field7_32)) { // filt_dir
      ;
    } else if (unformat (line_input, "v2a1_reflec_qos %u", &reflec_qos_v2a1field8_32)) { // reflec_qos
      ;
    } else if (unformat (line_input, "v2a2_abits %u", &abits_v2a2field0_32)) { // abits
      ;
    } else if (unformat (line_input, "v2a2_ig_strip %u", &ig_strip_v2a2field1_32)) { // ig_strip
      ;
    } else if (unformat (line_input, "v2a2_srcAddr %U", my_unformat_mac_address, &srcAddr_v2a2field2)) { // srcAddr
      ;
    } else if (unformat (line_input, "v2a2_dstAddr %U", my_unformat_mac_address, &dstAddr_v2a2field3)) { // dstAddr
      ;
    } else if (unformat (line_input, "v2a2_etherType %u", &etherType_v2a2field4_32)) { // etherType
      ;
    } else if (unformat (line_input, "v3a1_smac %U", my_unformat_mac_address, &smac_v3a1field0)) { // smac
      ;
    } else if (unformat (line_input, "v3a1_dmac %U", my_unformat_mac_address, &dmac_v3a1field1)) { // dmac
      ;
    } else {
     error = clib_error_return (0, "unknown input '%U'",
    		             format_unformat_error, input);
     goto done;
    }
    }

  // Get LSB from 32-bit key vars
  key0.field0 = k0field0_32 & 0xFF;
  key1.field2 = k1field2_32 & 0xFF;
  key1.field3 = k1field3_32 & 0xFF;
  key1.field4 = k1field4_32 & 0xFFFF;
  key1.field5 = k1field5_32 & 0xFFFF;
  key2.field2 = k2field2_32 & 0xFF;
  key2.field4 = k2field4_32 & 0xFFFF;
  key2.field5 = k2field5_32 & 0xFFFF;
  key3.field0 = k3field0_32 & 0xFFFF;
  // Get LBS from 32-bit value vars
  abits_v1a1field0 = abits_v1a1field0_32 & 0xFF;
  ig_strip_v1a1field1 = ig_strip_v1a1field1_32 & 0xFFFF;
  outer_desc_v1a1field2 = outer_desc_v1a1field2_32 & 0xFFFF;
  dstPort_v1a1field6 = dstPort_v1a1field6_32 & 0xFFFF;
  filt_dir_v1a1field7 = filt_dir_v1a1field7_32 & 0xFF;
  reflec_qos_v1a1field8 = reflec_qos_v1a1field8_32 & 0xFF;
  abits_v1a2field0 = abits_v1a2field0_32 & 0xFF;
  ig_strip_v1a2field1 = ig_strip_v1a2field1_32 & 0xFFFF;
  etherType_v1a2field4 = etherType_v1a2field4_32 & 0xFFFF;
  abits_v2a1field0 = abits_v2a1field0_32 & 0xFF;
  ig_strip_v2a1field1 = ig_strip_v2a1field1_32 & 0xFFFF;
  outer_desc_v2a1field2 = outer_desc_v2a1field2_32 & 0xFFFF;
  dstPort_v2a1field6 = dstPort_v2a1field6_32 & 0xFFFF;
  filt_dir_v2a1field7 = filt_dir_v2a1field7_32 & 0xFF;
  reflec_qos_v2a1field8 = reflec_qos_v2a1field8_32 & 0xFF;
  abits_v2a2field0 = abits_v2a2field0_32 & 0xFF;
  ig_strip_v2a2field1 = ig_strip_v2a2field1_32 & 0xFFFF;
  etherType_v2a2field4 = etherType_v2a2field4_32 & 0xFFFF;

  if (!strncmp((const char*)tbl_name, "intermediate_upf_filter_0", 25)) 
{
    if (!strncmp((const char*)action_name, "drop", 4)) {
      val0.action = drop;
    }
    else if (!strncmp((const char*)action_name, "allow", 5)) {
      val0.action = allow;
    }
    }
  else if (!strncmp((const char*)tbl_name, "pkt_filter4_0", 13)) 
{
    if (!strncmp((const char*)action_name, "drop4", 5)) {
      val1.action = drop4;
    }
    else if (!strncmp((const char*)action_name, "permit4", 7)) {
      val1.action = permit4;
      val1.u.permit4.abits = abits_v1a1field0;
      val1.u.permit4.ig_strip = ig_strip_v1a1field1;
      val1.u.permit4.outer_desc = outer_desc_v1a1field2;
      val1.u.permit4.teid = teid_v1a1field3;
      val1.u.permit4.ip = ip_v1a1field4;
      val1.u.permit4.src_ip = src_ip_v1a1field5;
      val1.u.permit4.dstPort = dstPort_v1a1field6;
      val1.u.permit4.filt_dir = filt_dir_v1a1field7;
      val1.u.permit4.reflec_qos = reflec_qos_v1a1field8;
    }
    else if (!strncmp((const char*)action_name, "add_eth4", 8)) {
      val1.action = add_eth4;
      val1.u.add_eth4.abits = abits_v1a2field0;
      val1.u.add_eth4.ig_strip = ig_strip_v1a2field1;
      memcpy(&val1.u.add_eth4.srcAddr, srcAddr_v1a2field2, sizeof(srcAddr_v1a2field2));
      memcpy(&val1.u.add_eth4.dstAddr, dstAddr_v1a2field3, sizeof(dstAddr_v1a2field3));
      val1.u.add_eth4.etherType = etherType_v1a2field4;
    }
    }
  else if (!strncmp((const char*)tbl_name, "pkt_filter6_0", 13)) 
{
    if (!strncmp((const char*)action_name, "drop6", 5)) {
      val2.action = drop6;
    }
    else if (!strncmp((const char*)action_name, "permit6", 7)) {
      val2.action = permit6;
      val2.u.permit6.abits = abits_v2a1field0;
      val2.u.permit6.ig_strip = ig_strip_v2a1field1;
      val2.u.permit6.outer_desc = outer_desc_v2a1field2;
      val2.u.permit6.teid = teid_v2a1field3;
      memcpy(&val2.u.permit6.ip6, ip6_v2a1field4, sizeof(ip6_v2a1field4));
      memcpy(&val2.u.permit6.src_ip6, src_ip6_v2a1field5, sizeof(src_ip6_v2a1field5));
      val2.u.permit6.dstPort = dstPort_v2a1field6;
      val2.u.permit6.filt_dir = filt_dir_v2a1field7;
      val2.u.permit6.reflec_qos = reflec_qos_v2a1field8;
    }
    else if (!strncmp((const char*)action_name, "add_eth6", 8)) {
      val2.action = add_eth6;
      val2.u.add_eth6.abits = abits_v2a2field0;
      val2.u.add_eth6.ig_strip = ig_strip_v2a2field1;
      memcpy(&val2.u.add_eth6.srcAddr, srcAddr_v2a2field2, sizeof(srcAddr_v2a2field2));
      memcpy(&val2.u.add_eth6.dstAddr, dstAddr_v2a2field3, sizeof(dstAddr_v2a2field3));
      val2.u.add_eth6.etherType = etherType_v2a2field4;
    }
    }
  else if (!strncmp((const char*)tbl_name, "rewrite_mac_0", 13)) 
{
    if (!strncmp((const char*)action_name, "on_miss", 7)) {
      val3.action = on_miss;
    }
    else if (!strncmp((const char*)action_name, "rewrite_src_dst_mac", 19)) {
      val3.action = rewrite_src_dst_mac;
      memcpy(&val3.u.rewrite_src_dst_mac.smac, smac_v3a1field0, sizeof(smac_v3a1field0));
      memcpy(&val3.u.rewrite_src_dst_mac.dmac, dmac_v3a1field1, sizeof(dmac_v3a1field1));
    }
    }

  // Program the entry.
  struct intermediate_upf_filter_0 *keyp0;
  struct pkt_filter4_0 *keyp1;
  struct pkt_filter6_0 *keyp2;
  struct rewrite_mac_0 *keyp3;

  if (!strncmp((const char*)tbl_name, "intermediate_upf_filter_0", 25)) 
{
    keyp0 = malloc(sizeof(key0));
    if (!keyp0) {
      error = clib_error_return (0, "malloc failed for key0",
			         format_unformat_error);
      goto done;
    }
    memcpy(keyp0, &key0, sizeof(key0));
    memcpy(&kv.key, keyp0, sizeof(key0));

    /* Setup value */
    value0 = malloc(sizeof(val0));
    if (!value0) {
      error = clib_error_return (0, "malloc failed for value0",
			         format_unformat_error);
      goto done;
    }
    memcpy(value0, &val0, sizeof(val0));
    kv.value = (u64) value0;

    clib_bihash_add_del_48_8 (&ump->hash_table_intermediate_upf_filter_0, &kv, 1);
    }
  else if (!strncmp((const char*)tbl_name, "pkt_filter4_0", 13)) 
{
    keyp1 = malloc(sizeof(key1));
    if (!keyp1) {
      error = clib_error_return (0, "malloc failed for key1",
			         format_unformat_error);
      goto done;
    }
    memcpy(keyp1, &key1, sizeof(key1));
    memcpy(&kv.key, keyp1, sizeof(key1));

    /* Setup value */
    value1 = malloc(sizeof(val1));
    if (!value1) {
      error = clib_error_return (0, "malloc failed for value1",
			         format_unformat_error);
      goto done;
    }
    memcpy(value1, &val1, sizeof(val1));
    kv.value = (u64) value1;

    clib_bihash_add_del_48_8 (&ump->hash_table_pkt_filter4_0, &kv, 1);
    }
  else if (!strncmp((const char*)tbl_name, "pkt_filter6_0", 13)) 
{
    keyp2 = malloc(sizeof(key2));
    if (!keyp2) {
      error = clib_error_return (0, "malloc failed for key2",
			         format_unformat_error);
      goto done;
    }
    memcpy(keyp2, &key2, sizeof(key2));
    memcpy(&kv.key, keyp2, sizeof(key2));

    /* Setup value */
    value2 = malloc(sizeof(val2));
    if (!value2) {
      error = clib_error_return (0, "malloc failed for value2",
			         format_unformat_error);
      goto done;
    }
    memcpy(value2, &val2, sizeof(val2));
    kv.value = (u64) value2;

    clib_bihash_add_del_48_8 (&ump->hash_table_pkt_filter6_0, &kv, 1);
    }
  else if (!strncmp((const char*)tbl_name, "rewrite_mac_0", 13)) 
{
    keyp3 = malloc(sizeof(key3));
    if (!keyp3) {
      error = clib_error_return (0, "malloc failed for key3",
			         format_unformat_error);
      goto done;
    }
    memcpy(keyp3, &key3, sizeof(key3));
    memcpy(&kv.key, keyp3, sizeof(key3));

    /* Setup value */
    value3 = malloc(sizeof(val3));
    if (!value3) {
      error = clib_error_return (0, "malloc failed for value3",
			         format_unformat_error);
      goto done;
    }
    memcpy(value3, &val3, sizeof(val3));
    kv.value = (u64) value3;

    clib_bihash_add_del_48_8 (&ump->hash_table_rewrite_mac_0, &kv, 1);
    }
 done:
  unformat_free (line_input);

  return error;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tbl_entry_add_command, static) =
{
  .path = "upf tbl-entry-add",
  .short_help =
  "upf tbl-entry-add <table name> <action_name> <key> => <value>",
  .function = upf_tbl_entry_add_command_fn,
/* *INDENT-ON* */
};
