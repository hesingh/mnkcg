  // Set entry value.
  pool_init_fixed (ump->pkt_filter4_0_pool, 1024);

  struct pkt_filter4_0_value val = {}, *value;
  val.action = permit4;
  val.u.permit4.abits = 130;
  val.u.permit4.ig_strip = 0;
  val.u.permit4.outer_desc = 1;
  val.u.permit4.teid = 5241;
  val.u.permit4.ip = 0x03030302;
  val.u.permit4.src_ip = 0x03030301;
  val.u.permit4.dstPort = 2152;
  val.u.permit4.filt_dir = 1;
  val.u.permit4.reflec_qos = 0;
  clib_memset (&val.pad[0], 0, sizeof (val.pad));

  pool_get_aligned (ump->pkt_filter4_0_pool, value, CLIB_CACHE_LINE_BYTES);
  memcpy(value, &val, sizeof(val));
  u32 index = value - ump->pkt_filter4_0_pool;
  kv.value = index;
  clib_bihash_add_del_48_8 (&ump->hash_table_pkt_filter4_0, &kv, 1);



 u32 index;
 /* perform lookup */
 clib_bihash_kv_48_8_t search_kv, return_kv;
 clib_memset (&search_kv, 0, sizeof(search_kv));
 clib_memset (&return_kv, 0, sizeof(return_kv));
 memcpy(&search_kv.key, &key, sizeof(key));
 if (clib_bihash_search_48_8 (hip_pkt_filter4_0, &search_kv, &return_kv) < 0) {
     fprintf(stderr, "Plugin pkt_filter4_0 tbl lookup FAIL\n");
 } else {
     index = return_kv.value >> CLIB_LOG2_CACHE_LINE_BYTES;
     value = pool_elt_at_index(ump->pkt_filter4_0_pool, index);
 }
