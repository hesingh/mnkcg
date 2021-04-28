static clib_error_t *
upf_tbl_entry_add_command_fn (vlib_main_t * vm, unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  struct pkt_filter4_0_key key;
  u8 *tbl_name = NULL, *action_name = NULL, *delimiter = NULL;

  uint8_t abits;
  uint16_t ig_strip;
  uint16_t outer_desc;
  uint32_t teid;
  uint32_t ip;
  uint32_t src_ip;
  uint16_t dstPort;
  uint8_t filt_dir;
  uint8_t reflec_qos;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s %s %x %x %hhu %hhu %hu %hu %s %hhu %hu %hu %u %x %x %hu %hhu %hhu",
		    &tbl_name,
		    &action_name,
		    &key.field0,
		    &key.field1,
		    &key.field2,
		    &key.field3,
		    &key.field4,
		    &key.field5,
		    &delimiter,
		    &abits,
		    &ig_strip,
		    &outer_desc,
		    &teid,
		    &ip,
		    &src_ip,
		    &dstPort,
		    &filt_dir,
		    &reflec_qos)) {
	break;
      } else {
	error = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
	goto done;
      }
    }

 done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (upf_tbl_entry_add_command, static) = {
  .path = "upf add-entry",
  .short_help = "upf add-entry <table name> <action_name> <key> => <value>",
  .function = upf_tbl_entry_add_command_fn,
};
/* *INDENT-ON* */
