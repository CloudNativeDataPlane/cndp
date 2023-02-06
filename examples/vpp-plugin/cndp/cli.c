/*
 * Copyright (c) 2021-2023 Intel Corporation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <cndp/cndp.h>

static clib_error_t *cndp_interface_create_command_fn (vlib_main_t *vm,
                                                       unformat_input_t *input,
                                                       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *ifname = NULL;
  u32 nb_qs = (u32)~0;
  u32 offset = (u32)0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &ifname))
        ;
      else if (unformat (line_input, "qs %d", &nb_qs))
        ;
      else if (unformat (line_input, "offset %d", &offset))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  unformat_free (line_input);

  if (!ifname)
    return clib_error_return (0, "missing interface name");

  if (nb_qs > CNDP_MAX_PORTS || nb_qs <= 0)
    return clib_error_return (0, "invalid number of queues");

  return cndp_create_dev (vm, ifname, nb_qs, offset);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cndp_create_command, static) = {
    .path = "create interface cndp",
    .short_help = "create interface cndp <name ifname> <qs num> <offset num>",
    .function = cndp_interface_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *cndp_delete_command_fn (vlib_main_t *vm,
                                             unformat_input_t *input,
                                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
                    &sw_if_index))
        ;

      else

        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "please specify interface name");

  cndp_delete_dev (vm, sw_if_index);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cndp_delete_command, static) = {
    .path = "delete interface cndp",
    .short_help = "delete interface cndp "
                  "{<interface>}",
    .function = cndp_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *cndp_show_command_fn (vlib_main_t *vm,
                                           unformat_input_t *input,
                                           vlib_cli_command_t *cmd)
{
  cndp_main_t *cmp = &cndp_main;
  cndp_lport_t *lport;
  cndp_device_t *cd;

  if (pool_elts (cmp->devices) == 0)
    {
      vlib_cli_output (vm, "No devices configured\n");
      goto exit;
    }

  for (int i = 0; i < cmp->total_devs; i++)
    {
      cd = cmp->devices[i];
      pool_foreach (lport, cd->lports)
          vlib_cli_output (vm, "   lport: %s\n", lport->cfg.name);
    }

exit:
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cndp_show_command, static) = {
    .path = "cndp show",
    .short_help = "show CNDP interfaces and lports",
    .function = cndp_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *cndp_set_log_level_command_fn (vlib_main_t *vm,
                                                    unformat_input_t *input,
                                                    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  cndp_main_t *sm = &cndp_main;
  u8 *level;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &level))
        {
          if (strcmp ((const char *)level, "error") == 0)
            sm->log_level = CNDP_LOG_LEVEL_ERR;
          else if (strcmp ((const char *)level, "warning") == 0)
            sm->log_level = CNDP_LOG_LEVEL_WARNING;
          else if (strcmp ((const char *)level, "notice") == 0)
            sm->log_level = CNDP_LOG_LEVEL_NOTICE;
          else if (strcmp ((const char *)level, "info") == 0)
            sm->log_level = CNDP_LOG_LEVEL_INFO;
          else if (strcmp ((const char *)level, "debug") == 0)
            sm->log_level = CNDP_LOG_LEVEL_DEBUG;
          else
            {
              sm->log_level = CNDP_LOG_LEVEL_DISABLED;
            }
          vlib_cli_output (vm, "CNDP log level %s", level);
        }
      else
        {
          error = clib_error_return (0, "parse error: '%U'",
                                     format_unformat_error, line_input);
        }
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cndp_set_log_level_command, static) = {
    .path = "cndp log-level",
    .short_help = "cndp log-level [error|warning|notice|info|debug]",
    .function = cndp_set_log_level_command_fn,
};
/* *INDENT-ON* */

clib_error_t *cndp_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (cndp_cli_init);
