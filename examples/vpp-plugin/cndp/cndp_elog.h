/*
 * Copyright (c) 2021-2023 Intel and/or its affiliates.
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
 */
#ifndef __included_cndp_elog_h__
#define __included_cndp_elog_h__

#include <vppinfra/elog.h>
#include <vlib/log.h>

/*
 * The vpp engine event log is thread-safe, and is shared by all threads.
 * Note: it’s not appropriate for per-packet use in hard-core data plane
 * code. It’s most appropriate for capturing rare events - link up-down
 * events, specific control-plane events and so forth.
 * More info can be found here: https://wiki.fd.io/view/VPP/elog
 * vpp# event-logger clear
 * vpp# event-logger save <filename> # for security, writes into
 * /tmp/<filename>. # <filename> must not contain '.' or '/' characters vpp#
 * show event-logger [all] [<nnn>] # display the event log # by default, the
 * last 250 entries
 */

#define foreach_cndp_log_level \
  _ (0, EMERG, emerg)          \
  _ (1, ALERT, alert)          \
  _ (2, CRIT, crit)            \
  _ (3, ERR, err)              \
  _ (4, WARNING, warn)         \
  _ (5, NOTICE, notice)        \
  _ (6, INFO, info)            \
  _ (7, DEBUG, debug)          \
  _ (8, DISABLED, disabled)

typedef enum
{
#define _(n, uc, lc) CNDP_LOG_LEVEL_##uc = n,
  foreach_cndp_log_level
#undef _
} cndp_log_level_t;

#define cndp_elog(_cmp, _level, _str)                 \
  do                                                  \
    {                                                 \
      if (PREDICT_FALSE (_cmp->log_level >= _level))  \
        {                                             \
          ELOG_TYPE_DECLARE (e) = {                   \
              .format = "cndp-msg " _str,             \
              .format_args = "",                      \
          };                                          \
          ELOG_DATA (&vlib_global_main.elog_main, e); \
        }                                             \
    }                                                 \
  while (0);

#define cndp_elog_X1(_cmp, _level, _fmt, _arg, _val1)         \
  do                                                          \
    {                                                         \
      if (PREDICT_FALSE (_cmp->log_level >= _level))          \
        {                                                     \
          ELOG_TYPE_DECLARE (e) = {                           \
              .format = "cndp-msg " _fmt,                     \
              .format_args = _arg,                            \
          };                                                  \
          CLIB_PACKED (struct { typeof (_val1) val1; }) * ed; \
          ed = ELOG_DATA (&vlib_global_main.elog_main, e);    \
          ed->val1 = _val1;                                   \
        }                                                     \
    }                                                         \
  while (0);

#define cndp_elog_STR1(_cmp, _level, _fmt, _arg, _val1)                  \
  do                                                                     \
    {                                                                    \
      if (PREDICT_FALSE (_cmp->log_level >= _level))                     \
        {                                                                \
          ELOG_TYPE_DECLARE (e) = {                                      \
              .format = "cndp-msg " _fmt,                                \
              .format_args = "T4",                                       \
          };                                                             \
          CLIB_PACKED (struct { u32 offset; }) * ed;                     \
          ed = ELOG_DATA (&vlib_global_main.elog_main, e);               \
          ed->offset = elog_string (&vlib_global_main.elog_main, _val1); \
        }                                                                \
    }                                                                    \
  while (0);

#if 0

// Can define other functions here in the future
// _cmp is the main node struct
#define cndp_elog_addr(_cmp, _level, _str, _addr)          \
  do                                                       \
    {                                                      \
      if (PREDICT_FALSE (_cmp->log_level >= _level))       \
        {                                                  \
          ELOG_TYPE_DECLARE (e) = {                        \
              .format = "cndp-msg " _str " %d.%d.%d.%d",   \
              .format_args = "i1i1i1i1",                   \
          };                                               \
          CLIB_PACKED (struct {                            \
            u8 oct1;                                       \
            u8 oct2;                                       \
            u8 oct3;                                       \
            u8 oct4;                                       \
          }) * ed;                                         \
          ed = ELOG_DATA (&_cmp->vlib_main->elog_main, e); \
          ed->oct4 = _addr >> 24;                          \
          ed->oct3 = _addr >> 16;                          \
          ed->oct2 = _addr >> 8;                           \
          ed->oct1 = _addr;                                \
        }                                                  \
    }                                                      \
  while (0);

//example usage
//cndp_elog_addr (cndp_LOG_WARNING, "[warn] max translations per user",
//                    clib_net_to_host_u32 (u->addr.as_u32));
#endif

/*
 * use like: cndp_elog_info (cmp, "Device added"););
 */

#define cndp_elog_notice(cmp, cndp_elog_str) \
  cndp_elog (cmp, CNDP_LOG_LEVEL_NOTICE, "[notice] " cndp_elog_str)
#define cndp_elog_warn(cmp, cndp_elog_str) \
  cndp_elog (cmp, CNDP_LOG_LEVEL_WARNING, "[warning] " cndp_elog_str)
#define cndp_elog_err(cmp, cndp_elog_str) \
  cndp_elog (cmp, CNDP_LOG_LEVEL_ERROR, "[error] " cndp_elog_str)
#define cndp_elog_debug(cmp, cndp_elog_str) \
  cndp_elog (cmp, CNDP_LOG_LEVEL_DEBUG, "[debug] " cndp_elog_str)
#define cndp_elog_info(cmp, cndp_elog_str) \
  cndp_elog (cmp, CNDP_LOG_LEVEL_INFO, "[info] " cndp_elog_str)

/*
 * use like:  cndp_elog_info_X1 (cmp, "Registering THREAD vpp_main_%d", "i4",
 * vlib_get_thread_index());
 */
#define cndp_elog_notice_X1(_cmp, cndp_elog_fmt_str, cndp_elog_fmt_arg,     \
                            cndp_elog_val1)                                 \
  cndp_elog_X1 (_cmp, CNDP_LOG_LEVEL_NOTICE, "[notice] " cndp_elog_fmt_str, \
                cndp_elog_fmt_arg, cndp_elog_val1)
#define cndp_elog_warn_X1(_cmp, cndp_elog_fmt_str, cndp_elog_fmt_arg,         \
                          cndp_elog_val1)                                     \
  cndp_elog_X1 (_cmp, CNDP_LOG_LEVEL_WARNING, "[warning] " cndp_elog_fmt_str, \
                cndp_elog_fmt_arg, cndp_elog_val1)
#define cndp_elog_err_X1(_cmp, cndp_elog_fmt_str, cndp_elog_fmt_arg,      \
                         cndp_elog_val1)                                  \
  cndp_elog_X1 (_cmp, CNDP_LOG_LEVEL_ERROR, "[error] " cndp_elog_fmt_str, \
                cndp_elog_fmt_arg, cndp_elog_val1)
#define cndp_elog_debug_X1(_cmp, cndp_elog_fmt_str, cndp_elog_fmt_arg,    \
                           cndp_elog_val1)                                \
  cndp_elog_X1 (_cmp, CNDP_LOG_LEVEL_DEBUG, "[debug] " cndp_elog_fmt_str, \
                cndp_elog_fmt_arg, cndp_elog_val1)
#define cndp_elog_info_X1(_cmp, cndp_elog_fmt_str, cndp_elog_fmt_arg,   \
                          cndp_elog_val1)                               \
  cndp_elog_X1 (_cmp, CNDP_LOG_LEVEL_INFO, "[info] " cndp_elog_fmt_str, \
                cndp_elog_fmt_arg, cndp_elog_val1)

/*
 * use like: cndp_elog_info_STR1 (cmp, "CNDP lport: %s created",
 * lport->cfg.name);
 */
#define cndp_elog_notice_STR1(_cmp, cndp_elog_fmt_str, cndp_elog_val1)        \
  cndp_elog_STR1 (_cmp, CNDP_LOG_LEVEL_NOTICE, "[notice] " cndp_elog_fmt_str, \
                  , cndp_elog_val1)
#define cndp_elog_warn_STR1(_cmp, cndp_elog_fmt_str, cndp_elog_val1) \
  cndp_elog_STR1 (_cmp, CNDP_LOG_LEVEL_WARNING,                      \
                  "[warning] " cndp_elog_fmt_str, , cndp_elog_val1)
#define cndp_elog_err_STR1(_cmp, cndp_elog_fmt_str, cndp_elog_val1)           \
  cndp_elog_STR1 (_cmp, CNDP_LOG_LEVEL_ERROR, "[error] " cndp_elog_fmt_str, , \
                  cndp_elog_val1)
#define cndp_elog_debug_STR1(_cmp, cndp_elog_fmt_str, cndp_elog_val1)         \
  cndp_elog_STR1 (_cmp, CNDP_LOG_LEVEL_DEBUG, "[debug] " cndp_elog_fmt_str, , \
                  cndp_elog_val1)
#define cndp_elog_info_STR1(_cmp, cndp_elog_fmt_str, cndp_elog_val1)        \
  cndp_elog_STR1 (_cmp, CNDP_LOG_LEVEL_INFO, "[info] " cndp_elog_fmt_str, , \
                  cndp_elog_val1)

#endif /* __included_cndp_elog_h__ */
