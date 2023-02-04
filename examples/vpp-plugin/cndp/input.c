/*
 * input.c - CNDP input node
 *
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
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <cndp/cndp.h>
#include <cndp/xskdev.h>

#if USE_2101_RX_QUEUES == 0
#include <vnet/interface/rx_queue_funcs.h>
#endif

#ifndef CLIB_MARCH_VARIANT
/* packet trace format function */
static u8 *format_cndp_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  cndp_trace_t *t = va_arg (*args, cndp_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

  s = format (s, "cndp: %v (%d) next-node %U", hi->name, t->hw_if_index,
              format_vlib_next_node_name, vm, node->index, t->next_index);

  return s;
}
#endif /* !CLIB_MARCH_VARIANT */

static_always_inline void cndp_device_input_trace (vlib_main_t *vm,
                                                   vlib_node_runtime_t *node,
                                                   u32 n_left, const u32 *bi,
                                                   u32 next_index,
                                                   u32 hw_if_index)
{
  u32 n_trace;

  if (PREDICT_TRUE (0 == (n_trace = vlib_get_trace_count (vm, node))))
    return;

  while (n_trace && n_left)
    {
      vlib_buffer_t *b;
      cndp_trace_t *tr;
      b = vlib_get_buffer (vm, bi[0]);
      if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, 0)))
        {
          tr = vlib_add_trace (vm, node, b, sizeof (*tr));
          tr->next_index = next_index;
          tr->hw_if_index = hw_if_index;
        }

      n_trace--;
      n_left--;
      bi++;
    }

  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline void proc_buf (vlib_buffer_t *rx_pkt, vlib_buffer_t *bt)
{
  vnet_buffer (rx_pkt)->sw_if_index[VLIB_RX] =
      vnet_buffer (bt)->sw_if_index[VLIB_RX];
  rx_pkt->flags = bt->flags;
  vnet_buffer (rx_pkt)->sw_if_index[VLIB_TX] = (u32)~0;
  rx_pkt->buffer_pool_index = bt->buffer_pool_index;
  vnet_buffer (rx_pkt)->feature_arc_index =
      vnet_buffer (bt)->feature_arc_index;
}

static uword cndp_device_input (vlib_main_t *vm, vlib_node_runtime_t *node,
                                cndp_device_t *cd, u16 qid)
{
  uword n_rx_packets = 0;
  u32 n_pkts;
  u32 n_rx_bytes = 0;
  u32 i = 0, n_left_to_next;
  u32 vlib_bi[VLIB_FRAME_SIZE], *b = vlib_bi;
  vlib_buffer_t *rx_pkts[VLIB_FRAME_SIZE];

  u32 *to_next = 0;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t bt;

  cndp_lport_t *port = vec_elt_at_index (cd->lports, qid - cd->offset);

  int tid = cne_id ();
  if (tid < 0)
    {
      char *name =
          (char *)format (0, "vpp_thread_%d", vlib_get_thread_index ());
      cne_register (name);
    }

  n_pkts = xskdev_rx_burst (port->xi, (void **)rx_pkts, VLIB_FRAME_SIZE);
  if (!n_pkts)
    {
      return 0;
    }
  vlib_get_buffer_indices (vm, rx_pkts, vlib_bi, n_pkts);

  n_rx_packets = n_pkts;
  vlib_buffer_copy_template (&bt, &cd->buffer_template);

  /* update the template with sw if index */
  vnet_buffer (&bt)->sw_if_index[VLIB_RX] = cd->sw_if_index;

  /* as all packets belong to the same interface feature arc lookup
   * can be done once and result stored in the buffer template
   */
  if (PREDICT_FALSE (vnet_device_input_have_features (cd->sw_if_index)))
    vnet_feature_start_device_input_x1 (cd->sw_if_index, &next_index, &bt);

  /* Get next frame from next node */
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  int n = n_rx_packets;

  while (n >= 4)
    {
      ASSERT (vlib_buffer_is_known (vm, b[0]) == VLIB_BUFFER_KNOWN_ALLOCATED);
      ASSERT (vlib_buffer_is_known (vm, b[1]) == VLIB_BUFFER_KNOWN_ALLOCATED);
      ASSERT (vlib_buffer_is_known (vm, b[2]) == VLIB_BUFFER_KNOWN_ALLOCATED);
      ASSERT (vlib_buffer_is_known (vm, b[3]) == VLIB_BUFFER_KNOWN_ALLOCATED);

      proc_buf (rx_pkts[i], &bt);
      proc_buf (rx_pkts[i + 1], &bt);
      proc_buf (rx_pkts[i + 2], &bt);
      proc_buf (rx_pkts[i + 3], &bt);

      n_rx_bytes += rx_pkts[i]->current_length;
      n_rx_bytes += rx_pkts[i + 1]->current_length;
      n_rx_bytes += rx_pkts[i + 2]->current_length;
      n_rx_bytes += rx_pkts[i + 3]->current_length;

      to_next[i] = b[0];
      to_next[i + 1] = b[1];
      to_next[i + 2] = b[2];
      to_next[i + 3] = b[3];

      b += 4;
      i += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      ASSERT (vlib_buffer_is_known (vm, b[0]) == VLIB_BUFFER_KNOWN_ALLOCATED);
      proc_buf (rx_pkts[i], &bt);
      n_rx_bytes += rx_pkts[i]->current_length;
      to_next[i] = b[0];
      b += 1;
      i += 1;
      n -= 1;
    }

  if (PREDICT_FALSE (VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT != next_index))
    goto put_frame;

  ethernet_input_frame_t *ef;
  vlib_next_frame_t *nf;
  vlib_frame_t *f;

  nf = vlib_node_runtime_get_next_frame (
      vm, node, VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT);
  f = vlib_get_frame (vm, nf->frame);
  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = cd->sw_if_index;
  ef->hw_if_index = cd->hw_if_index;

put_frame:
  n_left_to_next -= n_rx_packets;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  cndp_device_input_trace (vm, node, n_rx_packets, to_next, next_index,
                           cd->hw_if_index);

  vlib_increment_combined_counter (
      vnet_get_main ()->interface_main.combined_sw_if_counters +
          VNET_INTERFACE_COUNTER_RX,
      vlib_get_thread_index (), cd->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (vm->thread_index, n_rx_packets);

  return n_rx_packets;
}

VLIB_NODE_FN (cndp_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f)
{
  uword n_rx_packets = 0;
  cndp_main_t *cmp = &cndp_main;
#if USE_2101_RX_QUEUES == 1
  /* VPP 21.06 changes how rx queues are processed */
  vnet_device_input_runtime_t *rt = (void *)node->runtime_data;
  vnet_device_and_queue_t *dq;
#else
  vnet_hw_if_rxq_poll_vector_t *pv;
#endif

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
#if USE_2101_RX_QUEUES == 1
  /* VPP 21.06 changes how rx queues are processed */
  /* *INDENT-OFF* */
  foreach_device_and_queue (dq, rt->devices_and_queues)
    {
      cndp_device_t *cd;

      cd = cmp->devices[dq->dev_instance];
      n_rx_packets += cndp_device_input (vm, node, cd, dq->queue_id);
    }
  /* *INDENT-ON* */
#else
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (int i = 0; i < vec_len (pv); i++)
    {
      cndp_device_t *cd;

      cd = cmp->devices[pv[i].dev_instance];
      n_rx_packets += cndp_device_input (vm, node, cd, pv[i].queue_id);
    }
#endif

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cndp_input_node) = {
    .type = VLIB_NODE_TYPE_INPUT,
    .name = "cndp-input",
    .sibling_of = "device-input",

    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
#ifndef CLIB_MARCH_VARIANT
    .format_trace = format_cndp_trace,
#endif /* !CLIB_MARCH_VARIANT */

    /* Will be enabled if/when hardware is detected. */
    .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
