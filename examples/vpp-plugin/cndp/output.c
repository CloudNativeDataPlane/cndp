/*
 * output.c - CNDP device
 *
 * Copyright (c) 2021-2025 Intel Corporation
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

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <cndp/cndp.h>
#include <cndp/cne.h>
#include <cndp/xskdev.h>

/*
 * Transmits the packets on the frame to the interface associated with the
 * node.
 */
VNET_DEVICE_CLASS_TX_FN (cndp_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f)
{
  uword n_sent = 0;
  vlib_buffer_t *tx_pkts[VLIB_FRAME_SIZE];
  cndp_main_t *cmp = &cndp_main;
  vnet_interface_output_runtime_t *rd = (void *)node->runtime_data;
  u32 n_packets = f->n_vectors;
  u32 thread_index = vm->thread_index;
  cndp_device_t *d = cmp->devices[rd->dev_instance];

  cndp_lport_t *port =
      vec_elt_at_index (d->lports, thread_index % pool_elts (d->lports));

  ASSERT (n_packets <= VLIB_FRAME_SIZE);

  vlib_get_buffers (vm, vlib_frame_vector_args (f), tx_pkts, n_packets);

  int tid = cne_id ();
  if (tid < 0)
    {
      char *name =
          (char *)format (0, "vpp_thread_%d", vlib_get_thread_index ());
      tid = cne_register (name);
    }

  /* send packets to device */
  n_sent = xskdev_tx_burst (port->xi, (void **)tx_pkts, n_packets);

  return n_sent;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (cndp_device_class) = {
    .name = "cndp",
    .format_device_name = format_cndp_device_name,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
