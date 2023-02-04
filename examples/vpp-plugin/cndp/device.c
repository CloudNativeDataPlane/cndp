/*
 * device.c - CNDP plugin for vpp
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <cndp/cndp.h>
#include <cndp/cne_ether.h>
#include <cndp/cne_thread.h>
#include <cndp/netdev_funcs.h>
#include <vppinfra/unix.h>

#if USE_2101_RX_QUEUES == 0
#include <vnet/interface/rx_queue_funcs.h>
#endif

cndp_main_t cndp_main;

void cndp_delete_dev (vlib_main_t *vm, u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  cndp_main_t *cmp = &cndp_main;
  cndp_lport_t *lport;
  cndp_device_t *d;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || cndp_device_class.index != hw->dev_class_index)
    {
      vlib_cli_output (vm, "invalid interface");
      return;
    }

  d = cmp->devices[hw->dev_instance];

  vlib_cli_output (vm, " Deleting %s\n", d->ifname);

  if (d->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, d->hw_if_index, 0);
#if USE_2101_RX_QUEUES == 1
      /* VPP 21.06 changes how rx queues are processed */
      vec_foreach (lport, d->lports)
          vnet_hw_interface_unassign_rx_thread (vnm, d->hw_if_index, lport->qid);
#endif
      ethernet_delete_interface (vnm, d->hw_if_index);
    }

  vec_foreach (lport, d->lports) xskdev_socket_destroy (lport->xi);

  pool_free (d->lports);
  vec_free (d->ifname);
  cmp->total_devs -= 1;
  cmp->devices[cmp->total_devs] = NULL;
  free (d);
}

static int cndp_get_numa (const char *ifname)
{
  FILE *fptr;
  int numa;
  char *s;

  s = (char *)format (0, "/sys/class/net/%s/device/numa_node%c", ifname, 0);
  fptr = fopen (s, "rb");
  vec_free (s);

  if (!fptr)
    return 0;

  if (fscanf (fptr, "%d\n", &numa) != 1)
    numa = 0;

  fclose (fptr);

  if (numa < 0)
    numa = 0;

  return numa;
}

static inline int cndp_buf_alloc (void *arg, void **bufs, uint16_t nb_bufs)
{
  cndp_device_t *cd = (cndp_device_t *)arg;
  vlib_main_t *vm = vlib_get_main ();

  u32 bis[nb_bufs], *bi = bis;
  u32 n_alloc = 0;

  n_alloc = vlib_buffer_alloc_from_pool (vm, bi, nb_bufs, cd->pool);

  vlib_get_buffers (vm, bis, (vlib_buffer_t **)bufs, n_alloc);

  return n_alloc;
}

static inline void cndp_buf_free (void *arg, void **bufs, uint16_t nb_bufs)
{
  CLIB_UNUSED (cndp_device_t * cd) = (cndp_device_t *)arg;
  vlib_main_t *vm = vlib_get_main ();
  u32 bi[VLIB_FRAME_SIZE];

  vlib_get_buffer_indices (vm, (vlib_buffer_t **)bufs, bi, nb_bufs);

  vlib_buffer_free (vm, bi, nb_bufs);
}

static inline void cndp_buf_set_data_len (void *mb, int len)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  b->current_length = len;
}

static inline void cndp_buf_set_data (void *mb, uint64_t off)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  b->current_data = off;
}

static inline uint64_t cndp_buf_get_data (void *mb)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  return (vlib_buffer_get_current_va (b));
}

static inline uint16_t cndp_buf_get_data_len (void *mb)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  return b->current_length;
}

static inline uint64_t cndp_buf_get_addr (void *mb)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  return (pointer_to_uword (b));
}

static __cne_always_inline void **cndp_buf_inc_ptr (void **mbs)
{
  vlib_buffer_t **b = (vlib_buffer_t **)mbs;
  return (void **)++b;
}

static inline void cndp_buf_reset (void *mb, uint32_t buf_len, size_t headroom)
{
  vlib_buffer_t *b = (vlib_buffer_t *)mb;

  vlib_buffer_reset (b);
}

static clib_error_t *register_interface (vnet_main_t *vnm, cndp_device_t *cd)
{
#if USE_2110_ETHERNET_REGISTER_INTERFACE == 1
  /* VPP 22.02 changes how interfaces are registered */
  return ethernet_register_interface (vnm, cndp_device_class.index,
                                      cd->instance, cd->mac.ether_addr_octet,
                                      &cd->hw_if_index, NULL);
#else
  vnet_eth_interface_registration_t eir = {};

  eir.dev_class_index = cndp_device_class.index;
  eir.dev_instance = cd->instance;
  eir.address = cd->mac.ether_addr_octet,
  cd->hw_if_index = vnet_eth_register_interface (vnm, &eir);
  return NULL;
#endif
}

clib_error_t *cndp_create_dev (vlib_main_t *vm, u8 *ifname, u32 nb_qs,
                               u32 offset)
{
  vnet_main_t *vnm = vnet_get_main ();
  cndp_main_t *cmp = &cndp_main;
  vnet_device_main_t *vdm = &vnet_device_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cndp_lport_t *lport = NULL;
  cndp_device_t *cd;
  clib_error_t *error = NULL;
  int err = -1;

  if (tm->n_vlib_mains > 1 && (tm->n_vlib_mains - 1) != nb_qs)
    {
      return clib_error_return (0, "number of worker threads must be "
                                   "equal to number of rx queues");
    }

  if (tm->n_vlib_mains > 4 && nb_qs > 4)
    {
      return clib_error_return (0, "number of worker threads and queues must"
                                   " < 5 in worker thread mode");
    }

  if (cmp->total_devs == CNDP_MAX_DEVS)
    {
      return clib_error_return (0, "Max Number of devices already configured");
    }

  cd = (cndp_device_t *)calloc (1, sizeof (cndp_device_t));
  if (!cd)
    {
      return clib_error_return (0, "Error allocating a device");
    }
  memset (cd, 0, sizeof (cndp_device_t));

  cd->nb_qs = nb_qs;
  cd->offset = offset;
  cd->ifname = (char *)format (0, "%s", ifname);
  cd->instance = cmp->total_devs;
  cmp->devices[cmp->total_devs++] = cd;

  int tid = cne_id ();
  if (tid < 0)
    {
      char *name = (char *)format (0, "vpp_main_%d", vlib_get_thread_index ());
      cne_register (name);
    }

  cd->umem_addr = uword_to_pointer (vm->buffer_main->buffer_mem_start, void *);

  for (int i = 0; i < nb_qs; i++)
    {
      lport_cfg_t *p_config = NULL;
      int qid = offset + i;

      pool_get_zero (cd->lports, lport);

      cd->hw_if_index = (u32)~0;
      cd->pool = vlib_buffer_pool_get_default_for_numa (
          vm, cndp_get_numa ((char *)ifname));
      cndp_elog_info_X1 (cmp, "cd->pool %d", "i4", cd->pool);

      p_config = &lport->cfg;

      sprintf (p_config->pmd_name, "net_af_xdp");
      sprintf (p_config->ifname, "%s", ifname);
      sprintf (p_config->name, "%s:%d", ifname, qid);

      p_config->flags |= LPORT_USER_MANAGED_BUFFERS;
      p_config->flags |= LPORT_UMEM_UNALIGNED_BUFFERS;

      CNE_DEFAULT_SET (p_config->bufcnt, 0, DEFAULT_MBUF_COUNT);
      CNE_DEFAULT_SET (p_config->rx_nb_desc, 0,
                       XSK_RING_PROD__DEFAULT_NUM_DESCS);
      CNE_DEFAULT_SET (p_config->tx_nb_desc, 0,
                       XSK_RING_CONS__DEFAULT_NUM_DESCS);
      p_config->bufsz =
          sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (vm);

      p_config->buf_mgmt.buf_arg = (void *)cd;
      p_config->buf_mgmt.buf_alloc = cndp_buf_alloc;
      p_config->buf_mgmt.buf_free = cndp_buf_free;
      p_config->buf_mgmt.buf_set_len = NULL;
      p_config->buf_mgmt.buf_set_data_len = cndp_buf_set_data_len;
      p_config->buf_mgmt.buf_set_data = cndp_buf_set_data;
      p_config->buf_mgmt.buf_get_data_len = cndp_buf_get_data_len;
      p_config->buf_mgmt.buf_get_data = cndp_buf_get_data;
      p_config->buf_mgmt.buf_get_addr = cndp_buf_get_addr;
      p_config->buf_mgmt.buf_inc_ptr = cndp_buf_inc_ptr;
      p_config->buf_mgmt.buf_reset = cndp_buf_reset;
      p_config->buf_mgmt.buf_headroom = sizeof (vlib_buffer_t);
      p_config->buf_mgmt.frame_size = p_config->bufsz;
      p_config->buf_mgmt.pool_header_sz = 0;

      p_config->umem_addr =
          uword_to_pointer (vm->buffer_main->buffer_mem_start, void *);
      p_config->umem_size = vm->buffer_main->buffer_mem_size;
      p_config->addr = p_config->umem_addr;
      lport->qid = lport->cfg.qid = qid;

      lport->xi = xskdev_socket_create (&lport->cfg);
      if (lport->xi == NULL)
        {
          clib_error ("xskdev_socket_create() failed for %s", ifname);
          goto cleanup_dev;
        }

      cndp_elog_info_STR1 (cmp, "CNDP lport: %s created", lport->cfg.name);
    }

  lport = vec_elt_at_index (cd->lports, 0);
  err = netdev_get_mac_addr (lport->cfg.ifname, &cd->mac);
  if (err != 0)
    {
      error = clib_error_return (
          0, "pktdev_macaddr_get() failed with error %d", err);
      goto cleanup_xskdev;
    }

  error = register_interface (vnm, cd);
  if (error)
    {
      goto cleanup_xskdev;
    }

  cndp_elog_info (cmp, "Device added\n");
  error = vnet_hw_interface_set_flags (vnm, cd->hw_if_index,
                                       VNET_HW_INTERFACE_FLAG_LINK_UP);
  if (error)
    {
      goto cleanup_xskdev;
    }

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, cd->hw_if_index);

  cd->sw_if_index = sw->sw_if_index;

#if USE_2101_RX_QUEUES == 1
  /* VPP 21.06 changes how rx queues are processed */
  vnet_hw_interface_set_input_node (vnm, cd->hw_if_index,
                                    cndp_input_node.index);
#else
  vnet_hw_if_set_input_node (vnm, cd->hw_if_index, cndp_input_node.index);
#endif

  vnet_hw_interface_set_flags (vnm, cd->hw_if_index,
                               VNET_HW_INTERFACE_FLAG_LINK_UP);

  u32 thread_index = vdm->first_worker_thread_index;
  for (int i = 0; i < nb_qs; i++)
    {
      int qid = offset + i;
#if USE_2101_RX_QUEUES == 0
      u32 queue_index;
#endif

      if (tm->n_vlib_mains == 1)
        thread_index = ~0; /* any cpu */
#if USE_2101_RX_QUEUES == 1
      /* VPP 21.06 changes how rx queues are processed */
      vnet_hw_interface_assign_rx_thread (vnm, cd->hw_if_index, qid,
                                          thread_index++);
      vnet_hw_interface_set_rx_mode (vnm, cd->hw_if_index, qid,
                                     VNET_HW_IF_RX_MODE_POLLING);
#else
      queue_index = vnet_hw_if_register_rx_queue (vnm, cd->hw_if_index, qid,
                                                  thread_index++);
      vnet_hw_if_set_rx_queue_mode (vnm, queue_index,
                                    VNET_HW_IF_RX_MODE_POLLING);
#endif
      thread_index = (thread_index > vdm->last_worker_thread_index)
                         ? vdm->first_worker_thread_index
                         : thread_index;
    }

#if USE_2101_RX_QUEUES == 0
  /* VPP 21.06 changes how rx queues are processed */
  vnet_hw_if_update_runtime_data (vnm, cd->hw_if_index);
#endif

  /* buffer template */
  vlib_buffer_t *bt = &cd->buffer_template;

  /* Update buffer template */
  bt->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | VLIB_BUFFER_IS_TRACED;
  bt->ref_count = 1;
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = cd->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = (u32)~0;
  bt->buffer_pool_index = cd->pool;
  vnet_buffer (bt)->feature_arc_index = 0;
  bt->total_length_not_including_first_buffer = 0;
  bt->current_config_index = 0;

  return 0;

cleanup_xskdev:
  xskdev_socket_destroy (lport->xi);

cleanup_dev:
  pool_put (cd->lports, lport);
  if (cd->ifname)
    vec_free (cd->ifname);
  cmp->total_devs -= 1;
  cmp->devices[cmp->total_devs] = NULL;
  free (cd);

  return error;
}

static clib_error_t *cndp_init (vlib_main_t *vm)
{
  cndp_main_t *cmp = &cndp_main;
  cmp->vlib_main = vm;
  cmp->log_level = CNDP_LOG_LEVEL_INFO;
  cmp->total_devs = 0;

  cndp_elog_info (cmp, "CONFIGURING CNDP");

  vlib_cli_output (vm,
                   "CNDP sizeof (vlib_buffer_t) + "
                   "vlib_buffer_get_default_data_size (vm) %d\n",
                   sizeof (vlib_buffer_t) +
                       vlib_buffer_get_default_data_size (vm));

  /* Initialize CNDP */
  if (cne_init () < 0)
    return clib_error_return (0, "cne_init() failed");

  return 0;
}

VLIB_INIT_FUNCTION (cndp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "CNDP plugin for vpp",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
