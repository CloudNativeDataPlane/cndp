..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2025 Intel Corporation.

.. _xsk_buf_mgmt:

xskdev Buffer Management
==========================
The goal of the xskdev buffer management API is to make sure that external applications that want
to use the xskdev API with their own buffer manager can do so without having to use the predefined
pktmbuf.

This API is enabled through the use of a flag in the lport configuration structure (lport_cfg_t).

.. code-block:: C

    #define LPORT_USER_MANAGED_BUFFERS   (1 << 5) /**< Enable Buffer Manager outside of CNDP */

To enable buffer management outside of CNDP simple add the following flag to the lport configuration:

.. code-block:: C

    lport->flags |= LPORT_USER_MANAGED_BUFFERS

By default CNDP supports an aligned memory model for UMEM frames (aligned to 2K). If an unaligned
memory model is required, this can be enabled through an additional lport_cfg_t flag:

.. code-block:: C

    #define LPORT_UMEM_UNALIGNED_BUFFERS (1 << 6) /**< Enable unaligned frame UMEM support */

Under the hood of the xskdev API - this unaligned buffer flag enables a different calculation for
the buffer address and data offset.

A new set of callback functions were introduced to allow users to register external buffer management
functions that will be called back through the xskdev API. These include functions to allocate and
free buffers. As well as functions to set/get buffer pointers, lengths... Finally the option to provide
ones own RX/TX function is also available should one prefer to provide their own implementation.

.. code-block:: C

    typedef int (*buf_alloc_t)(xinfo_t *arg, mbuf_t **bufs, uint16_t nb_pkts);
    typedef void (*buf_free_t)(xinfo_t *arg, mbuf_t **bufs, uint16_t nb_pkts);
    typedef void (*buf_reset_t)(mbuf_t *buf, uint16_t buf_len, uint16_t headroom);
    typedef void (*buf_set_len_t)(mbuf_t *buf, uint16_t len);
    typedef void (*buf_set_data_len_t)(mbuf_t *buf, uint16_t len);
    typedef void (*buf_set_data_off_t)(mbuf_t *buf, uint16_t off);
    typedef void **(*buf_inc_ptr_t)(mbuf_t **buf);
    typedef uint16_t (*buf_get_data_len_t)(mbuf_t *buf);
    typedef uint16_t (*buf_get_data_off_t)(mbuf_t *buf);
    typedef uint64_t (*buf_get_data_ptr_t)(mbuf_t *buf);
    typedef uint64_t (*buf_get_base_ptr_t)(mbuf_t *buf);
    typedef uint16_t (*buf_rx_burst_t)(xinfo_t *arg, mbuf_t **bufs, uint16_t nb_pkts);
    typedef uint16_t (*buf_tx_burst_t)(xinfo_t *arg, mbuf_t **bufs, uint16_t nb_pkts);

    typedef struct lport_buf_mgmt {
        void *buf_arg;                           /**< Argument for the buffer mgmt routines */
        buf_alloc_t buf_alloc;                   /**< Allocate buffer routine */
        buf_free_t buf_free;                     /**< Free buffer routine */
        buf_reset_t buf_reset;                   /**< Buffer reset function */
        buf_set_len_t buf_set_len;               /**< Set total buffer length routine */
        buf_inc_ptr_t buf_inc_ptr;               /**< Increment the buffer pointer */
        buf_rx_burst_t buf_rx_burst;             /**< RX burst callback */
        buf_tx_burst_t buf_tx_burst;             /**< TX burst callback */
        buf_get_base_ptr_t buf_get_base_ptr;     /**< Get buffer base address routine */
        buf_set_data_len_t buf_set_data_len;     /**< Set buffer data length routine */
        buf_set_data_off_t buf_set_data_off;     /**< Set buffer data offset routine */
        buf_get_data_len_t buf_get_data_len;     /**< Get buffer data length routine */
        buf_get_data_off_t buf_get_data_off;     /**< Get buffer data offset routine */
        buf_get_data_ptr_t buf_get_data_ptr;     /**< Get buffer data pointer address routine */
        uint32_t frame_size;                     /**< Frame size in umem */
        uint32_t buf_header_sz;                  /**< Buffer headroom size */
        uint32_t pool_header_sz;                 /**< Pool header size for external buffer pool*/
        uint32_t reserved;                       /**< Reserved space for alignment */
    } lport_buf_mgmt_t;

These functions are set in the xskdev_info_t during the call to xskdev_socket_create()

.. note::
    For the case of CNDP managed buffers, new buffer management functions were implemented
    in xskdev.c with the \*_default suffix. If CNDP is managing the buffers, then these
    default functions are registered with the xskdev_info_t at setup time.
    It's critical for the default case that the bufsz in the lport configuration is set
    appropriately as it will dictate the UMEM framesize.

These functions are shown below:

.. code-block:: C

    if (c->flags & LPORT_USER_MANAGED_BUFFERS) {
        if (!c->buf_mgmt.buf_arg || !c->buf_mgmt.buf_alloc || !c->buf_mgmt.buf_free)
            CNE_ERR_GOTO(err, "Buffer management alloc/free/arg pointers are not set\n");

        if (!c->buf_mgmt.buf_set_data_off || !c->buf_mgmt.buf_set_data_len)
            CNE_ERR_GOTO(err, "Buffer management to set data len/offset are not set\n");

        if (!c->buf_mgmt.buf_get_data_off || !c->buf_mgmt.buf_get_data_len)
            CNE_ERR_GOTO(err, "Buffer management pointers to get data are not set\n");

        if (!c->buf_mgmt.buf_reset || !c->buf_mgmt.buf_inc_ptr)
            CNE_ERR_GOTO(err, "Buffer management pointers to reset/inc buffer are not set\n");

        if (!c->buf_mgmt.buf_get_base_ptr)
            CNE_ERR_GOTO(err, "Buffer management pointer to get buffer base address is not set\n");

        if (c->buf_mgmt.frame_size == 0)
            CNE_ERR_GOTO(err, "Buffer management invalid frame size\n");

        if (c->buf_mgmt.buf_header_sz == 0)
            CNE_ERR_GOTO(err, "Buffer management invalid headroom size\n");

        xskdev_buf_set_buf_mgmt_ops(&xi->buf_mgmt, &c->buf_mgmt);
    } else {
        xi->buf_mgmt.buf_arg = xi->pi = c->pi; /*Buffer pool*/
        xi->buf_mgmt.buf_alloc        = xskdev_buf_alloc_default;
        xi->buf_mgmt.buf_free         = xskdev_buf_free_default;
        xi->buf_mgmt.buf_set_len      = xskdev_buf_set_len_default;
        xi->buf_mgmt.buf_set_data_len = xskdev_buf_set_data_len_default;
        xi->buf_mgmt.buf_set_data_off = xskdev_buf_set_data_off_default;
        xi->buf_mgmt.buf_get_data_len = xskdev_buf_get_data_len_default;
        xi->buf_mgmt.buf_get_data_off = xskdev_buf_get_data_off_default;
        xi->buf_mgmt.buf_get_data_ptr = xskdev_buf_get_data_ptr_default;
        xi->buf_mgmt.buf_inc_ptr      = xskdev_buf_inc_ptr_default;
        xi->buf_mgmt.buf_get_base_ptr = xskdev_buf_get_base_ptr_default;
        xi->buf_mgmt.buf_reset        = xskdev_buf_reset_default;
        xi->buf_mgmt.frame_size       = c->bufsz;
        xi->buf_mgmt.pool_header_sz   = 0;
        xi->buf_mgmt.buf_header_sz    = sizeof(pktmbuf_t);
    }

.. note::
    It is assumed that if a user doesn't provide RX/TX function they wish to use the CNDP
    xskdev API functions.

.. code-block:: C

    if (!c->buf_mgmt.buf_rx_burst || !c->buf_mgmt.buf_tx_burst ) {
        /* If no external rx and tx functions were registered*/
        xi->buf_mgmt.buf_rx_burst = xskdev_rx_burst_default;
        xi->buf_mgmt.buf_tx_burst = xskdev_tx_burst_default;
    }

Some additional internal functions were added to the xskdev_info_t structure to allow for the
support of an unaligned memory model.

.. code-block:: C

    if (!(c->flags & LPORT_UMEM_UNALIGNED_BUFFERS)) {
        xi->__get_mbuf_addr_tx = __get_mbuf_addr_tx_aligned;
        xi->__pull_cq_addr = __pull_cq_addr_aligned;
        xi->__get_mbuf_rx =  __get_mbuf_rx_aligned;
    } else {
        xi->__get_mbuf_addr_tx = __get_mbuf_addr_tx_unaligned;
        xi->__pull_cq_addr =  __pull_cq_addr_unaligned;
        xi->__get_mbuf_rx =  __get_mbuf_rx_unaligned;
    }

A few examples of how the buffer management callbacks are invoked is shown below:

.. code-block:: C

    /**
    * Receive packets from the interface
    *
    * @param xi
    *   The void * type of xskdev_info_t structure
    * @param bufs
    *   The list or vector or pktmbufs structures to send on the interface.
    * @param nb_pkts
    *   The number of pktmbuf_t pointers in the list or vector bufs
    * @return
    *   The number of packet sent to the interface or 0 if RX is empty.
    */
    CNDP_API __cne_always_inline uint16_t
    xskdev_rx_burst(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts)
    {
        return xi->buf_mgmt.buf_rx_burst(xi, bufs, nb_pkts);
    }

    /**
    * Send buffers to be transmitted
    *
    * @param xi
    *   The void * type of xskdev_info_t structure
    * @param bufs
    *   The list or vector or pktmbufs structures to send on the interface.
    * @param nb_pkts
    *   The number of pktmbuf_t pointers in the list or vector bufs
    * @return
    *   The number of packet sent to the interface or 0 if RX is empty.
    */
    CNDP_API __cne_always_inline uint16_t
    xskdev_tx_burst(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts)
    {
        return xi->buf_mgmt.buf_tx_burst(xi, bufs, nb_pkts);
    }
