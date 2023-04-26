..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2023 Intel Corporation.

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

    typedef int (*buf_alloc_t)(void *arg, void **bufs, uint16_t nb_pkts);
    typedef void (*buf_free_t)(void **bufs, uint16_t nb_pkts);
    typedef void (*buf_set_len_t)(void *buf, int len);
    typedef void (*buf_set_data_len_t)(void *buf, int len);
    typedef void (*buf_set_data_t)(void *buf, uint64_t off);
    typedef void **(*buf_inc_ptr_t)(void **buf);
    typedef uint16_t (*buf_get_len_t)(void *buf);
    typedef uint16_t (*buf_get_data_len_t)(void *buf);
    typedef uint64_t (*buf_get_data_t)(void *buf);
    typedef uint64_t (*buf_get_addr_t)(void *buf);
    typedef uint16_t (*buf_rx_burst_t)(void *arg, void **bufs, uint16_t nb_pkts);
    typedef uint16_t (*buf_tx_burst_t)(void *arg, void **bufs, uint16_t nb_pkts);

    typedef struct lport_buf_mgmt {
        buf_alloc_t buf_alloc;                   /**< Allocate buffer routine */
        buf_free_t buf_free;                     /**< Free buffer routine */
        buf_set_len_t buf_set_len;               /**< Set buffer length routine */
        buf_set_data_len_t buf_set_data_len;     /**< Set buffer data length routine */
        buf_set_data_t buf_set_data;             /**< Set buffer data pointer routine*/
        buf_get_len_t buf_get_len;               /**< Get buffer length routine */
        buf_get_data_len_t buf_get_data_len;     /**< Get buffer data length routine */
        buf_get_data_t buf_get_data;             /**< Get buffer data pointer routine */
        buf_get_addr_t buf_get_addr;             /**< Get buffer base address routine */
        buf_inc_ptr_t buf_inc_ptr;               /**< Increment the buffer pointer */
        uint32_t frame_size;                     /**< Frame size in umem */
        size_t buf_headroom;                     /**< Buffer headroom size */
        size_t pool_header_sz;                   /**< Pool header size for external buffer pool*/
        void    *buf_arg;                        /**< Argument for the buffer alloc/free routines */
        buf_rx_burst_t buf_rx_burst;             /**< RX burst callback */
        buf_tx_burst_t buf_tx_burst;             /**< TX burst callback */
        bool unaligned_buff;                     /**< Unaligned buffer support */
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
        if (!c->buf_mgmt.buf_arg || !c->buf_mgmt.buf_alloc || !c->buf_mgmt.buf_free ||
            !c->buf_mgmt.buf_set_len || !c->buf_mgmt.buf_set_data || !c->buf_mgmt.buf_get_len ||
            !c->buf_mgmt.buf_get_data || c->buf_mgmt.buf_headroom == 0 || !c->buf_mgmt.buf_get_addr)
            CNE_ERR_GOTO(err, "Buffer alloc/free pointers are not set\n");

        xskdev_buf_set_buf_mgmt_ops(&xi->buf_mgmt, &c->buf_mgmt);
    } else {
        xi->buf_mgmt.buf_arg = xi->pi = c->pi; /*Buffer pool*/
        xi->buf_mgmt.buf_alloc        = xskdev_buf_alloc_default;
        xi->buf_mgmt.buf_free         = xskdev_buf_free_default;
        xi->buf_mgmt.buf_set_len      = xskdev_buf_set_len_default;
        xi->buf_mgmt.buf_set_data_len = xskdev_buf_set_data_len_default;
        xi->buf_mgmt.buf_set_data     = xskdev_buf_set_data_default;
        xi->buf_mgmt.buf_get_data_len = xskdev_buf_get_data_len_default;
        xi->buf_mgmt.buf_get_len      = xskdev_buf_get_len_default;
        xi->buf_mgmt.buf_get_data     = xskdev_buf_get_data_default;
        xi->buf_mgmt.buf_inc_ptr      = xskdev_buf_inc_ptr_default;
        xi->buf_mgmt.buf_headroom     = sizeof(pktmbuf_t);
        xi->buf_mgmt.buf_get_addr     = xskdev_buf_get_addr_default;
        xi->buf_mgmt.frame_size       = c->bufsz;
        xi->buf_mgmt.pool_header_sz   = 0;
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
        xi->buf_mgmt.unaligned_buff = true;
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


