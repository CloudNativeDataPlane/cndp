..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2022 Intel Corporation.

.. _Crypto_Prog_Guide:

Crypto Libraries
================

CNDP does not implement or wrap any crypto API. The developer is free to choose a crypto
implementation which satisfies their application's requirements. OpenSSL* is an implementation that
has support for both Intel(R) Multi-Buffer Crypto for OpenSSL* and Intel(R) QuickAssist Technology
Engine for OpenSSL* (Intel(R) QAT Engine for OpenSSL*). The Multi-Buffer API is preferred when a
Intel(R) QuickAssist Accelerator is not available, or in cases where offloading to an accelerator
would yield less throughput, such as those processing predominantly small packets. The OpenSSL
toolkit offers the developer the flexibility to choose at runtime which Engine to use, while still
programming to the same high-level API.

OpenSSL*
--------

There are many resources available to describe how to develop applications using OpenSSL. Learn more
at the `OpenSSL website <https://www.openssl.org/>`_ and the `QAT_Engine
<https://github.com/intel/QAT_Engine>`_ repo on GitHub*.

Intel(R) Multi-Buffer Crypto for IPsec Library
----------------------------------------------

For developers who need fast *software* crypto acceleration, the `intel-ipsec-mb
<https://github.com/intel/intel-ipsec-mb>`_ library is efficient and easy to use. To develop an
application on Ubuntu*, the libipsec-mb-dev package can be installed.

.. code-block:: Console

   sudo apt-get install -y libipsec-mb-dev

To build an executable, add a dependency to the meson build file.

.. code-block:: Console

   libipsecmb = cc.find_library('IPSec_MB')
   executable(..., dependencies: [libipsecmb])

To use the library for, e.g. IPsec ESP Tunnel mode encryption with AES128-GCM, submit a job.

.. code-block:: C

   #include <intel-ipsec-mb.h>


   const uint8_t secret[] = { 0, 1, 2, ...};
   struct gcm_key_data key;
   JOB_AES_HMAC *job;
   MB_MGR mb_mgr;

   init_mb_mgr_avx(&mb_mgr);

   IMB_AES128_GCM_PRE(&mb_mgr, secret, &key);

   job                        = IMB_GET_NEXT_JOB(&mb_mgr);
   job->cipher_mode           = GCM;
   job->hash_alg              = AES_GMAC;
   job->chain_order           = CIPHER_HASH;
   job->aes_enc_key_expanded  = &key;
   job->iv                    = /* Salt + IV */
   job->u.GCM.aad             = /* SPI + [E]SN */
   job->auth_tag_output       = /* ICV */
   job->cipher_direction      = ENCRYPT;
   ...

   job = IMB_SUBMIT_JOB(&mb_mgr);
   while (job) {
      if (job->status != STS_COMPLETED)
            ... job failed ...
      job = IMB_GET_COMPLETED_JOB(&mb_mgr);
   }

   while ((job = IMB_FLUSH_JOB(&mb_mgr)))
      if (job->status != STS_COMPLETED)
         ... job failed ...

The CNDP pktmbuf can be manipulated to insert the outer IPv4 header, ESP header, IV, and append the
ESP trailer and ICV.

.. code-block:: C

   neweth = (struct ether_header *)pktmbuf_prepend(m, 20 + 8 + 8 /* IP hdr, ESP hdr, IV */);

   pad = pktmbuf_append(m, pad_len + 2 + 16 /* padding, pad length, next header, ICV */);
   ... populate padding, pad length, next header ...

   ... encrypt/authenticate payload ...

   /* populate outer ip header */
   oip                  = (struct cne_ipv4_hdr *)(neweth + 1);
   oip->version_ihl     = CNE_IPV4_VHL_DEF;
   oip->type_of_service = 0;
   /* length is the length of the old packet, plus new header, plus ESP trailer and ICV */
   oip->total_length    = htobe16(sizeof(*oip) + pay_len + pad_len + 2 + 16);
   oip->next_proto_id   = 50; /* ESP */
   ... remaining ip header fields
   oip->hdr_checksum    = cne_ipv4_chksum(oip);

   ... populate esp header and IV ...

The Security Association Database (SAD) and Security Policy Database (SPD) can be implemented using
the CNDP hash or ACL libraries. Finally, routing decisions can be made using the CNDP RIB/FIB
libraries.

Legal Acknowledgements
----------------------

\* Intel is a trademark of Intel Corporation in the U.S. or its subsidiaries. Other names and
brands may be claimed as the property of others.
