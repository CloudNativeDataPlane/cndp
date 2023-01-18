#include <fcntl.h>

#include <semaphore.h>

#include "mempool.h"                // for mempool_t
#include "mempool_private.h"        // for cne_mempool, mempool_cache, mempo...
#include "mempool_ring.h"           // for mempool_ring_dequeue, mempool_rin...

#include "cne_ring.h"
#include "cne_ring_generic.h"        // for __cne_ring_do_dequeue, __cne_ring...

#ifndef _CNE_MEMPOOL_SHARED_H_
#define _CNE_MEMPOOL_SHARED_H_

#define HUGEPAGE_SZ 1073741824

typedef struct shared_mempool {

    // The semaphore for managing the smempool
    sem_t *sem;

    // The mempool configuration
    mempool_cfg_t *mp_cfg;

    // The mempool ring struct
    struct cne_mempool *cne_mp;

    struct cne_ring *cne_ring;

    // The mempool cache struct
    struct mempool_cache *mem_cache;

    struct mempool_stats *mem_stats;

} shared_mempool_cfg_t;

// Layout of a shareable mempool

// OFFSET    | struct type
// 0x0000    | struct shared_mempool
// 0x0030    | struct mempool_cfg
// 0x0068    | struct cne_mempool
// 0x00A8    | struct cne_ring
// 0x0228    | struct mempool_cache
// 0x1A68    | struct mempool_stats
// 0x1AA8    | object memory - the actual mempool

/**

 * Creates a shareable mempool at the address of vaddr with the size of sm_sz
 * minus the extra space required to set up the necessary pointers

 * @param vaddr
 *   The address of the mempool
 * @param m_sz
 *   The size of the mempool
 * @return shared_mempool_cfg_t
 *   The resulting shared mempool

**/
shared_mempool_cfg_t *initialize_shared_mempool(void *vaddr, int sm_sz, struct mempool_cfg *ci);

void teardown_shared_mempool(shared_mempool_cfg_t *mp, size_t size);

int populate_shared_mempool(mempool_t *_mp);

#endif /* _CNE_MEMPOOL_SHARED_H_ */
