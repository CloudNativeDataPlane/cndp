#include <fcntl.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <semaphore.h>

#include "mempool.h"                // for mempool_t
#include "mempool_private.h"        // for cne_mempool, mempool_cache, mempo...
#include "mempool_ring.h"           // for mempool_ring_dequeue, mempool_rin...

#ifndef _CNE_MEMPOOL_SHARED_H_
#define _CNE_MEMPOOL_SHARED_H_

#define HUGEPAGE_SZ 1073741824

typedef struct shared_mempool
{
	//The semaphore for managing the smempool
	sem_t *sem;

	//The mempool that is shared across the cndp instances
	mempool_cfg_t *mp_cfg;
	
	//The mempool ring struct
	struct cne_mempool * cne_mp;

} shared_mempool_cfg_t;

shared_mempool_cfg_t *initialize_shared_mempool(struct mempool_cfg *ci);

void teardown_shared_mempool(shared_mempool_cfg_t *mp);

int populate_shared_mempool(mempool_t *_mp);



#endif /* _CNE_MEMPOOL_SHARED_H_ */
