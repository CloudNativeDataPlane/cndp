#include "mempool_shared.h"

/**

 * Creates a shareable mempool at the address of vaddr with the size of sm_sz
 * minus the extra space required to set up the necessary pointers

 * @param vaddr
 *   The address of the mempool
 * @param m_sz
 *   The size of the mempool
 * @return shared_mempool_cfg_t
 *   The resulting shared mempool

 * @TODO Modify so that we don't need to use semaphores for synchro

**/
shared_mempool_cfg_t *
initialize_shared_mempool(void *vaddr, int sm_sz, struct mempool_cfg *ci)
{

    size_t mem_sz = sm_sz;

    // The shared mempool
    shared_mempool_cfg_t *smempool = vaddr;

    // Validate the inputs
    if (vaddr == NULL) {
        smempool = NULL;
        goto BAD_VADDR;
    }

    // The mempool configuration
    mempool_cfg_t *mp_cfg = (void *)((long)vaddr + sizeof(shared_mempool_cfg_t));

    // The actual mempool
    struct cne_mempool *cne_mp = (void *)((long)mp_cfg + sizeof(mempool_cfg_t));

    // The ring of mempool objects
    struct cne_ring *cne_ring = (void *)((long)cne_mp + sizeof(struct cne_mempool));
    cne_mp->objring           = cne_ring;

    // The cache for the mempool
    struct mempool_cache *mem_cache = (void *)((long)cne_ring + sizeof(struct cne_ring));

    // The stats for the mempool
    struct mempool_stats *mem_stats = (void *)((long)mem_cache + sizeof(struct mempool_cache));

    // The mempool address
    mempool_t *mempool_addr = (void *)((long)mem_stats + sizeof(struct mempool_stats));

    // Store the variables in the sharable mempool
    smempool->mp_cfg    = mp_cfg;
    smempool->cne_mp    = cne_mp;
    smempool->cne_ring  = cne_ring;
    smempool->mem_cache = mem_cache;
    smempool->mem_stats = mem_stats;

    // Attempt to get the global semaphore if it already exists
    sem_t *sem = sem_open("cndp_smem_sem", 0, 0644, 0);
    if (sem == SEM_FAILED) {

        // Semaphore doesn't exist, try to create it
        sem = sem_open("cndp_smem_sem", O_CREAT, 0644, 0);
        if (sem == SEM_FAILED) {
            cne_printf("Failed to open the shared memory semaphore\n");
            goto ERR;
        }

    }

    // The semaphore already exists so the memory region is already set up
    // or it is about to be set up
    else {
        // Allow the other process to fully set up the mempool before
        // moving forward
        smempool->sem = sem;
        sem_wait(sem);
        sem_post(sem);
        goto SEM_EXISTS;
    }

    // Store the semaphore
    smempool->sem = sem;

    // Set up the sharable mempool by setting the necessary pointers and ring structures

    // Validate mempool_cfg
    if (ci == NULL) {
        cne_printf("Invalid mempool configurationg given\n");
        goto ERR;
    }

    // Copy the mempool cfg into the sharable mempool
    memcpy(mp_cfg, ci, sizeof(struct mempool_cfg));

    // Determine whether the shared mempool will be large enough
    if (mem_sz < (ci->objcnt * ci->objsz + sizeof(mempool_cfg_t))) {
        cne_printf("Mempool Size is too large\n");
        goto ERR;
    }

    // Allocate the cne_mempool structure
    cne_mp = mempool_create_empty(ci, cne_mp, mem_cache, mem_stats);
    if (cne_mp == NULL) {
        cne_printf("Failed to allocate cne mempool struct\n");
        goto ERR;
    }

    // Call private mempool initializer function
    if (ci->mp_init)
        ci->mp_init(mp_cfg, ci->mp_init_arg);

    mp_cfg->objcnt   = ci->objcnt;
    mp_cfg->objsz    = ci->objsz;
    mp_cfg->cache_sz = ci->cache_sz;

    // Save the address of the mempool in the mempool_cfg
    mp_cfg->addr = mempool_addr;

    // Initialize Cache
    cne_mp->cache[0].size        = mp_cfg->cache_sz;
    cne_mp->cache[0].flushthresh = CALC_CACHE_FLUSHTHRESH(mp_cfg->cache_sz);
    cne_mp->cache[0].len         = 0;

    // Populate the mempool
    if (mempool_populate(cne_mp, mempool_addr, mp_cfg->objcnt * mp_cfg->objsz) < 0)
        goto ERR;

    // TODO: Figure out the logistics of whether we clear out the memory
    // as the memory may have been initialized by another process

    // Allow other processes to use the region
    sem_post(sem);

SEM_EXISTS:

    return smempool;

ERR:

    smempool = NULL;

BAD_VADDR:
    return smempool;
}

void
teardown_shared_mempool(shared_mempool_cfg_t *mp, size_t size)
{
    // Validate input
    if (!mp) {
        goto BAD_MP;
    }

    // First, close the semaphore
    sem_close(mp->sem);
    mp->sem = NULL;

    // Because we mmap'd the memory, we can just bzero the whole thing
    bzero(mp, size);

BAD_MP:
}
