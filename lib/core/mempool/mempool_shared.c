#include "mempool_shared.h"


shared_mempool_cfg_t *smempool;

//Allocate the shared mempool
shared_mempool_cfg_t *
initialize_shared_mempool(struct mempool_cfg *ci)
{

	char mmap_fname[32] = "/dev/hugepages/cndp_mempool";

	size_t mem_sz = HUGEPAGE_SZ;
	
	mempool_t *mempool_addr = NULL;
	mempool_cfg_t *mp = NULL;

	struct cne_mempool *cne_mp = NULL;

	sem_t *sem = NULL;

	//Validate mempool_cfg
	if(ci == NULL) {
		cne_printf("Invalid mempool configurationg given\n");
		goto BAD_CI;
	}

	//Determine whether the shared mempool will be large enough
	if (mem_sz < (ci->objcnt * ci->objsz + sizeof(mempool_cfg_t))) {
		cne_printf("Mempool Size is too large\n");
		goto SMALL_MEMPOOL_SIZE;
    	}

	//Allocate the mempool configuration struct
	mp = (mempool_cfg_t *)calloc(1, sizeof(mempool_cfg_t));
	if (mp == NULL) {
		cne_printf("Failed to allocate mempool conf struct\n");
		goto ALLOC_MEMPOOL_CFG;
	}

	//Allocate the struct for the shared mempool
	smempool = calloc(1, sizeof(shared_mempool_cfg_t));
	if (smempool == NULL) {
		cne_printf("Failed to allocate shared mempool struct\n");
		goto ALLOC_SMEMPOOL;
	}

	//Allocate the cne_mempool structure
	cne_mp = mempool_create_empty(ci);
	if (cne_mp == NULL) {
		cne_printf("Failed to allocate cne mempool struct\n");
		goto ALLOC_CNE_MP;
	}

	//Call private mempool initializer function
	if (ci->mp_init)
		ci->mp_init(mp, ci->mp_init_arg);

	mp->objcnt  = ci->objcnt;
	mp->objsz   = ci->objsz;
	mp->cache_sz = ci->cache_sz;

	/*Attempt to open a hugepage that is shared across multiple cndp 
	processes*/
	int mmap_fd = open(mmap_fname, O_RDWR, S_IRWXU);
	if (mmap_fd == -1) {

		//The mempool does not exist so we need to create it ourselves
		mmap_fd = open(mmap_fname, O_RDWR | O_CREAT, S_IRWXU);
		if (mmap_fd == -1) {
			cne_printf("Failed to open the shared mempools\n");
			goto OPEN_FAIL;
		}
		
		//Resize to a huge page
		if (ftruncate(mmap_fd, mem_sz) == -1) {
			cne_printf("Failed to resize the shared mempool\n");
			goto FTRUNCATE_FAIL;
		}
	}
	
	//Map the huge page into our process address space
	mempool_addr = (mempool_t *)mmap(NULL, mem_sz, PROT_READ | 
	PROT_WRITE, MAP_SHARED | MAP_HUGETLB, mmap_fd, 0);
	if (mempool_addr == (mempool_t *)-1) {
		cne_printf("Failed to map the shared mempool\n");
		goto MMAP_FAIL;
	}
	
	//Save the address of the mempool in the mempool_cfg
	mp->addr = mempool_addr;

	//Initialize Cache
	cne_mp->cache[0].size        = mp->cache_sz;
	cne_mp->cache[0].flushthresh = CALC_CACHE_FLUSHTHRESH(mp->cache_sz);
	cne_mp->cache[0].len         = 0;

	//Populate the mempool
	if (mempool_populate(cne_mp, mempool_addr, mp->objcnt * mp->objsz) < 0)
		goto MP_POPULATE_FAIL;
	
	//Store the mempool cfg in the shared_mempool_cfg
	smempool->mp_cfg = mp;

	//Store the mempool ring in the shared_mempool_cfg
	smempool->cne_mp = cne_mp;

	//Attempt to get the global semaphore if it already exists
	sem = sem_open("cndp_smem_sem", 0, 0644, 0);
	if (sem == SEM_FAILED) {
	
		//Semaphore doesn't exist, try to create it
		sem = sem_open("cndp_smem_sem", O_CREAT, 0644, 0);
		if (sem == SEM_FAILED) {
			cne_printf("Failed to open the shared memory semaphore\n");
			goto SEMAPHORE_FAIL;
		}
		
		//Semaphore was created, so initialize it to a value of 1
		sem_post(sem);

	}

	//Store the semaphore in the cfg
	smempool->sem = sem;

	//TODO: Figure out the logistics of whether we clear out the memory
	// as the memory may have been initialized by another process

	//We no longer need the hugepage file
	close(mmap_fd);

	return smempool;

SEMAPHORE_FAIL:
MP_POPULATE_FAIL:
	munmap(mempool_addr, mem_sz);
	mempool_addr = NULL;

MMAP_FAIL:
FTRUNCATE_FAIL:
	close(mmap_fd);
	mmap_fd = 0;

OPEN_FAIL:
ALLOC_CNE_MP:
	free(smempool);
	smempool = NULL;

ALLOC_SMEMPOOL:
	free(mp);
	mp = NULL;

ALLOC_MEMPOOL_CFG:
SMALL_MEMPOOL_SIZE:
BAD_CI:

	return smempool;
}

void teardown_shared_mempool(shared_mempool_cfg_t *mp)
{
	//Validate input
	if (!mp) {goto BAD_MP;}

	//First, close the semaphore
	sem_close(mp->sem);
	mp->sem = NULL;

	//Clear out the mempool cfg
	free(mp->mp_cfg);

	//Clear out the mempool
	mempool_destroy(mp->cne_mp);
	mp->cne_mp = NULL;

BAD_MP:

}

