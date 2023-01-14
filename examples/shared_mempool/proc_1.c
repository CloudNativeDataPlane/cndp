#include "proc_1.h"

int main(void)
{

	//Set up the mempool configuration
	struct mempool_cfg *ci = calloc(1, sizeof(struct mempool_cfg));

	ci->objcnt = 2048;
	ci->objsz = 1024;
	ci->cache_sz = 64;

	//Set up the shared memory for the shared mempool
	char mmap_fname[32] = "/dev/hugepages/cndp_mempool";

	size_t mem_sz = HUGEPAGE_SZ;

	//TODO: Figure out how to map the memory region at the same
	// virtual address for each run


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
	void *mempool_addr = mmap(NULL, mem_sz, PROT_READ | 
	PROT_WRITE, MAP_SHARED | MAP_HUGETLB, mmap_fd, 0);
	if (mempool_addr == (mempool_t *)-1) {
		cne_printf("Failed to map the shared mempool\n");
		goto MMAP_FAIL;
	}

	//bzero(mempool_addr, HUGEPAGE_SZ);

	shared_mempool_cfg_t *spool;
	spool = (shared_mempool_cfg_t *)initialize_shared_mempool(mempool_addr,
		mem_sz, ci);

	mempool_cfg_t *mp = spool->mp_cfg;

	struct cne_mempool *cne_mp = spool->cne_mp;

	printf("spool: %p\n", spool);

	printf("semloc: %p\n", spool->sem);
	printf("mempool_cfgloc: %p\n", mp);
	printf("cne_mempoolloc: %p\n", cne_mp);
	printf("cne_ring: %p\n", spool->cne_ring);
	printf("mempool_cacheloc: %p\n", spool->mem_cache);
	printf("mempool_statsloc: %p\n\n", spool->mem_stats);
	
	printf("objcnt: %u\n", mp->objcnt);
	printf("objsz: %u\n", mp->objsz);
	printf("cache_sz: %u\n", mp->cache_sz);
	printf("addr: %p\n\n", mp->addr);
	
	printf("objring: %p\n", cne_mp->objring);
	printf("objmem: %p\n", cne_mp->objmem);


	int x = -1;
	sem_getvalue(spool->sem, &x);
	printf("Semaphore value: %d\n", x);

	//teardown_shared_mempool(spool);

MMAP_FAIL:
FTRUNCATE_FAIL:
	close(mmap_fd);

OPEN_FAIL:

	return 0;
}
