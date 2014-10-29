/*
 * zbud.c
 *
 * Copyright (C) 2013, Seth Jennings, IBM
 *
 * Concepts based on zcache internal zbud allocator by Dan Magenheimer.
 *
 * zbud is an special purpose allocator for storing compressed pages.  Contrary
 * to what its name may suggest, zbud is not a buddy allocator, but rather an
 * allocator that "buddies" two compressed pages together in a single memory
 * page.
 *
 * While this design limits storage density, it has simple and deterministic
 * reclaim properties that make it preferable to a higher density approach when
 * reclaim will be used.
 *
 * zbud works by storing compressed pages, or "zpages", together in pairs in a
 * single memory page called a "zbud page".  The first buddy is "left
 * justified" at the beginning of the zbud page, and the last buddy is "right
 * justified" at the end of the zbud page.  The benefit is that if either
 * buddy is freed, the freed buddy space, coalesced with whatever slack space
 * that existed between the buddies, results in the largest possible free region
 * within the zbud page.
 *
 * zbud also provides an attractive lower bound on density. The ratio of zpages
 * to zbud pages can not be less than 1.  This ensures that zbud can never "do
 * harm" by using more pages to store zpages than the uncompressed zpages would
 * have used on their own.
 *
 * zbud pages are divided into "chunks".  The size of the chunks is fixed at
 * compile time and determined by NCHUNKS_ORDER below.  Dividing zbud pages
 * into chunks allows organizing unbuddied zbud pages into a manageable number
 * of unbuddied lists according to the number of free chunks available in the
 * zbud page.
 *
 * The zbud API differs from that of conventional allocators in that the
 * allocation function, zbud_alloc(), returns an opaque handle to the user,
 * not a dereferenceable pointer.  The user must map the handle using
 * zbud_map() in order to get a usable pointer by which to access the
 * allocation data and unmap the handle with zbud_unmap() when operations
 * on the allocation data are complete.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/zbud.h>
#include <linux/zpool.h>

/*****************
 * Structures
*****************/
/*
 * NCHUNKS_ORDER determines the internal allocation granularity, effectively
 * adjusting internal fragmentation.  It also determines the number of
 * freelists maintained in each pool. NCHUNKS_ORDER of 6 means that the
 * allocation granularity will be in chunks of size PAGE_SIZE/64.
 * NCHUNKS will be calculated to 64 which shows the max number of free
 * chunks in zbud page, also there will be 64 freelists per pool.
 */
#define NCHUNKS_ORDER	6

#define CHUNK_SHIFT	(PAGE_SHIFT - NCHUNKS_ORDER)
#define CHUNK_SIZE	(1 << CHUNK_SHIFT)
#define NCHUNKS		(PAGE_SIZE >> CHUNK_SHIFT)

/**
 * struct zbud_pool - stores metadata for each zbud pool
 * @lock:	protects all pool fields and first|last_chunk fields of any
 *		zbud page in the pool
 * @unbuddied:	array of lists tracking zbud pages that only contain one buddy;
 *		the lists each zbud page is added to depends on the size of
 *		its free region.
 * @lru:	list tracking the zbud pages in LRU order by most recently
 *		added buddy.
 * @pages_nr:	number of zbud pages in the pool.
 * @ops:	pointer to a structure of user defined operations specified at
 *		pool creation time.
 *
 * This structure is allocated at pool creation time and maintains metadata
 * pertaining to a particular zbud pool.
 */
struct zbud_pool {
	spinlock_t lock;
	struct list_head unbuddied[NCHUNKS];
	struct list_head lru;
	u64 pages_nr;
	struct zbud_ops *ops;
};

/*****************
 * zpool
 ****************/

#ifdef CONFIG_ZPOOL

static int zbud_zpool_evict(struct zbud_pool *pool, unsigned long handle)
{
	return zpool_evict(pool, handle);
}

static struct zbud_ops zbud_zpool_ops = {
	.evict =	zbud_zpool_evict
};

static void *zbud_zpool_create(gfp_t gfp, struct zpool_ops *zpool_ops)
{
	return zbud_create_pool(gfp, &zbud_zpool_ops);
}

static void zbud_zpool_destroy(void *pool)
{
	zbud_destroy_pool(pool);
}

static int zbud_zpool_malloc(void *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	return zbud_alloc(pool, size, gfp, handle);
}

static void zbud_zpool_free(void *pool, unsigned long handle)
{
	zbud_free(pool, handle);
}

static int zbud_zpool_shrink(void *pool, unsigned int pages,
			unsigned int *reclaimed)
{
	unsigned int total = 0;
	int ret = -EINVAL;

	while (total < pages) {
		ret = zbud_reclaim_page(pool, 8);
		if (ret < 0)
			break;
		total++;
	}

	if (reclaimed)
		*reclaimed = total;

	return ret;
}

static void *zbud_zpool_map(void *pool, unsigned long handle,
			enum zpool_mapmode mm)
{
	return zbud_map(pool, handle);
}

static void zbud_zpool_unmap(void *pool, unsigned long handle)
{
	zbud_unmap(pool, handle);
}

static u64 zbud_zpool_total_size(void *pool)
{
	return zbud_get_pool_size(pool) * PAGE_SIZE;
}

static struct zpool_driver zbud_zpool_driver = {
	.type =		"zbud",
	.owner =	THIS_MODULE,
	.create =	zbud_zpool_create,
	.destroy =	zbud_zpool_destroy,
	.malloc =	zbud_zpool_malloc,
	.free =		zbud_zpool_free,
	.shrink =	zbud_zpool_shrink,
	.map =		zbud_zpool_map,
	.unmap =	zbud_zpool_unmap,
	.total_size =	zbud_zpool_total_size,
};

MODULE_ALIAS("zpool-zbud");
#endif /* CONFIG_ZPOOL */

/*****************
 * Helpers
*****************/
/* Just to make the code easier to read */
enum buddy {
	FIRST,
	LAST
};

/* Converts an allocation size in bytes to size in zbud chunks */
static int size_to_chunks(size_t size)
{
	return (size + CHUNK_SIZE - 1) >> CHUNK_SHIFT;
}

static void set_num_chunks(struct page *page, enum buddy bud, size_t chunks)
{
	page->private = (page->private & (0xffff << (16 * !bud))) |
				((chunks & 0xffff) << (16 * bud));
}

static size_t get_num_chunks(struct page *page, enum buddy bud)
{
	return (page->private >> (16 * bud)) & 0xffff;
}

#define for_each_unbuddied_list(_iter, _begin) \
	for ((_iter) = (_begin); (_iter) < NCHUNKS; (_iter)++)

/* Initializes a newly allocated zbud page */
static void init_zbud_page(struct page *page)
{
	set_num_chunks(page, FIRST, 0);
	set_num_chunks(page, LAST, 0);
	INIT_LIST_HEAD((struct list_head *) &page->index);
	INIT_LIST_HEAD(&page->lru);
	ClearPageReclaim(page);
}

/* Resets the struct page fields and frees the page */
static void free_zbud_page(struct page *page)
{
	init_page_count(page);
	page_mapcount_reset(page);
	__free_page(page);
}

static int is_last_chunk(unsigned long handle)
{
	return (handle & LAST) == LAST;
}

/*
 * Encodes the handle of a particular buddy within a zbud page
 * Pool lock should be held as this function accesses first|last_chunks
 */
static unsigned long encode_handle(struct page *page, enum buddy bud)
{
	return (unsigned long) page | bud;
}

/* Returns struct page of the zbud page where a given handle is stored */
static struct page *handle_to_zbud_page(unsigned long handle)
{
	return (struct page *) (handle & ~LAST);
}

/* Returns the number of free chunks in a zbud page */
static int num_free_chunks(struct page *page)
{
	/*
	 * Rather than branch for different situations, just use the fact that
	 * free buddies have a length of zero to simplify everything.
	 */
	return NCHUNKS - get_num_chunks(page, FIRST)
				- get_num_chunks(page, LAST);
}

/*****************
 * API Functions
*****************/
/**
 * zbud_create_pool() - create a new zbud pool
 * @gfp:	gfp flags when allocating the zbud pool structure
 * @ops:	user-defined operations for the zbud pool
 *
 * Return: pointer to the new zbud pool or NULL if the metadata allocation
 * failed.
 */
struct zbud_pool *zbud_create_pool(gfp_t gfp, struct zbud_ops *ops)
{
	struct zbud_pool *pool;
	int i;

	pool = kmalloc(sizeof(struct zbud_pool), gfp);
	if (!pool)
		return NULL;
	spin_lock_init(&pool->lock);
	for_each_unbuddied_list(i, 0)
		INIT_LIST_HEAD(&pool->unbuddied[i]);
	INIT_LIST_HEAD(&pool->lru);
	pool->pages_nr = 0;
	pool->ops = ops;
	return pool;
}

/**
 * zbud_destroy_pool() - destroys an existing zbud pool
 * @pool:	the zbud pool to be destroyed
 *
 * The pool should be emptied before this function is called.
 */
void zbud_destroy_pool(struct zbud_pool *pool)
{
	kfree(pool);
}

/**
 * zbud_alloc() - allocates a region of a given size
 * @pool:	zbud pool from which to allocate
 * @size:	size in bytes of the desired allocation
 * @gfp:	gfp flags used if the pool needs to grow
 * @handle:	handle of the new allocation
 *
 * This function will attempt to find a free region in the pool large enough to
 * satisfy the allocation request.  A search of the unbuddied lists is
 * performed first. If no suitable free region is found, then a new page is
 * allocated and added to the pool to satisfy the request.
 *
 * gfp should not set __GFP_HIGHMEM as highmem pages cannot be used
 * as zbud pool pages.
 *
 * Return: 0 if success and handle is set, otherwise -EINVAL if the size or
 * gfp arguments are invalid or -ENOMEM if the pool was unable to allocate
 * a new page.
 */
int zbud_alloc(struct zbud_pool *pool, size_t size, gfp_t gfp,
			unsigned long *handle)
{
	int chunks, i, freechunks;
	enum buddy bud;
	struct page *page;

	if (!size || (gfp & __GFP_HIGHMEM))
		return -EINVAL;
	if (size > PAGE_SIZE - CHUNK_SIZE)
		return -ENOSPC;
	chunks = size_to_chunks(size);
	spin_lock(&pool->lock);

	/* First, try to find an unbuddied zbud page. */
	for_each_unbuddied_list(i, chunks) {
		if (!list_empty(&pool->unbuddied[i])) {
			page = list_entry((unsigned long *)
				pool->unbuddied[i].next, struct page, index);
			list_del((struct list_head *) &page->index);
			goto found;
		}
	}

	/* Couldn't find unbuddied zbud page, create new one */
	spin_unlock(&pool->lock);
	page = alloc_page(gfp);
	if (!page)
		return -ENOMEM;
	spin_lock(&pool->lock);
	pool->pages_nr++;
	init_zbud_page(page);

found:
	if (get_num_chunks(page, FIRST) == 0)
		bud = FIRST;
	else
		bud = LAST;

	set_num_chunks(page, bud, chunks);

	if (get_num_chunks(page, FIRST) == 0 ||
		get_num_chunks(page, LAST) == 0) {
		/* Add to unbuddied list */
		freechunks = num_free_chunks(page);
		list_add((struct list_head *) &page->index,
				&pool->unbuddied[freechunks]);
	}

	/* Add/move zbud page to beginning of LRU */
	if (!list_empty(&page->lru))
		list_del(&page->lru);
	list_add(&page->lru, &pool->lru);

	*handle = encode_handle(page, bud);
	spin_unlock(&pool->lock);

	return 0;
}

/**
 * zbud_free() - frees the allocation associated with the given handle
 * @pool:	pool in which the allocation resided
 * @handle:	handle associated with the allocation returned by zbud_alloc()
 *
 * In the case that the zbud page in which the allocation resides is under
 * reclaim, as indicated by the PG_reclaim flag being set, this function
 * only sets the first|last_chunks to 0.  The page is actually freed
 * once both buddies are evicted (see zbud_reclaim_page() below).
 */
void zbud_free(struct zbud_pool *pool, unsigned long handle)
{
	struct page *page;
	int freechunks;

	spin_lock(&pool->lock);
	page = handle_to_zbud_page(handle);

	if (!is_last_chunk(handle))
		set_num_chunks(page, FIRST, 0);
	else
		set_num_chunks(page, LAST, 0);

	if (PageReclaim(page)) {
		/* zbud page is under reclaim, reclaim will free */
		spin_unlock(&pool->lock);
		return;
	}

	freechunks = num_free_chunks(page);
	if (freechunks == NCHUNKS) {
		/* Remove from existing unbuddied list */
		list_del((struct list_head *) &page->index);
		/* zbud page is empty, free */
		list_del(&page->lru);
		free_zbud_page(page);
		pool->pages_nr--;
	} else {
		/* Add to unbuddied list */
		list_add((struct list_head *) &page->index,
				&pool->unbuddied[freechunks]);
	}

	spin_unlock(&pool->lock);
}

#define list_tail_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

/**
 * zbud_reclaim_page() - evicts allocations from a pool page and frees it
 * @pool:	pool from which a page will attempt to be evicted
 * @retires:	number of pages on the LRU list for which eviction will
 *		be attempted before failing
 *
 * zbud reclaim is different from normal system reclaim in that the reclaim is
 * done from the bottom, up.  This is because only the bottom layer, zbud, has
 * information on how the allocations are organized within each zbud page. This
 * has the potential to create interesting locking situations between zbud and
 * the user, however.
 *
 * To avoid these, this is how zbud_reclaim_page() should be called:

 * The user detects a page should be reclaimed and calls zbud_reclaim_page().
 * zbud_reclaim_page() will remove a zbud page from the pool LRU list and call
 * the user-defined eviction handler with the pool and handle as arguments.
 *
 * If the handle can not be evicted, the eviction handler should return
 * non-zero. zbud_reclaim_page() will add the zbud page back to the
 * appropriate list and try the next zbud page on the LRU up to
 * a user defined number of retries.
 *
 * If the handle is successfully evicted, the eviction handler should
 * return 0 _and_ should have called zbud_free() on the handle. zbud_free()
 * contains logic to delay freeing the page if the page is under reclaim,
 * as indicated by the setting of the PG_reclaim flag on the underlying page.
 *
 * If all buddies in the zbud page are successfully evicted, then the
 * zbud page can be freed.
 *
 * Returns: 0 if page is successfully freed, otherwise -EINVAL if there are
 * no pages to evict or an eviction handler is not registered, -EAGAIN if
 * the retry limit was hit.
 */
int zbud_reclaim_page(struct zbud_pool *pool, unsigned int retries)
{
	int i, ret, freechunks;
	struct page *page;
	unsigned long first_handle, last_handle;

	spin_lock(&pool->lock);
	if (!pool->ops || !pool->ops->evict || list_empty(&pool->lru) ||
			retries == 0) {
		spin_unlock(&pool->lock);
		return -EINVAL;
	}
	for (i = 0; i < retries; i++) {
		page = list_tail_entry(&pool->lru, struct page, lru);
		list_del(&page->lru);
		list_del((struct list_head *) &page->index);
		/* Protect zbud page against free */
		SetPageReclaim(page);
		/*
		 * We need encode the handles before unlocking, since we can
		 * race with free that will set (first|last)_chunks to 0
		 */
		first_handle = 0;
		last_handle = 0;
		if (get_num_chunks(page, FIRST))
			first_handle = encode_handle(page, FIRST);
		if (get_num_chunks(page, LAST))
			last_handle = encode_handle(page, LAST);
		spin_unlock(&pool->lock);

		/* Issue the eviction callback(s) */
		if (first_handle) {
			ret = pool->ops->evict(pool, first_handle);
			if (ret)
				goto next;
		}
		if (last_handle) {
			ret = pool->ops->evict(pool, last_handle);
			if (ret)
				goto next;
		}
next:
		spin_lock(&pool->lock);
		ClearPageReclaim(page);
		freechunks = num_free_chunks(page);
		if (freechunks == NCHUNKS) {
			/*
			 * Both buddies are now free, free the zbud page and
			 * return success.
			 */
			free_zbud_page(page);
			pool->pages_nr--;
			spin_unlock(&pool->lock);
			return 0;
		} else if (get_num_chunks(page, FIRST) == 0 ||
				get_num_chunks(page, LAST) == 0) {
			/* add to unbuddied list */
			list_add((struct list_head *) &page->index,
					&pool->unbuddied[freechunks]);
		}

		/* add to beginning of LRU */
		list_add(&page->lru, &pool->lru);
	}
	spin_unlock(&pool->lock);
	return -EAGAIN;
}

/**
 * zbud_map() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be mapped
 *
 * While trivial for zbud, the mapping functions for others allocators
 * implementing this allocation API could have more complex information encoded
 * in the handle and could create temporary mappings to make the data
 * accessible to the user.
 *
 * Returns: a pointer to the mapped allocation
 */
void *zbud_map(struct zbud_pool *pool, unsigned long handle)
{
	size_t offset = 0;
	struct page *page = handle_to_zbud_page(handle);

	if (is_last_chunk(handle))
		offset = PAGE_SIZE -
				(get_num_chunks(page, LAST) << CHUNK_SHIFT);

	return (unsigned char *) page_address(page) + offset;
}

/**
 * zbud_unmap() - maps the allocation associated with the given handle
 * @pool:	pool in which the allocation resides
 * @handle:	handle associated with the allocation to be unmapped
 */
void zbud_unmap(struct zbud_pool *pool, unsigned long handle)
{
}

/**
 * zbud_get_pool_size() - gets the zbud pool size in pages
 * @pool:	pool whose size is being queried
 *
 * Returns: size in pages of the given pool.  The pool lock need not be
 * taken to access pages_nr.
 */
u64 zbud_get_pool_size(struct zbud_pool *pool)
{
	return pool->pages_nr;
}

static int __init init_zbud(void)
{
	pr_info("loaded\n");

#ifdef CONFIG_ZPOOL
	zpool_register_driver(&zbud_zpool_driver);
#endif

	return 0;
}

static void __exit exit_zbud(void)
{
#ifdef CONFIG_ZPOOL
	zpool_unregister_driver(&zbud_zpool_driver);
#endif

	pr_info("unloaded\n");
}

module_init(init_zbud);
module_exit(exit_zbud);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seth Jennings <sjenning@linux.vnet.ibm.com>");
MODULE_DESCRIPTION("Buddy Allocator for Compressed Pages");
