# Linux SLUB allocator

The Linux kernel is responsible for managing the available physical memory that it needs to satisfy memory allocation/de-allocation requests coming from different sources like device drivers, usermode processes, filesystems etc. It needs to ensure that it efficiently serves these requests under the specified constraints (if any) and to do so it relies on different types of memory allocators. Each allocator has its own interface and underlying implementation. The three main memory allocators used by the kernel are:
- Page allocator
- Slab allocator
- Vmalloc allocator
And There are other allocators as well such as contiguous memory allocator (CMA) etc.

The Linux kernel groups available physical memory into pages (usually of size 4K) and these pages are allocated by the page allocator which serves as an interface for allocating physically contiguous memory in multiples of page size. For allocating large virtually contiguous blocks (that can be physically discontiguous) the vmalloc interface is used.

More commonly the allocation requests initiated by the kernel for its internal use are for smaller blocks (usually less than page size) and using the page allocator for such cases results in wastage and internal fragmentation of memory. In order to avoid these issues the slab allocator is used. 

The Linux kernel has 3 flavors of slab allocators namely, SLAB, SLUB and SLOB allocators. The SLUB allocator is the default and most widely used slab allocator and this article will only cover the SLUB allocator.
SLUB (Simple List of Unused Blocks) is the default kernel memory allocator in Linux, designed as a simplified replacement for the original SLAB allocator. It maintains the performance characteristics of SLAB while providing better maintainability, reduced memory overhead, and improved scalability..

## Basic Concepts


The idea of the slab allocator is based on the idea of object cache. The slab allocator uses a pre-allocated cache of objects. This cache of objects is created by:
- reserving some page frames (allocated via the page allocator)
- dividing these page frames into objects and maintaining some metadata about the objects.

So, A cache is a collection of slabs and A slab is a collection of objects.
Objects belonging to a cache are further grouped into slabs, which will be of a fixed size and contain a fixed number of objects. 

So when the kernel wants to make an allocation via the SLUB allocator, it will find the right cache (depending on type/size) and then find a partial slab to allocate that object.
If there are no partial or free slabs, the SLUB allocator will allocate some new slabs via the buddy allocator. Yep, there it is, we're full circle now. The slabs themselves are allocated and freed using the buddy allocator we touched on last time.

Note: “the SLAB allocator” vs “the slab”
`The SLAB allocator` is a design/paradigm of memory allocation, whereas `the slab` is data struscture.



## Data Structures

### Slab cache: struct kmem_cache

Here's the complete `kmem_cache` as written in `https://elixir.bootlin.com/linux/v5.19.17/source/include/linux/slub_def.h` :

```c
/*
 * Slab cache management.
 */
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	/* The size of an object including metadata */
	unsigned int object_size;/* The size of an object without metadata */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;	/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	/* Number of per cpu partial objects to keep around */
	unsigned int cpu_partial;
	/* Number of per cpu partial slabs to keep around */
	unsigned int cpu_partial_slabs;
#endif
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	struct kmem_cache_order_objects min;
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	int refcount;		/* Refcount for slab cache destroy */
	void (*ctor)(void *);
	unsigned int inuse;		/* Offset to metadata */
	unsigned int align;		/* Alignment */
	unsigned int red_left_pad;	/* Left redzone padding size */
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SYSFS
	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	unsigned int remote_node_defrag_ratio;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};
```

// TO BE REMOVED
A **slab cache** is represented by a `kmem_cache` object which has a per-CPU pointer **cpu_slab** to a `kmem_cache_cpu` object. \
A `kmem_cache_cpu` object holds per-CPU information for a slab cache. Each slab is represented by a slab object. \
`kmem_cache_node` represents a memory node used by the slab allocator.


### Analysis:

- `name`: is name for the cache.
- `size`, `object_size` and `offset` are illustrated with this image:
// IMAGE HERE
- `oo` : number of objects per slab 
- `flags` holds the flags that can be set when creating a kmem_cache object: TO COMPLETE.
- `list` is a linked list of all the slab caches.
- `cpu_slab` is a per-CPU pointer to a `kmem_cache_cpu` structure that enables lockless, fast-path allocation for each CPU core:
        - Each CPU core gets its own copy of the `kmem_cache_cpu` structure.
        - No locking needed since each CPU works on its own copy.

Here's its structure: 
```c
struct kmem_cache_cpu {
	void **freelist;	/* Pointer to next available object */
	unsigned long tid;	/* Globally unique transaction id */
	struct slab *slab;	/* The slab from which we are allocating */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct slab *partial;	/* Partially allocated frozen slabs */
#endif
	local_lock_t lock;	/* Protects the fields above */
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS];
#endif
};
```

Note : We should note that both `kmem_cache_cpu.freelist` and `kmem_cache_cpu.slab.freelist` are pointing to objects on the active slab and these are two different lists albeit consisting of objects from the same slab.

Here's the structure of the slab:
```c
struct slab {
	unsigned long __page_flags;

	union {
		struct list_head slab_list;
		struct rcu_head rcu_head;
#ifdef CONFIG_SLUB_CPU_PARTIAL
		struct {
			struct slab *next;
			int slabs;	/* Nr of slabs left */
		};
#endif
	};
	struct kmem_cache *slab_cache;
	/* Double-word boundary */
	void *freelist;		/* first free object */
	union {
		unsigned long counters;
		struct {
			unsigned inuse:16;
			unsigned objects:15;
			unsigned frozen:1;
		};
	};
	unsigned int __unused;

	atomic_t __page_refcount;
#ifdef CONFIG_MEMCG
	unsigned long memcg_data;
#endif
};
```

Note: Before the 5.17 Kernel, a slab's metadata was accessed directly via a union in the `struct page`.

- `slab_cache` is a pointer to the `kmem_cache` struct the slab belongs to.
- `freelist` is a pointer to the first free object in this slab as we saw earlier.
- `inuse:16` is the number of objects currently allocated.
- `frozen`: mean that the slab is being actively modified by one CPU and should not be accessed by other CPUs

A slab can consist of one or more pages and this does not depend on the object size i.e.  a slab can consist of multiple pages even if its objects are smaller than a page. The number of pages in a slab depends on `kmem_cache.oo` .

Last by not least, we have the `kmem_cache_node` structure:

```c
struct kmem_cache_node {
	spinlock_t list_lock;

	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};
```

- `partial` is a circular doubly-linked list of all partially filled slabs available for allocation.
- `nr_partial` is the  number of partial slabs.
- `kmem_cache->min_partial` is the minimum number of partial slabs to retain even when they're empty.


## Allocating a slub object

Allocation always happens from the **active slab** and both per-cpu's `freelist` and per-cpu's `slab.freelist` point to a free object on the active slab.

There are 2 allocation paths for objects: **Fastpath** and **Slowpath**.

### Fastpath:

- allocation happens when per-cpu lockless `freelist` (`kmem_cache.cpu_slab->freelist`) contains free objects. This is the simplest allocation path and it does not involve any locking or irq/preemption disabling. The object at the front of this freelist is returned as an allocated object and next available object in the `freelist` becomes the head of the list. If allocation ends up consuming all objects in the lockless `freelist`, then this list becomes `NULL` and will get objects when allocation is next attempted. As mentioned earlier if the CPU does not support **cmpxchg for 2 words** or if slub debugging (slub_debug) is enabled, **`Fastpath` is not used**.

Scenario:
When a slab becomes the active slab for a CPU, its freelist is transferred to the CPU's lockless freelist (kmem_cache_cpu->freelist) and the slab's own freelist is cleared and marked as frozen. Objects are then allocated directly from this per-CPU freelist without any locking. When objects are freed, the behavior depends on which CPU performs the free operation: if freed by the same CPU that allocated them, they're added to the head of that CPU's freelist for immediate reuse. However, if freed by a different CPU, they're atomically added to the frozen slab's freelist using compare-and-swap operations for thread safety, since the slab remains "owned" by the original CPU. This asymmetric free behavior can lead to a situation where a CPU's per-CPU freelist becomes empty (after allocating all objects) while the slab's freelist accumulates objects (from cross-CPU frees). When the CPU needs more objects and finds its freelist empty, the slow path will check the slab's freelist and transfer any available objects back to the per-CPU freelist before falling back to partial slabs or allocating new slabs entirely. This design optimizes for the common case of same-CPU allocation/free cycles while handling cross-CPU frees safely through atomic operations on the slab's freelist.

### SLOWPATH 1:
- If the per-cpu lockless `freelist` does not contain free objects but the `slab.freelist` of the active slab does contain free objects then the first object of the slab’s freelist is returned as an allocated object and the **rest of the active slab’s freelist is transferred to that CPU’s lockless freelist and the active slab’s freelist becomes NULL**. This path involves disabling preemption and acquiring `kmem_cache_cpu.lock` so it is slower than `Fastpath` allocation but is still faster than other allocation paths. Explicit disabling of preemption is needed for CONFIG_PREEMPT_RT kernels.


### SLOWPATH 2:
In allocation paths discussed so far a CPU’s active slab had some free objects but it may happen that there are no more free objects in the active slab but the per-cpu partial slab list has slabs with free objects (assuming support of partial slab list is enabled). In this case the first slab in the per-cpu partial slab list becomes the active slab, its freelist is transferred to the CPU’s lockless freelist and objects get allocated from that freelist. This path also only involves disabling preemption and acquiring kmem_cache_cpu.lock but has additional overhead compared to the previous path. This additional overhead comes from the fact that in this case we need to make the first slab in per-cpu partial slab list, the current active slab and the second slab (if any) in the per-cpu partial slab list becomes head of this list.


If per-cpu slabs (active and partial) do not have free objects, then allocation is attempted from slabs from the per-node partial slab list. How does the per-node partial slab list get its slabs ? Slabs are never explicitly allocated for the per-node partial slab list. When a full slab becomes empty or partial, we try to put it into the per-cpu partial slab list first and if that is not possible (either because the per-cpu partial slab list is not supported or because it has the maximum allowed number of objects), the slab is put into the per-node partial slab list. This is how the per-node partial slab list gets its slabs.

### SLOWPATH 3:
Now when neither of the per CPU active or partial slabs have free objects, slub allocator tries to get slabs from the partial slab list of local node but if it can’t find slabs in that node’s partial slab list, then it tries to get partial slabs from the per-node partial slab list corresponding to other nodes. The nodes nearer to CPU are tried first. The traversal of a node’s partial slab list involves acquiring kmem_cache_node.list_lock and since this is a central lock, the involved overhead is much more than acquiring kmem_cache_cpu.lock needed in previously described cases. While looking for a slab, slub allocator iterates through the per-node partial slab list and for the first found slab, it notes the first free object and this object will be returned as an allocated object and the rest of this slab becomes the per-cpu active slab.

### SLOWPATH 4:
If the per-cpu partial slab list is supported then slub allocator continues even after getting a usable slab and making it the active slab. It moves slabs from the per-node partial slab list to the per-cpu partial slab list and continues doing so until all slabs in the per-node partial slab list have been moved or the limit of maximum number of slabs that can be kept in a per-cpu partial slab list has been reached. The maximum number of slabs that can exist in the per-cpu partial slab list depends on object size. slub allocator tries to keep a certain number of objects available in the per-cpu partial slab list. Based on this number of objects and assuming that each slab will be half full, slub allocator decides how many slabs can reside in the per-cpu partial slab list. The number of objects in the per-cpu partial slab list, depends on the object size and can be 6, 24, 52 or 120. For larger objects, the number of objects that the slub allocator tries to maintain in the per-cpu partial slab list is smaller. For example for objects of size >= PAGE_SIZE this number is 6 and for objects of size < 256 this number is 120.

### Very SLOWPATH:
Lastly if all of the slabs of a slab cache are full, a new slab gets allocated using page allocator and this newly allocated slab becomes the CPU’s current active slab. Amongst all the slow allocation paths this is the slowest one because it involves getting new pages from the **buddy allocator**.


## Freeing a slub object
TO BE CONTINUED



# REFERENCES

![](https://blogs.oracle.com/linux/post/linux-slub-allocator-internals-and-debugging-1)
![](https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf)
![](https://sam4k.com/linternals-memory-allocators-0x02/)
![](https://events.static.linuxfound.org/sites/events/files/slides/slaballocators-japan-2015.pdf)
