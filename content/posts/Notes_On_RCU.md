---
date: 2026-03-09
# description: ""
# image: ""
lastmod: 2026-03-09
showTableOfContents: false
tags: ["Kernel", "RCU"]
title: "Notes On RCU"
type: "post"
---


RCU is a mechanism in the Linux kernel for concurrency that is lock-free, wait-free (for readers) and that allows concurrent readers and a single updater. 
RCU is made up of three fundamental mechanisms, one for **insertion**, the other for **deletion**, and the third being used to allow readers to tolerate **concurrent insertions and deletions**. These mechanisms are described in the following sections, which focus on applying RCU to linked lists.

1. Publish-Subscribe Mechanis.
2. Wait For Pre-Existing RCU Readers to Complete.
3. Maintain Multiple Versions of Recently Updated Objects.

### I. Publish-Subscribe Mechanism:

Let's see this example:
```c
struct foo {
	int a;
	int b;
	int c;
};

struct foo *gp = NULL;
// [...]

p = kmalloc(sizeof(*p), GFP_KERNEL);
p->a = 1;
p->b = 2;
p->c = 3;
gp = p; // [1]
```

A reader can see uninitialized data if the CPU / Compiler chooses to put [1] before the assignments of `a`, `b` and `c`.

**Solution**:
```c
p->a = 1;
p->b = 2;
p->c = 3;
rcu_assign_pointer(gp, p);
```

The `rcu_assign_pointer()` _publishes_ the pointer **`p`** by assigning it to an RCU-protected pointer **`gp`**, forcing both the compiler and the CPU to execute the assignment to `gp` _after_ the assignments to the fields referenced by `p` so that RCU readers will see these assignments.

Let's see that in more detail:
```c
// /include/linux/rcupdate.h
#define rcu_assign_pointer(p, v)                                                
do {                                  
										                                        \
    uintptr_t _r_a_p__v = (uintptr_t)(v);                                       \
    rcu_check_sparse(p, __rcu); // [2]                                          \
                                                                                \
    if (__builtin_constant_p(v) && (_r_a_p__v) == (uintptr_t)NULL)              \
        WRITE_ONCE((p), (typeof(p))(_r_a_p__v));                                \
    else                                                                        \
        smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); // [3]    \
} while (0)
```

At [2], it calls 
```c
#define rcu_check_sparse(p, space) \
    ((void)(((typeof(*p) space *)p) == p))
```

which does a trivial (?) check on the assignee pointer.
And then in [3] -  if **`v`** is not null -  it calls
**`smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v))`**, where 
- the 1st arg the address of the destination pointer to be filled
- the 2nd arg is an initialized RCU-protected global variable with the source pointer **`v`**.

```c
#define smp_store_release(p, v) do
{
	kcsan_release(); //                 \ 
	__smp_store_release(p, v); // [5]   \
} while (0)
```

**`kcsan_release`** is race check between CPUs thing.
In **[5]**, `__smp_store_release`:
```c
#define __smp_store_release(p, v)             \
do {                                          \
    compiletime_assert_atomic_type(*p);       \
    barrier();                                \
    WRITE_ONCE(*p, v); // [6]                 \
} while (0)

```

The heart of this mechanism is `barrier()`.
It forces the compiler to complete the initialization:
```c
p->a = 1;
p->b = 2;
p->c = 3;
```

Before reaching [6], **`WRITE_ONCE(*p, v);`**

So, that's basically it about **`rcu_assign_pointer`** and ordering at the writer side.

So let's see ordering from the reader's side.
For the same reasons, readers, as much as writer, may also fetch disordered data due to value speculation and various compiler optimizations.  To counter that, we need to subscribe the previously published data(with `rcu_assign_pointer`s), that's why it is called **Publish-Subscribe**:
```
p = rcu_dereference(gp);
```

This is implemented using **`rcu_dereference`** which fetches any initialization done beforehand on RCU-protected pointer:
```c
#define rcu_dereference(p) rcu_dereference_check(p, 0)
```

which calls:
```c
#define __rcu_dereference_check(p, local, c, space) \
({ \
    /* Dependency order vs. p above. */ \
    typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p); \
    RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
    rcu_check_sparse(p, space); \
    ((typeof(*p) __force __kernel *)(local)); \
})
```


This Publish-Subscribe mechanism is embedded into a higher-level API to do operations on RCU-protected data structures.
It implements single and double linked lists that we can read and write objects on.

For singly linked lists:

```c
struct example {
	struct list_head list;
	int x;
	int y;
	int z;
};

LIST_HEAD(head); // [7]


p = kmalloc(sizeof(*p), GFP_KERNEL); // [8]
p->x = 24;
p->y = 25;
p->z = 26;

// Lock
list_add_rcu(&p->list, &head); // [9]
// Unlock
```

In [7] it declares the head of the list to operate on,  and at [8], object is initialized and filled with data, and at [9], we call `list_add_rcu` which adds this new element to the list AKA Publish, by doing and underlying call to `rcu_assign_pointer` :
```c

// include/linux/rculist.h
// -> __list_add_rcu(new, head, head->next);
static inline void __list_add_rcu(struct list_head *new,
        struct list_head *prev, struct list_head *next)
{
    if (!__list_add_valid(new, prev, next))
        return;

    new->next = next;
    new->prev = prev;
    rcu_assign_pointer(list_next_rcu(prev), new); // <-----------
    next->prev = new;
}
```

To Subscribe, we use `list_for_each_entry_rcu`:
```c
// Lock

list_for_each_entry_rcu(p, head, list) {
   // operate on p->x, p->y, p->z);
}

// Unlock
```

> Note: RCU-Locking in both Publishing and Subscribing is important to avoid concurrency issues.

So, `list_for_each_entry_rcu` iterates over the elements of the list.

For Doubly linked lists we got the same thing basically.

Here's the full API list:

| Category | Publish                                                                                                      | Retract                         | Subscribe                    |
| -------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------- | ---------------------------- |
| Pointers | `rcu_assign_pointer()`                                                                                       | `rcu_assign_pointer(..., NULL)` | `rcu_dereference()`          |
| Lists    | `list_add_rcu()`  <br>`list_add_tail_rcu()`  <br>`list_replace_rcu()`                                        | `list_del_rcu()`                | `list_for_each_entry_rcu()`  |
| Hlists   | `hlist_add_after_rcu()`  <br>`hlist_add_before_rcu()`  <br>`hlist_add_head_rcu()`  <br>`hlist_replace_rcu()` | `hlist_del_rcu()`               | `hlist_for_each_entry_rcu()` |

Now, with `Retracting` / `Deleting` operations on lists, it beg's the question: when we remove an element from a list with (say) `list_del_rcu`, how can we possibly know when all the readers have released their references to that data element ?.

> Note: An RCU reader is what is inside of **rcu_read_lock** and **rcu_read_unlock** .

This brings us to the second part.



###  II. Grace Period:

**Grace Period** is waiting for Pre-Existing RCU readers to complete, before deleting or replacing an object in the list. 

![](/Qdiv7/images/RCU/Screenshot-1.png)

In this example, we replace object `p` by object `q` in the list:
```c
struct example {
	struct list_head list;
	int a;
	int b;
	int c;
};

LIST_HEAD(head);

// Add key object
// [...]
p = search(head, key);

q = kmalloc(sizeof(*p), GFP_KERNEL);
*q = *p;
q->b = 2;
q->c = 3;

list_replace_rcu(&p->list, &q->list);
synchronize_rcu();
kfree(p);

```

`synchronize_rcu()` is what does the actual waiting.
Actually, this is the Synchronous mode.

There's an Asynchronous mode where the task of waiting for readers and freeing the target object is delegated to other kthread workers. In this case, we define a callback and register a callback that will be called instead of  `synchronize_rcu()` :

```c
struct example {
	struct list_head list;
	struct rcu_head rcu;
	int a;
	int b;
	int c;
};

LIST_HEAD(head);

// Add key object
// [...]
p = search(head, key);

q = kmalloc(sizeof(*p), GFP_KERNEL);
*q = *p;
q->b = 2;
q->c = 3;

list_replace_rcu(&p->list, &q->list);
call_rcu(&p->rcu, cb);
```

the callback could be defined as:
```c
static void cb(struct rcu_head *arg)
{
    struct example *e = container_of(arg, struct example, rcu);
    kfree(e);
}
```

## Resources
- https://lwn.net/Articles/262464/