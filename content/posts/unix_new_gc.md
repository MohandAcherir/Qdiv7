---
date: 2026-04-19
# description: ""
# image: ""
lastmod: 2026-04-19
showTableOfContents: false
tags: ["kernel", "graphs", "exploitation"]
title: "Unix GC Remastered"
type: "post"
---


First off, ladies and gentlemen,
### AF_UNIX Garbage Collector Analysis:

The garbage collector is a mechanism for cleaning unused objects in the heap and liberate memory for other allocations.
Every subsystem has its own special-purpose GC for freeing certain objects: sockets, nf objects...etc.

For socket GC, concretely, when either of **two** conditions are satisfied, the GC function `unix_gc()` is triggered:
```c
static DECLARE_WORK(unix_gc_work, __unix_gc);

void unix_gc(void) // <-----
{
	WRITE_ONCE(gc_in_progress, true);
	queue_work(system_dfl_wq, &unix_gc_work);
}
```

`unix_gc()` core is `__unix_gc()`:
```c
static void __unix_gc(struct work_struct *work)
{
	struct sk_buff_head hitlist;
	struct sk_buff *skb;

	spin_lock(&unix_gc_lock);

	if (!unix_graph_maybe_cyclic) {
		spin_unlock(&unix_gc_lock);
		goto skip_gc;
	}

	__skb_queue_head_init(&hitlist);

	if (unix_graph_grouped)
		unix_walk_scc_fast(&hitlist);
	else
		unix_walk_scc(&hitlist);

	spin_unlock(&unix_gc_lock);

	skb_queue_walk(&hitlist, skb) {
		if (UNIXCB(skb).fp)
			UNIXCB(skb).fp->dead = true;
	}

	__skb_queue_purge_reason(&hitlist, SKB_DROP_REASON_SOCKET_CLOSE);
skip_gc:
	WRITE_ONCE(gc_in_progress, false);
}
```

### Concepts:
- **unix_socket**:
```c
/* The AF_UNIX socket */
struct unix_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;							 // Inheritence
	struct unix_address	*addr;		 // Name of the socket
	struct path		path;						 // path in the filesystem if bound
	struct mutex		iolock, bindlock; // Mutex 
	struct sock		*peer;				   // peer socket connected to
	struct list_head	link;
	atomic_long_t		inflight;			 // [1] SCM_RIGHTS fd count
	// ...
	struct sk_buff		*oob_skb;		// socket's buffer
#endif
};
```

The most important member for GC is `inflight` **[1]**.
A socket is "in flight" means exactly what it says: It's going from point A to point B i.e: Process A to Process B; and each time, it's being sent - Sent by process A but to yet arrived to/accept by a process B using **SCM_RIGHTS** - the `inflight` member is incremented until it is accepted, after that it is decremented. When the GC is triggered it looks for sockets that have their `refcount == inflight` - meaning that these sockets exist only "inflight" but have no backing in the out-flight realm and thus can no more be accessed from userspace. 
Here's how it is described by this [LWN](https://lwn.net/Articles/966730/) article:

> "Let's say we send a fd of AF_UNIX socket A to B and vice versa and
   close() both sockets.
   When created, each socket's struct file initially has one reference.
   After the fd exchange, both refcounts are bumped up to 2.  Then, close()
   decreases both to 1.  From this point on, no one can touch the file/socket. 
   However, the struct file has one refcount and thus never calls the
   release() function of the AF_UNIX socket. That's why we need to track all inflight AF_UNIX sockets and run garbage collection."

The kernel maintains a global variable `unix_tot_inflight` that incremented for each "inflight" socket, and decremented each time a socket is accepted.

Coming back to the **two** conditions mentioned earlier, here they are:
- `unix_tot_inflight` > UNIX_INFLIGHT_TRIGGER_GC == 16000 :
```c
	if (READ_ONCE(unix_tot_inflight) > UNIX_INFLIGHT_TRIGGER_GC &&
	    !READ_ONCE(gc_in_progress))
		unix_gc(); // <-----
```
- Calling: `close(fd)` on a socket file descriptor:
```c
static const struct proto_ops unix_stream_ops = {
	.family =	PF_UNIX,
	.owner =	THIS_MODULE,
	.release =	unix_release, // <-----
	// [...]
}

static int unix_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sk->sk_prot->close(sk, 0);
	unix_release_sock(sk, 0);
	sock->sk = NULL;

	return 0;
}

// -----------------------------------------------------------------------------

static void unix_release_sock(struct sock *sk, int embrion)
{
	struct unix_sock *u = unix_sk(sk);
	struct sock *skpair;
	// [...]
	if (READ_ONCE(unix_tot_inflight))
		unix_gc(); // <---------	/* Garbage collect fds */
}


```


### Old GC Version

One very good article that describes it well is this one from [Google P0 ](https://projectzero.google/2022/08/the-quantum-state-of-linux-kernel.html) where it goes into the details of the process taking place in `unix_gc()`, and then analyses an Android In-The-Wild exploit discovered back in 2021. So, it is highly recommended to read it before continuing.
For my part, i'm discussing the new version and then a CVE exploited in Google's KernelCTF.
Nevertheless, here's a quick recap on this:

![](/Qdiv7/images/gc_remastered/Screenshot-gc-1.png)

The GC tracks cycles and checks whether inflight != refcount, if not, it is considered to be in a potential cycle.  
### New GC Version

As it said in the [GC Rework](https://lwn.net/Articles/966730/) article: 
> "... replaces the current GC implementation that locks each inflight
socket's receive queue and requires trickiness in other places.
The new GC does not lock each socket's queue to minimise its effect and
tries to be lightweight if there is no cyclic reference or no update in
the shape of the inflight fd graph."

The idea is to represent the **inflight** sockets as vertices and their backing file objects as edges:
here's an example with sockets A, B, C and D.
Send:
1) A to  C
2) C to D and
3) Send B to D

So here, we have 3 inflight sockets which are A, B and C, but not D; and here's how they're seen by the GC:

![](/Qdiv7/images/gc_remastered/Screenshot-gc-2.png)


It then uses Tarjan's algorithm to form Strongly Connected Components. Why SCCs?
For any graph(in general), and for any SCC(of more than 1 vertice) inside it, there's necessarily at least one cycle in that SCC:

![](/Qdiv7/images/gc_remastered/Screenshot-gc-3.png)

The vertices forming a cycle is seen as potential garbage by the GC which actually logical if we think about it; What does it mean for a vertex(socket) to be garbage ? First it must be inflight of course, and be only(potentially) reachable from other inflight sockets, and also must be unreachable from userspace i.e refcount > inflight . So having a cycle, is a necessary but not sufficient condition for having a real Garbage.


The core function `__unix_gc()`:
```c
static void __unix_gc(struct work_struct *work)
{
	struct sk_buff_head hitlist; // [2]
	struct sk_buff *skb;
	// [...]
	__skb_queue_head_init(&hitlist); // [2.5]
}
```
At **[2]**, the `hitlist` is a list that will hold the final sockets what will be freed; it is initialized at **[2.5]**.

Next up:
```c
static void __unix_gc(struct work_struct *work)
{
	// [...]
	if (!unix_graph_maybe_cyclic) { // [3]
		spin_unlock(&unix_gc_lock);
		goto skip_gc;
	}
	// [...]
}

```

`unix_graph_maybe_cyclic` is a boolean variable that tracks the state of the graph, so in **[3]**, `__unix_gc()` aborts if the graph is considered to be in a non-cyclic state. This state is activated when an edge is added from an inflight socket into another inflight socket:
```c
static void unix_add_edge(struct scm_fp_list *fpl, struct unix_edge *edge)
{
	struct unix_vertex *vertex = edge->predecessor->vertex;

	if (!vertex) {
		vertex = list_first_entry(&fpl->vertices, typeof(*vertex), entry);
		vertex->index = unix_vertex_unvisited_index;
		// [...]
	}

	vertex->out_degree++;
	list_add_tail(&edge->vertex_entry, &vertex->edges);
	unix_update_graph(unix_edge_successor(edge)); // <------
}
```

In `unix_update_graph`:
```c
static void unix_update_graph(struct unix_vertex *vertex)
{
	/* If the receiver socket is not inflight, no cyclic
	 * reference could be formed.
	 */
	if (!vertex)
		return;

	WRITE_ONCE(unix_graph_state, UNIX_GRAPH_MAYBE_CYCLIC); // <------
	unix_graph_grouped = false; // <---------
}
```

This forces the GC to run if it senses some cycles are hanging around; notice that it sets `unix_graph_grouped` to `false` too.

After that, the real work starts:
```c
static void __unix_gc(struct work_struct *work)
{
	// [...]
	__skb_queue_head_init(&hitlist);

	if (unix_graph_grouped)
		unix_walk_scc_fast(&hitlist);
	else
		unix_walk_scc(&hitlist);

	// [...]
}
```

**`unix_walk_scc_fast()`** or **`unix_walk_scc()`** are called depending on whether the graph is grouped into Strongly Connected Components or not.

`1)Slow Path`:
This where the Strongly Connected Components are created:
```c
static void unix_walk_scc(struct sk_buff_head *hitlist)
{
	unsigned long last_index = UNIX_VERTEX_INDEX_START;

	unix_graph_maybe_cyclic = false;
	unix_vertex_max_scc_index = UNIX_VERTEX_INDEX_START;

	/* Visit every vertex exactly once.
	 * __unix_walk_scc() moves visited vertices to unix_visited_vertices.
	 */
	while (!list_empty(&unix_unvisited_vertices)) { // [3.5]
		struct unix_vertex *vertex;

		vertex = list_first_entry(&unix_unvisited_vertices, typeof(*vertex), entry);
		__unix_walk_scc(vertex, &last_index, hitlist);
	}

	list_replace_init(&unix_visited_vertices, &unix_unvisited_vertices);
	swap(unix_vertex_unvisited_index, unix_vertex_grouped_index);

	unix_graph_grouped = true;
}

```

The vertex indexing starts at `UNIX_VERTEX_INDEX_START`, and at the beginning the of `unix_walk_scc` it assumes that the graph is not cyclic.
The graph walk begins at [8] by iterating over the unvisited vertices as in the algorithm.

> Note: Iterating through all vertices as in [3.5] does not really happen effectively; if the graph is at last Weakly Connected it needs only one single iteration. So, iterating over many vertices is useful only when the graph is a non connected set of graphs i.e a **forest**. So, that's why it has a good algorithmic complexity `O(|V|+|E|)` where V is the number of vertices, and E the number of edges.

### Tarjan's Algorithm:
The algorithm takes a [directed graph](https://en.wikipedia.org/wiki/Directed_graph "Directed graph") as input, and forms its strongly connected components. Each vertex of the graph appears in exactly one of the strongly connected component. Any vertex that is not on a directed cycle forms a strongly connected component all by itself.
The basic idea is to start from an arbitrary vertex that is associated to a pair (`index`, `scc_value`), and then do a Depth-First-Search on it recursively; the goal is to reach this starting vertex again to propagate its `scc_value` to form its containing SCC.

You can find all the details in this [Wikipedia page](https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm).

![](/Qdiv7/images/gc_remastered/tarjan.gif)


Here's the Pseudo-code for a better understanding(I hope at least ;-):
```c
For each unvisited vertex v:
	__unix_walk_scc(v, last_index, hitlist)


__unix_walk_scc(v, last_index, hitlist):
	vertex_S, edge_S, edge
	|------------------------------------|
next_vertex:
	vertex_S.push(v)
	v.index <- last_index
	v.scc_index <- last_index
	last_index += 1
	
	for each edge e: (v, w) in the Graph:
		// w == e.successor
		if vertex w is not yet visited:
			edge_S.push(e: (v, w))
			v <- w
			goto next_vertex
			|------------------------------|
		        -> prev_vertex: i.e: returning from the recursion
			edge = edge_S.pop() or getFirst() ?
			delete edge from edge_S
			// backtrack
			w <- v
			v <- edge.predecessor.vertex
			v.scc_index = min(v.scc_index, w.scc_index)
		else if w is not in another SCC:
			v.scc_index = min(v.scc_index, w.scc_index
	|-----------------------------------------------|
	if v.index == v.scc_index:
		scc <- {}
		scc_dead = true
		
		// vertex_S == [SCC(0)][SCC(1)][...][SCC(N)]
		// vertex_S == [SCC(0)][SCC(1)][...][SCC(N-1)][v ...]
		// cutting vertex_S taking the [v ...] SCC
		//__list_cut_position(&scc, &vertex_stack, &vertex->scc_entry);
		scc <- [v ...]
		
		while scc in not empty:
			u <- scc.pop() // not a pop, but takes the last elem
			// So maybe add: scc.push(u) ;-)
			// adding it to the visited vertices
			unix_visited_vertices.add(u)
			// marking it as grouped
			u.index <- unix_vertex_grouped_index
			if(scc_dead):
				scc_dead <- unix_vertex_dead(v);
		if scc_dead:
			// purge
			unix_collect_skb(&scc, hitlist);
		else:
			if unix_vertex_max_scc_index < v.scc_index:
				unix_vertex_max_scc_index <- vertex.scc_index;
			if not unix_graph_maybe_cyclic:
			        unix_graph_maybe_cyclic<-unix_scc_cyclic(&scc);
	|-----------------------------------------------|
	// Need backtracking ? It is basically recursion
	if edge_stack is not empty
		goto prev_vertex;

```

---

`2) Fast Path`:
This path assumes that the SCCs are already formed, and the graph is unchanged.
It iterates through all the unvisited vertices one by one `[4]`:  

```c
static void unix_walk_scc_fast(struct sk_buff_head *hitlist)
{
	unix_graph_maybe_cyclic = false;

	while (!list_empty(&unix_unvisited_vertices)) { // [4]
		struct unix_vertex *vertex;
		struct list_head scc;
		bool scc_dead = true;

		vertex = list_first_entry(&unix_unvisited_vertices, typeof(*vertex), entry);
		list_add(&scc, &vertex->scc_entry);

		list_for_each_entry_reverse(vertex, &scc, scc_entry) { // [5]
			list_move_tail(&vertex->entry, &unix_visited_vertices); // [6]

			if (scc_dead)
				scc_dead = unix_vertex_dead(vertex); // [7]
		}

		if (scc_dead)
			unix_collect_skb(&scc, hitlist);
		else if (!unix_graph_maybe_cyclic)
			unix_graph_maybe_cyclic = unix_scc_cyclic(&scc);

		list_del(&scc);
	}

	list_replace_init(&unix_visited_vertices, &unix_unvisited_vertices);
}
```

It starts by picking the first vertex in  `unix_unvisited_vertices` and initializes with it the Strongly Connected Component variable `scc`.
In [5], it goes through all the vertices of the `scc` in the reverse order, and each vertex marked as visited by putting it into `unix_visited_vertices` [7]; in each iteration, if the previous vertex was dead, the current one is also checked [6] with  `unix_vertex_dead(vertex)`.
If the last vertex is marked as "dead", the whole SCC is put into the `hitlist` to be purged [7].

### CVE-2025-40214: kCTF entry

The patch:
```diff
diff --git a/net/unix/garbage.c b/net/unix/garbage.c
index 684ab03137b6c..65396a4e1b07e 100644
--- a/net/unix/garbage.c
+++ b/net/unix/garbage.c
@@ -145,6 +145,7 @@ enum unix_vertex_index {
 };
 
 static unsigned long unix_vertex_unvisited_index = UNIX_VERTEX_INDEX_MARK1;
+static unsigned long unix_vertex_max_scc_index = UNIX_VERTEX_INDEX_START;
 
 static void unix_add_edge(struct scm_fp_list *fpl, struct unix_edge *edge)
 {
@@ -153,6 +154,7 @@ static void unix_add_edge(struct scm_fp_list *fpl, struct unix_edge *edge)
 	if (!vertex) {
 		vertex = list_first_entry(&fpl->vertices, typeof(*vertex), entry);
 		vertex->index = unix_vertex_unvisited_index;
+		vertex->scc_index = ++unix_vertex_max_scc_index;
 		vertex->out_degree = 0;
 		INIT_LIST_HEAD(&vertex->edges);
 		INIT_LIST_HEAD(&vertex->scc_entry);
@@ -489,10 +491,15 @@ prev_vertex:
 				scc_dead = unix_vertex_dead(v);
 		}
 
-		if (scc_dead)
+		if (scc_dead) {
 			unix_collect_skb(&scc, hitlist);
-		else if (!unix_graph_maybe_cyclic)
-			unix_graph_maybe_cyclic = unix_scc_cyclic(&scc);
+		} else {
+			if (unix_vertex_max_scc_index < vertex->scc_index)
+				unix_vertex_max_scc_index = vertex->scc_index;
+
+			if (!unix_graph_maybe_cyclic)
+				unix_graph_maybe_cyclic = unix_scc_cyclic(&scc);
+		}
 
 		list_del(&scc);
 	}
@@ -507,6 +514,7 @@ static void unix_walk_scc(struct sk_buff_head *hitlist)
 	unsigned long last_index = UNIX_VERTEX_INDEX_START;
 
 	unix_graph_maybe_cyclic = false;
+	unix_vertex_max_scc_index = UNIX_VERTEX_INDEX_START;
 
 	/* Visit every vertex exactly once.
 	 * __unix_walk_scc() moves visited vertices to unix_visited_vertices.
```

Trying to do the POC:
> "The repro consists of three stages:
> 1)     1-a. Create a single cyclic reference with many sockets
>     1-b. close() all sockets 
>     1-c -> Trigger GC 
> 2)      2-a. Pass sk-A to an embryo sk-B 
	   2-b. Pass sk-X to sk-X
	   2-c. Trigger GC 
> 3)     3-a. accept() the embryo sk-B
>     3-b. Pass sk-B to sk-C
>     3-c. close() the in-flight sk-A
>     3-d. Trigger GC"

**Step I**: is used for heap spraying, making a newly allocated vertex have -> 
`vertex->scc_index == 2` (UNIX_VERTEX_INDEX_START) set by the GC in `unix_walk_scc()` at [1-c].

**Step II**: `sk-A` and `sk-X` are linked to `unix_unvisited_vertices`, and `unix_walk_scc()` groups them into two different SCCs:
`unix_sk(sk-A)->vertex->scc_indesx = 2` (UNIX_VERTEX_INDEX_START) & 
`unix_sk(sk-X)->vertex->scc_index = 3`.

**Step III**: form A -> B -> (C), this way B will be mistaken to be in A's SCC by `unix_add_edge()` which do not initialize `v->scc_index` due to the spraying in Step I. 
And when the GC runs, we get A freed even though it's not dead.

```c
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <liburing.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <err.h>

// [...]




```