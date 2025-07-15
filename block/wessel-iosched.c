// SPDX-License-Identifier: GPL-2.0
/*
 *  Wessel I/O scheduler
 *  for the blk-mq scheduling framework
 *
 *  Copyright (C) 2025 Elchanz3 <inutilidades639@gmail.com>
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-tag.h"
#include "blk-mq-sched.h"
#include "wessel-cgroup.h"
#include "wessel-iosched.h"

#if IS_ENABLED(CONFIG_BLK_SEC_STATS)
extern void blk_sec_stats_account_init(struct request_queue *q);
extern void blk_sec_stats_account_exit(struct elevator_queue *eq);
extern void blk_sec_stats_account_io_done(
		struct request *rq, unsigned int data_size,
		pid_t tgid, const char *tg_name, u64 tg_start_time);
#else
#define blk_sec_stats_account_init(q)	do {} while(0)
#define blk_sec_stats_account_exit(eq)	do {} while(0)
#define blk_sec_stats_account_io_done(rq, size, tgid, name, time) do {} while(0)
#endif

#define MAX_ASYNC_WRITE_RQS	8

static const int read_expire = HZ / 2;
static const int write_expire = 5 * HZ;
static const int max_write_starvation = 2;
static const int congestion_threshold = 90;
static const int max_tgroup_io_ratio = 50;
static const int max_async_write_ratio = 25;

static inline struct rb_root *wessel_rb_root(struct wessel_data *wessel, struct request *rq)
{
	return &wessel->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq\' in sector-sorted order
 */
static inline struct request *wessel_latter_request(struct request *rq)
{
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}

static void wessel_add_rq_rb(struct wessel_data *wessel, struct request *rq)
{
	struct rb_root *root = wessel_rb_root(wessel, rq);

	elv_rb_add(root, rq);
}

static inline void wessel_del_rq_rb(struct wessel_data *wessel, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	if (wessel->next_rq[data_dir] == rq)
		wessel->next_rq[data_dir] = wessel_latter_request(rq);

	elv_rb_del(wessel_rb_root(wessel, rq), rq);
}

static inline struct wessel_request_info *wessel_rq_info(struct wessel_data *wessel,
		struct request *rq)
{
	if (unlikely(!wessel->rq_info))
		return NULL;

	if (unlikely(!rq))
		return NULL;

	if (unlikely(rq->internal_tag < 0))
		return NULL;

	if (unlikely(rq->internal_tag >= rq->q->nr_requests))
		return NULL;

	return &wessel->rq_info[rq->internal_tag];
}

static inline void set_thread_group_info(struct wessel_request_info *rqi)
{
	struct task_struct *gleader = current->group_leader;

	rqi->tgid = task_tgid_nr(gleader);
	strncpy(rqi->tg_name, gleader->comm, TASK_COMM_LEN - 1);
	rqi->tg_name[TASK_COMM_LEN - 1] = '\0';
	rqi->tg_start_time = gleader->start_time;
}

static inline void clear_thread_group_info(struct wessel_request_info *rqi)
{
	rqi->tgid = 0;
	rqi->tg_name[0] = '\0';
	rqi->tg_start_time = 0;
}

/*
 * remove rq from rbtree and fifo.
 */
static void wessel_remove_request(struct request_queue *q, struct request *rq)
{
	struct wessel_data *wessel = q->elevator->elevator_data;

	list_del_init(&rq->queuelist);

	if (!RB_EMPTY_NODE(&rq->rb_node))
		wessel_del_rq_rb(wessel, rq);

	elv_rqhash_del(q, rq);
	if (q->last_merge == rq)
		q->last_merge = NULL;
}

static void wessel_request_merged(struct request_queue *q, struct request *req,
			      enum elv_merge type)
{
	struct wessel_data *wessel = q->elevator->elevator_data;

	if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(wessel_rb_root(wessel, req), req);
		wessel_add_rq_rb(wessel, req);
	}
}

static void wessel_merged_requests(struct request_queue *q, struct request *req,
			       struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before((unsigned long)next->fifo_time,
				(unsigned long)req->fifo_time)) {
			list_move(&req->queuelist, &next->queuelist);
			req->fifo_time = next->fifo_time;
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	wessel_remove_request(q, next);
}

/*
 * move an entry to dispatch queue
 */
static void wessel_move_request(struct wessel_data *wessel, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	wessel->next_rq[READ] = NULL;
	wessel->next_rq[WRITE] = NULL;
	wessel->next_rq[data_dir] = wessel_latter_request(rq);

	/*
	 * take it off the sort and fifo list
	 */
	wessel_remove_request(rq->q, rq);
}

/*
 * wessel_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&wessel->fifo_list[data_dir])
 */
static inline int wessel_check_fifo(struct wessel_data *wessel, int ddir)
{
	struct request *rq = rq_entry_fifo(wessel->fifo_list[ddir].next);

	/*
	 * rq is expired!
	 */
	if (time_after_eq(jiffies, (unsigned long)rq->fifo_time))
		return 1;

	return 0;
}

static struct request *wessel_fifo_request(struct wessel_data *wessel, int data_dir)
{
	struct request *rq;
	unsigned long flags;

	if (WARN_ON_ONCE(data_dir != READ && data_dir != WRITE))
		return NULL;

	if (list_empty(&wessel->fifo_list[data_dir]))
		return NULL;

	rq = rq_entry_fifo(wessel->fifo_list[data_dir].next);
	if (data_dir == READ || !blk_queue_is_zoned(rq->q))
		return rq;

	/*
	 * Look for a write request that can be dispatched, that is one with
	 * an unlocked target zone.
	 */
	spin_lock_irqsave(&wessel->zone_lock, flags);
	list_for_each_entry(rq, &wessel->fifo_list[WRITE], queuelist) {
		if (blk_req_can_dispatch_to_zone(rq))
			goto out;
	}
	rq = NULL;
out:
	spin_unlock_irqrestore(&wessel->zone_lock, flags);

	return rq;
}

/*
 * For the specified data direction, return the next request to
 * dispatch using sector position sorted lists.
 */
static struct request *wessel_next_request(struct wessel_data *wessel, int data_dir)
{
	struct request *rq;
	unsigned long flags;

	if (WARN_ON_ONCE(data_dir != READ && data_dir != WRITE))
		return NULL;

	rq = wessel->next_rq[data_dir];
	if (!rq)
		return NULL;

	if (data_dir == READ || !blk_queue_is_zoned(rq->q))
		return rq;

	/*
	 * Look for a write request that can be dispatched, that is one with
	 * an unlocked target zone.
	 */
	spin_lock_irqsave(&wessel->zone_lock, flags);
	while (rq) {
		if (blk_req_can_dispatch_to_zone(rq))
			break;
		rq = wessel_latter_request(rq);
	}
	spin_unlock_irqrestore(&wessel->zone_lock, flags);

	return rq;
}

/*
 * wessel_dispatch_requests selects the best request according to
 * read/write expire, etc
 */
static struct request *__wessel_dispatch_request(struct wessel_data *wessel)
{
	struct request *rq, *next_rq;
	bool reads, writes;
	int data_dir;

	if (!list_empty(&wessel->dispatch)) {
		rq = list_first_entry(&wessel->dispatch, struct request, queuelist);
		list_del_init(&rq->queuelist);
		goto done;
	}

	reads = !list_empty(&wessel->fifo_list[READ]);
	writes = !list_empty(&wessel->fifo_list[WRITE]);

	/*
	 * select the appropriate data direction (read / write)
	 */

	if (reads) {
		BUG_ON(RB_EMPTY_ROOT(&wessel->sort_list[READ]));

		if (wessel_fifo_request(wessel, WRITE) &&
		    (wessel->starved_writes++ >= wessel->max_write_starvation))
			goto dispatch_writes;

		data_dir = READ;

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */

	if (writes) {
dispatch_writes:
		BUG_ON(RB_EMPTY_ROOT(&wessel->sort_list[WRITE]));

		wessel->starved_writes = 0;

		data_dir = WRITE;

		goto dispatch_find_request;
	}

	return NULL;

dispatch_find_request:
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	next_rq = wessel_next_request(wessel, data_dir);
	if (wessel_check_fifo(wessel, data_dir) || !next_rq) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		rq = wessel_fifo_request(wessel, data_dir);
	} else {
		/*
		 * The last req was the same dir and we have a next request in
		 * sort order. No expired requests so continue on from here.
		 */
		rq = next_rq;
	}

	/*
	 * For a zoned block device, if we only have writes queued and none of
	 * them can be dispatched, rq will be NULL.
	 */
	if (!rq)
		return NULL;

	/*
	 * rq is the selected appropriate request.
	 */
	wessel_move_request(wessel, rq);
done:
	/*
	 * If the request needs its target zone locked, do it.
	 */
	blk_req_zone_write_lock(rq);
	rq->rq_flags |= RQF_STARTED;
	return rq;
}

/*
 * One confusing aspect here is that we get called for a specific
 * hardware queue, but we may return a request that is for a
 * different hardware queue. This is because wessel-iosched has shared
 * state for all hardware queues, in terms of sorting, FIFOs, etc.
 */
static struct request *wessel_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct wessel_data *wessel = hctx->queue->elevator->elevator_data;
	struct request *rq;
	struct wessel_request_info *rqi;

	spin_lock(&wessel->lock);
	rq = __wessel_dispatch_request(wessel);
	spin_unlock(&wessel->lock);

	rqi = wessel_rq_info(wessel, rq);
	if (likely(rqi))
		rqi->data_size = blk_rq_bytes(rq);

	return rq;
}

static void wessel_completed_request(struct request *rq, u64 now)
{
	struct wessel_data *wessel = rq->q->elevator->elevator_data;
	struct wessel_request_info *rqi;

	rqi = wessel_rq_info(wessel, rq);
	if (likely(rqi))
		blk_sec_stats_account_io_done(rq, rqi->data_size,
				rqi->tgid, rqi->tg_name, rqi->tg_start_time);
}

static void wessel_set_shallow_depth(struct wessel_data *wessel, struct blk_mq_tags *tags)
{
	unsigned int depth = tags->bitmap_tags->sb.depth;
	unsigned int map_nr = tags->bitmap_tags->sb.map_nr;

	wessel->max_async_write_rqs = depth * max_async_write_ratio / 100U;
	wessel->max_async_write_rqs =
		min_t(int, wessel->max_async_write_rqs, MAX_ASYNC_WRITE_RQS);
	wessel->async_write_shallow_depth =
		max_t(unsigned int, wessel->max_async_write_rqs / map_nr, 1);

	wessel->max_tgroup_rqs = depth * max_tgroup_io_ratio / 100U;
	wessel->tgroup_shallow_depth =
		max_t(unsigned int, wessel->max_tgroup_rqs / map_nr, 1);
}

static void wessel_depth_updated(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct wessel_data *wessel = q->elevator->elevator_data;
	struct blk_mq_tags *tags = hctx->sched_tags;
	unsigned int depth = tags->bitmap_tags->sb.depth;

	wessel->congestion_threshold_rqs = depth * congestion_threshold / 100U;

	kfree(wessel->rq_info);
	wessel->rq_info = kmalloc(depth * sizeof(struct wessel_request_info),
			GFP_KERNEL | __GFP_ZERO);
	if (ZERO_OR_NULL_PTR(wessel->rq_info))
		wessel->rq_info = NULL;

	wessel_set_shallow_depth(wessel, tags);
	sbitmap_queue_min_shallow_depth(tags->bitmap_tags,
			wessel->async_write_shallow_depth);

	wessel_blkcg_depth_updated(hctx);
}

static inline bool wessel_op_is_async_write(unsigned int op)
{
	return (op & REQ_OP_MASK) == REQ_OP_WRITE && !op_is_sync(op);
}

static unsigned int wessel_async_write_shallow_depth(unsigned int op,
		struct blk_mq_alloc_data *data)
{
	struct wessel_data *wessel = data->q->elevator->elevator_data;

	if (!wessel_op_is_async_write(op))
		return 0;

	if (atomic_read(&wessel->async_write_rqs) < wessel->max_async_write_rqs)
		return 0;

	return wessel->async_write_shallow_depth;
}

static unsigned int wessel_tgroup_shallow_depth(struct blk_mq_alloc_data *data)
{
	struct wessel_data *wessel = data->q->elevator->elevator_data;
	pid_t tgid = task_tgid_nr(current->group_leader);
	int nr_requests = data->q->nr_requests;
	int tgroup_rqs = 0;
	int i;

	if (unlikely(!wessel->rq_info))
		return 0;

	for (i = 0; i < nr_requests; i++)
		if (tgid == wessel->rq_info[i].tgid)
			tgroup_rqs++;

	if (tgroup_rqs < wessel->max_tgroup_rqs)
		return 0;

	return wessel->tgroup_shallow_depth;
}

static void wessel_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	struct wessel_data *wessel = data->q->elevator->elevator_data;
	unsigned int shallow_depth = wessel_blkcg_shallow_depth(data->q);

	shallow_depth = min_not_zero(shallow_depth,
			wessel_async_write_shallow_depth(op, data));

	if (atomic_read(&wessel->allocated_rqs) > wessel->congestion_threshold_rqs)
		shallow_depth = min_not_zero(shallow_depth,
				wessel_tgroup_shallow_depth(data));

	data->shallow_depth = shallow_depth;
}

static int wessel_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct wessel_data *wessel = hctx->queue->elevator->elevator_data;
	struct blk_mq_tags *tags = hctx->sched_tags;

	wessel_set_shallow_depth(wessel, tags);
	sbitmap_queue_min_shallow_depth(tags->bitmap_tags,
			wessel->async_write_shallow_depth);

	return 0;
}

static void wessel_exit_queue(struct elevator_queue *e)
{
	struct wessel_data *wessel = e->elevator_data;

	wessel_blkcg_deactivate(wessel->queue);

	BUG_ON(!list_empty(&wessel->fifo_list[READ]));
	BUG_ON(!list_empty(&wessel->fifo_list[WRITE]));

	kfree(wessel->rq_info);
	kfree(wessel);

	blk_sec_stats_account_exit(e);
}

/*
 * initialize elevator private data (wessel_data).
 */
static int wessel_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct wessel_data *wessel;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	wessel = kzalloc_node(sizeof(*wessel), GFP_KERNEL, q->node);
	if (!wessel) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = wessel;

	wessel->queue = q;
	INIT_LIST_HEAD(&wessel->fifo_list[READ]);
	INIT_LIST_HEAD(&wessel->fifo_list[WRITE]);
	wessel->sort_list[READ] = RB_ROOT;
	wessel->sort_list[WRITE] = RB_ROOT;
	wessel->fifo_expire[READ] = read_expire;
	wessel->fifo_expire[WRITE] = write_expire;
	wessel->max_write_starvation = max_write_starvation;
	wessel->front_merges = 1;

	atomic_set(&wessel->allocated_rqs, 0);
	atomic_set(&wessel->async_write_rqs, 0);
	wessel->congestion_threshold_rqs =
		q->nr_requests * congestion_threshold / 100U;
	wessel->rq_info = kmalloc(q->nr_requests * sizeof(struct wessel_request_info),
			GFP_KERNEL | __GFP_ZERO);
	if (ZERO_OR_NULL_PTR(wessel->rq_info))
		wessel->rq_info = NULL;

	spin_lock_init(&wessel->lock);
	spin_lock_init(&wessel->zone_lock);
	INIT_LIST_HEAD(&wessel->dispatch);

	wessel_blkcg_activate(q);

	q->elevator = eq;

	blk_sec_stats_account_init(q);
	return 0;
}

static int wessel_request_merge(struct request_queue *q, struct request **rq,
			    struct bio *bio)
{
	struct wessel_data *wessel = q->elevator->elevator_data;
	sector_t sector = bio_end_sector(bio);
	struct request *__rq;

	if (!wessel->front_merges)
		return ELEVATOR_NO_MERGE;

	__rq = elv_rb_find(&wessel->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		BUG_ON(sector != blk_rq_pos(__rq));

		if (elv_bio_merge_ok(__rq, bio)) {
			*rq = __rq;
			return ELEVATOR_FRONT_MERGE;
		}
	}

	return ELEVATOR_NO_MERGE;
}

static bool wessel_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	struct wessel_data *wessel = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	spin_lock(&wessel->lock);
	ret = blk_mq_sched_try_merge(q, bio, nr_segs, &free);
	spin_unlock(&wessel->lock);

	if (free)
		blk_mq_free_request(free);

	return ret;
}

/*
 * add rq to rbtree and fifo
 */
static void wessel_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			      bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct wessel_data *wessel = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);

	/*
	 * This may be a requeue of a write request that has locked its
	 * target zone. If it is the case, this releases the zone lock.
	 */
	blk_req_zone_write_unlock(rq);

	if (blk_mq_sched_try_insert_merge(q, rq))
		return;

	blk_mq_sched_request_inserted(rq);

	if (at_head || blk_rq_is_passthrough(rq)) {
		if (at_head)
			list_add(&rq->queuelist, &wessel->dispatch);
		else
			list_add_tail(&rq->queuelist, &wessel->dispatch);
	} else {
		wessel_add_rq_rb(wessel, rq);

		if (rq_mergeable(rq)) {
			elv_rqhash_add(q, rq);
			if (!q->last_merge)
				q->last_merge = rq;
		}

		/*
		 * set expire time and add to fifo list
		 */
		rq->fifo_time = jiffies + wessel->fifo_expire[data_dir];
		list_add_tail(&rq->queuelist, &wessel->fifo_list[data_dir]);
	}
}

static void wessel_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *list, bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct wessel_data *wessel = q->elevator->elevator_data;

	spin_lock(&wessel->lock);
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);
		wessel_insert_request(hctx, rq, at_head);
	}
	spin_unlock(&wessel->lock);
}

/*
 * Nothing to do here. This is defined only to ensure that .finish_request
 * method is called upon request completion.
 */
static void wessel_prepare_request(struct request *rq)
{
	struct wessel_data *wessel = rq->q->elevator->elevator_data;
	struct wessel_request_info *rqi;

	atomic_inc(&wessel->allocated_rqs);

	rqi = wessel_rq_info(wessel, rq);
	if (likely(rqi)) {
		set_thread_group_info(rqi);

		rcu_read_lock();
		rqi->blkg = blkg_lookup(css_to_blkcg(blkcg_css()), rq->q);
		wessel_blkcg_inc_rq(rqi->blkg);
		rcu_read_unlock();
	}

	if (wessel_op_is_async_write(rq->cmd_flags))
		atomic_inc(&wessel->async_write_rqs);
}

/*
 * For zoned block devices, write unlock the target zone of
 * completed write requests. Do this while holding the zone lock
 * spinlock so that the zone is never unlocked while wessel_fifo_request()
 * or wessel_next_request() are executing. This function is called for
 * all requests, whether or not these requests complete successfully.
 *
 * For a zoned block device, __wessel_dispatch_request() may have stopped
 * dispatching requests if all the queued requests are write requests directed
 * at zones that are already locked due to on-going write requests. To ensure
 * write request dispatch progress in this case, mark the queue as needing a
 * restart to ensure that the queue is run again after completion of the
 * request and zones being unlocked.
 */
static void wessel_finish_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct wessel_data *wessel = q->elevator->elevator_data;
	struct wessel_request_info *rqi;

	if (blk_queue_is_zoned(q)) {
		unsigned long flags;

		spin_lock_irqsave(&wessel->zone_lock, flags);
		blk_req_zone_write_unlock(rq);
		if (!list_empty(&wessel->fifo_list[WRITE]))
			blk_mq_sched_mark_restart_hctx(rq->mq_hctx);
		spin_unlock_irqrestore(&wessel->zone_lock, flags);
	}

	if (unlikely(!(rq->rq_flags & RQF_ELVPRIV)))
		return;

	atomic_dec(&wessel->allocated_rqs);

	rqi = wessel_rq_info(wessel, rq);
	if (likely(rqi)) {
		clear_thread_group_info(rqi);
		wessel_blkcg_dec_rq(rqi->blkg);
		rqi->blkg = NULL;
	}

	if (wessel_op_is_async_write(rq->cmd_flags))
		atomic_dec(&wessel->async_write_rqs);
}

static bool wessel_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct wessel_data *wessel = hctx->queue->elevator->elevator_data;

	return !list_empty_careful(&wessel->dispatch) ||
		!list_empty_careful(&wessel->fifo_list[0]) ||
		!list_empty_careful(&wessel->fifo_list[1]);
}

/*
 * sysfs parts below
 */
static ssize_t wessel_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static void wessel_var_store(int *var, const char *page)
{
	char *p = (char *) page;

	*var = simple_strtol(p, &p, 10);
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct wessel_data *wessel = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return wessel_var_show(__data, (page));				\
}
SHOW_FUNCTION(wessel_read_expire_show, wessel->fifo_expire[READ], 1);
SHOW_FUNCTION(wessel_write_expire_show, wessel->fifo_expire[WRITE], 1);
SHOW_FUNCTION(wessel_max_write_starvation_show, wessel->max_write_starvation, 0);
SHOW_FUNCTION(wessel_front_merges_show, wessel->front_merges, 0);
SHOW_FUNCTION(wessel_tgroup_shallow_depth_show, wessel->tgroup_shallow_depth, 0);
SHOW_FUNCTION(wessel_async_write_shallow_depth_show, wessel->async_write_shallow_depth, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct wessel_data *wessel = e->elevator_data;			\
	int __data;							\
	wessel_var_store(&__data, (page));					\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return count;							\
}
STORE_FUNCTION(wessel_read_expire_store, &wessel->fifo_expire[READ], 0, INT_MAX, 1);
STORE_FUNCTION(wessel_write_expire_store, &wessel->fifo_expire[WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(wessel_max_write_starvation_store, &wessel->max_write_starvation, INT_MIN, INT_MAX, 0);
STORE_FUNCTION(wessel_front_merges_store, &wessel->front_merges, 0, 1, 0);
#undef STORE_FUNCTION

#define WESSEL_ATTR(name) \
	__ATTR(name, 0644, wessel_##name##_show, wessel_##name##_store)

#define WESSEL_ATTR_RO(name) \
	__ATTR(name, 0444, wessel_##name##_show, NULL)

static struct elv_fs_entry wessel_attrs[] = {
	WESSEL_ATTR(read_expire),
	WESSEL_ATTR(write_expire),
	WESSEL_ATTR(max_write_starvation),
	WESSEL_ATTR(front_merges),
	WESSEL_ATTR_RO(tgroup_shallow_depth),
	WESSEL_ATTR_RO(async_write_shallow_depth),
	__ATTR_NULL
};

#ifdef CONFIG_BLK_DEBUG_FS
#define WESSEL_DEBUGFS_DDIR_ATTRS(ddir, name)				\
static void *wessel_##name##_fifo_start(struct seq_file *m,		\
					  loff_t *pos)			\
	__acquires(&wessel->lock)						\
{									\
	struct request_queue *q = m->private;				\
	struct wessel_data *wessel = q->elevator->elevator_data;		\
									\
	spin_lock(&wessel->lock);						\
	return seq_list_start(&wessel->fifo_list[ddir], *pos);		\
}									\
									\
static void *wessel_##name##_fifo_next(struct seq_file *m, void *v,	\
					 loff_t *pos)			\
{									\
	struct request_queue *q = m->private;				\
	struct wessel_data *wessel = q->elevator->elevator_data;		\
									\
	return seq_list_next(v, &wessel->fifo_list[ddir], pos);		\
}									\
									\
static void wessel_##name##_fifo_stop(struct seq_file *m, void *v)	\
	__releases(&wessel->lock)						\
{									\
	struct request_queue *q = m->private;				\
	struct wessel_data *wessel = q->elevator->elevator_data;		\
									\
	spin_unlock(&wessel->lock);					\
}									\
									\
static const struct seq_operations wessel_##name##_fifo_seq_ops = {	\
	.start	= wessel_##name##_fifo_start,				\
	.next	= wessel_##name##_fifo_next,				\
	.stop	= wessel_##name##_fifo_stop,				\
	.show	= blk_mq_debugfs_rq_show,				\
};									\
									\
static int wessel_##name##_next_rq_show(void *data,			\
					  struct seq_file *m)		\
{									\
	struct request_queue *q = data;					\
	struct wessel_data *wessel = q->elevator->elevator_data;		\
	struct request *rq = wessel->next_rq[ddir];			\
									\
	if (rq)								\
		__blk_mq_debugfs_rq_show(m, rq);			\
	return 0;							\
}
WESSEL_DEBUGFS_DDIR_ATTRS(READ, read)
WESSEL_DEBUGFS_DDIR_ATTRS(WRITE, write)
#undef WESSEL_DEBUGFS_DDIR_ATTRS

static int wessel_starved_writes_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct wessel_data *wessel = q->elevator->elevator_data;

	seq_printf(m, "%u\n", wessel->starved_writes);
	return 0;
}

static void *wessel_dispatch_start(struct seq_file *m, loff_t *pos)
	__acquires(&wessel->lock)
{
	struct request_queue *q = m->private;
	struct wessel_data *wessel = q->elevator->elevator_data;

	spin_lock(&wessel->lock);
	return seq_list_start(&wessel->dispatch, *pos);
}

static void *wessel_dispatch_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct request_queue *q = m->private;
	struct wessel_data *wessel = q->elevator->elevator_data;

	return seq_list_next(v, &wessel->dispatch, pos);
}

static void wessel_dispatch_stop(struct seq_file *m, void *v)
	__releases(&wessel->lock)
{
	struct request_queue *q = m->private;
	struct wessel_data *wessel = q->elevator->elevator_data;

	spin_unlock(&wessel->lock);
}

static const struct seq_operations wessel_dispatch_seq_ops = {
	.start	= wessel_dispatch_start,
	.next	= wessel_dispatch_next,
	.stop	= wessel_dispatch_stop,
	.show	= blk_mq_debugfs_rq_show,
};

#define WESSEL_IOSCHED_QUEUE_DDIR_ATTRS(name)						\
	{#name "_fifo_list", 0400, .seq_ops = &wessel_##name##_fifo_seq_ops},	\
	{#name "_next_rq", 0400, wessel_##name##_next_rq_show}
static const struct blk_mq_debugfs_attr wessel_queue_debugfs_attrs[] = {
	WESSEL_IOSCHED_QUEUE_DDIR_ATTRS(read),
	WESSEL_IOSCHED_QUEUE_DDIR_ATTRS(write),
	{"starved_writes", 0400, wessel_starved_writes_show},
	{"dispatch", 0400, .seq_ops = &wessel_dispatch_seq_ops},
	{},
};
#undef WESSEL_IOSCHED_QUEUE_DDIR_ATTRS
#endif

static struct elevator_type wessel_iosched = {
	.ops = {
		.insert_requests = wessel_insert_requests,
		.dispatch_request = wessel_dispatch_request,
		.completed_request = wessel_completed_request,
		.prepare_request = wessel_prepare_request,
		.finish_request = wessel_finish_request,
		.next_request = elv_rb_latter_request,
		.former_request = elv_rb_former_request,
		.bio_merge = wessel_bio_merge,
		.request_merge = wessel_request_merge,
		.requests_merged = wessel_merged_requests,
		.request_merged = wessel_request_merged,
		.has_work = wessel_has_work,
		.limit_depth = wessel_limit_depth,
		.depth_updated = wessel_depth_updated,
		.init_hctx = wessel_init_hctx,
		.init_sched = wessel_init_queue,
		.exit_sched = wessel_exit_queue,
	},

#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = wessel_queue_debugfs_attrs,
#endif
	.elevator_attrs = wessel_attrs,
	.elevator_name = "wessel",
	.elevator_alias = "wessel",
	.elevator_features = ELEVATOR_F_ZBD_SEQ_WRITE,
	.elevator_owner = THIS_MODULE,
};
MODULE_ALIAS("wessel");

static int __init wessel_iosched_init(void)
{
	int ret;

	ret = elv_register(&wessel_iosched);
	if (ret)
		return ret;

	ret = wessel_blkcg_init();
	if (ret) {
		elv_unregister(&wessel_iosched);
		return ret;
	}

	return ret;
}

static void __exit wessel_iosched_exit(void)
{
	wessel_blkcg_exit();
	elv_unregister(&wessel_iosched);
}

module_init(wessel_iosched_init);
module_exit(wessel_iosched_exit);

MODULE_AUTHOR("Elchanz3");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Wessel IO Scheduler");
