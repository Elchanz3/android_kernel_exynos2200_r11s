/* SPDX-License-Identifier: GPL-2.0 */
#ifndef WESSEL_IOSCHED_H
#define WESSEL_IOSCHED_H

#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/rbtree.h>
#include <linux/sbitmap.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/compiler.h>

#include "wessel-cgroup.h"

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

struct wessel_request_info {
	pid_t tgid;
	char tg_name[TASK_COMM_LEN];
	u64 tg_start_time;

	struct blkcg_gq *blkg;

	unsigned int data_size;
};

struct wessel_data {
	struct request_queue *queue;

	/*
	 * requests are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2];
	struct list_head fifo_list[2];

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2];
	unsigned int starved_writes;	/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2];
	int max_write_starvation;
	int front_merges;

	/*
	 * to control request allocation
	 */
	atomic_t allocated_rqs;
	atomic_t async_write_rqs;
	int congestion_threshold_rqs;
	int max_tgroup_rqs;
	int max_async_write_rqs;
	unsigned int tgroup_shallow_depth;
	unsigned int async_write_shallow_depth;

	/*
	 * I/O context information for each request
	 */
	struct wessel_request_info *rq_info;

	spinlock_t lock;
	spinlock_t zone_lock;
	struct list_head dispatch;
};

#endif


