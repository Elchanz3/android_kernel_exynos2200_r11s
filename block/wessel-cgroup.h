/* SPDX-License-Identifier: GPL-2.0 */
#ifndef WESSEL_CGROUP_H
#define WESSEL_CGROUP_H
#include <linux/blk-cgroup.h>

#if IS_ENABLED(CONFIG_MQ_IOSCHED_WESSEL_CGROUP)
struct wessel_blkcg {
	struct blkcg_policy_data cpd;

	int max_available_ratio;
};

struct wessel_blkg {
	struct blkg_policy_data pd; 

	atomic_t current_rqs;
	int max_available_rqs;
	unsigned int shallow_depth;
};

extern int wessel_blkcg_init(void);
extern void wessel_blkcg_exit(void);
extern int wessel_blkcg_activate(struct request_queue *q);
extern void wessel_blkcg_deactivate(struct request_queue *q);
extern unsigned int wessel_blkcg_shallow_depth(struct request_queue *q);
extern void wessel_blkcg_depth_updated(struct blk_mq_hw_ctx *hctx);
extern void wessel_blkcg_inc_rq(struct blkcg_gq *blkg);
extern void wessel_blkcg_dec_rq(struct blkcg_gq *blkg);
#else
int wessel_blkcg_init(void)
{
	return 0;
}
void wessel_blkcg_exit(void)
{
}

int wessel_blkcg_activate(struct request_queue *q)
{
	return 0;
}

void wessel_blkcg_deactivate(struct request_queue *q)
{
}

unsigned int wessel_blkcg_shallow_depth(struct request_queue *q)
{
	return 0;
}

void wessel_blkcg_depth_updated(struct blk_mq_hw_ctx *hctx)
{
}

void wessel_blkcg_inc_rq(struct blkcg_gq *blkg)
{
}

void wessel_blkcg_dec_rq(struct blkcg_gq *blkg)
{
}
#endif

#endif


