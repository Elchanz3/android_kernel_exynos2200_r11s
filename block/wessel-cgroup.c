// SPDX-License-Identifier: GPL-2.0
/*
 *  Control Group of Wessel I/O scheduler
 *
 *  Copyright (C) 2025 Elchanz3 <inutilidades639@gmail.com>
 *
 */

#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include "blk-mq.h"
#include "blk-mq-tag.h"
#include "wessel-cgroup.h"



static struct blkcg_policy wessel_blkcg_policy;



#define CPD_TO_WESSEL_BLKCG(_cpd) \
	container_of_safe((_cpd), struct wessel_blkcg, cpd)
#define BLKCG_TO_WESSEL_BLKCG(_blkcg) \
	CPD_TO_WESSEL_BLKCG(blkcg_to_cpd((_blkcg), &wessel_blkcg_policy))

#define PD_TO_WESSEL_BLKG(_pd) \
	container_of_safe((_pd), struct wessel_blkg, pd)
#define BLKG_TO_WESSEL_BLKG(_blkg) \
	PD_TO_WESSEL_BLKG(blkg_to_pd((_blkg), &wessel_blkcg_policy))

#define CSS_TO_WESSEL_BLKCG(css) BLKCG_TO_WESSEL_BLKCG(css_to_blkcg(css))



static struct blkcg_policy_data *wessel_blkcg_cpd_alloc(gfp_t gfp)
{
	struct wessel_blkcg *wessel_blkcg;

	wessel_blkcg = kzalloc(sizeof(struct wessel_blkcg), gfp);
	if (ZERO_OR_NULL_PTR(wessel_blkcg))
		return NULL;

	return &wessel_blkcg->cpd;
}

static void wessel_blkcg_cpd_init(struct blkcg_policy_data *cpd)
{
	struct wessel_blkcg *wessel_blkcg = CPD_TO_WESSEL_BLKCG(cpd);

	if (IS_ERR_OR_NULL(wessel_blkcg))
		return;

	wessel_blkcg->max_available_ratio = 100;
}

static void wessel_blkcg_cpd_free(struct blkcg_policy_data *cpd)
{
	struct wessel_blkcg *wessel_blkcg = CPD_TO_WESSEL_BLKCG(cpd);

	if (IS_ERR_OR_NULL(wessel_blkcg))
		return;

	kfree(wessel_blkcg);
}

static void wessel_blkcg_set_shallow_depth(struct wessel_blkcg *wessel_blkcg,
		struct wessel_blkg *wessel_blkg, struct blk_mq_tags *tags)
{
	unsigned int depth = tags->bitmap_tags->sb.depth;
	unsigned int map_nr = tags->bitmap_tags->sb.map_nr;

	wessel_blkg->max_available_rqs =
		depth * wessel_blkcg->max_available_ratio / 100U;
	wessel_blkg->shallow_depth =
		max_t(unsigned int, 1, wessel_blkg->max_available_rqs / map_nr);
}

static struct blkg_policy_data *wessel_blkcg_pd_alloc(gfp_t gfp,
		struct request_queue *q, struct blkcg *blkcg)
{
	struct wessel_blkg *wessel_blkg;

	wessel_blkg = kzalloc_node(sizeof(struct wessel_blkg), gfp, q->node);
	if (ZERO_OR_NULL_PTR(wessel_blkg))
		return NULL;

	return &wessel_blkg->pd;
}

static void wessel_blkcg_pd_init(struct blkg_policy_data *pd)
{
	struct wessel_blkg *wessel_blkg;
	struct wessel_blkcg *wessel_blkcg;

	wessel_blkg = PD_TO_WESSEL_BLKG(pd);
	if (IS_ERR_OR_NULL(wessel_blkg))
		return;

	wessel_blkcg = BLKCG_TO_WESSEL_BLKCG(pd->blkg->blkcg);
	if (IS_ERR_OR_NULL(wessel_blkcg))
		return;

	atomic_set(&wessel_blkg->current_rqs, 0);
	wessel_blkcg_set_shallow_depth(wessel_blkcg, wessel_blkg,
			pd->blkg->q->queue_hw_ctx[0]->sched_tags);
}

static void wessel_blkcg_pd_free(struct blkg_policy_data *pd)
{
	struct wessel_blkg *wessel_blkg = PD_TO_WESSEL_BLKG(pd);

	if (IS_ERR_OR_NULL(wessel_blkg))
		return;

	kfree(wessel_blkg);
}

unsigned int wessel_blkcg_shallow_depth(struct request_queue *q)
{
	struct blkcg_gq *blkg;
	struct wessel_blkg *wessel_blkg;

	rcu_read_lock();
	blkg = blkg_lookup(css_to_blkcg(blkcg_css()), q);
	wessel_blkg = BLKG_TO_WESSEL_BLKG(blkg);
	rcu_read_unlock();

	if (IS_ERR_OR_NULL(wessel_blkg))
		return 0;

	if (atomic_read(&wessel_blkg->current_rqs) < wessel_blkg->max_available_rqs)
		return 0;

	return wessel_blkg->shallow_depth;
}

void wessel_blkcg_depth_updated(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct cgroup_subsys_state *pos_css;
	struct blkcg_gq *blkg;
	struct wessel_blkg *wessel_blkg;
	struct wessel_blkcg *wessel_blkcg;

	rcu_read_lock();
	blkg_for_each_descendant_pre(blkg, pos_css, q->root_blkg) {
		wessel_blkg = BLKG_TO_WESSEL_BLKG(blkg);
		if (IS_ERR_OR_NULL(wessel_blkg))
			continue;

		wessel_blkcg = BLKCG_TO_WESSEL_BLKCG(blkg->blkcg);
		if (IS_ERR_OR_NULL(wessel_blkcg))
			continue;

		atomic_set(&wessel_blkg->current_rqs, 0);
		wessel_blkcg_set_shallow_depth(wessel_blkcg, wessel_blkg, hctx->sched_tags);
	}
	rcu_read_unlock();
}

void wessel_blkcg_inc_rq(struct blkcg_gq *blkg)
{
	struct wessel_blkg *wessel_blkg = BLKG_TO_WESSEL_BLKG(blkg);

	if (IS_ERR_OR_NULL(wessel_blkg))
		return;

	atomic_inc(&wessel_blkg->current_rqs);
}

void wessel_blkcg_dec_rq(struct blkcg_gq *blkg)
{
	struct wessel_blkg *wessel_blkg = BLKG_TO_WESSEL_BLKG(blkg);

	if (IS_ERR_OR_NULL(wessel_blkg))
		return;

	atomic_dec(&wessel_blkg->current_rqs);
}

static int wessel_blkcg_show_max_available_ratio(struct seq_file *sf, void *v)
{
	struct wessel_blkcg *wessel_blkcg = CSS_TO_WESSEL_BLKCG(seq_css(sf));

	if (IS_ERR_OR_NULL(wessel_blkcg))
		return -EINVAL;

	seq_printf(sf, "%d\n", wessel_blkcg->max_available_ratio);

	return 0;
}

static int wessel_blkcg_set_max_available_ratio(struct cgroup_subsys_state *css,
		struct cftype *cftype, u64 ratio)
{
	struct blkcg *blkcg = css_to_blkcg(css);
	struct wessel_blkcg *wessel_blkcg = CSS_TO_WESSEL_BLKCG(css);
	struct blkcg_gq *blkg;
	struct wessel_blkg *wessel_blkg;

	if (IS_ERR_OR_NULL(wessel_blkcg))
		return -EINVAL;

	if (ratio > 100)
		return -EINVAL;

	spin_lock_irq(&blkcg->lock);
	wessel_blkcg->max_available_ratio = ratio;
	hlist_for_each_entry(blkg, &blkcg->blkg_list, blkcg_node) {
		wessel_blkg = BLKG_TO_WESSEL_BLKG(blkg);
		if (IS_ERR_OR_NULL(wessel_blkg))
			continue;

		wessel_blkcg_set_shallow_depth(wessel_blkcg, wessel_blkg,
				blkg->q->queue_hw_ctx[0]->sched_tags);
	}
	spin_unlock_irq(&blkcg->lock);

	return 0;
}

struct cftype wessel_blkg_files[] = {
	{
		.name = "wessel.max_available_ratio",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = wessel_blkcg_show_max_available_ratio,
		.write_u64 = wessel_blkcg_set_max_available_ratio,
	},

	{} /* terminate */
};

static struct blkcg_policy wessel_blkcg_policy = {
	.legacy_cftypes = wessel_blkg_files,

	.cpd_alloc_fn = wessel_blkcg_cpd_alloc,
	.cpd_init_fn = wessel_blkcg_cpd_init,
	.cpd_free_fn = wessel_blkcg_cpd_free,

	.pd_alloc_fn = wessel_blkcg_pd_alloc,
	.pd_init_fn = wessel_blkcg_pd_init,
	.pd_free_fn = wessel_blkcg_pd_free,
};

int wessel_blkcg_activate(struct request_queue *q)
{
	return blkcg_activate_policy(q, &wessel_blkcg_policy);
}

void wessel_blkcg_deactivate(struct request_queue *q)
{
	blkcg_deactivate_policy(q, &wessel_blkcg_policy);
}

int wessel_blkcg_init(void)
{
	return blkcg_policy_register(&wessel_blkcg_policy);
}

void wessel_blkcg_exit(void)
{
	blkcg_policy_unregister(&wessel_blkcg_policy);
}


