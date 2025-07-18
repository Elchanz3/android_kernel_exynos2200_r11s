// SPDX-License-Identifier: GPL-2.0-only
/*
 * Linux VM pressure
 *
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * Based on ideas from Andrew Morton, David Rientjes, KOSAKI Motohiro,
 * Leonid Moiseichuk, Mel Gorman, Minchan Kim and Pekka Enberg.
 */

#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/eventfd.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/printk.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmpressure.h>

#include <trace/hooks/mm.h>

/*
 * These thresholds are used when we account memory pressure through
 * scanned/reclaimed ratio. The current values were chosen empirically. In
 * essence, they are percents: the higher the value, the more number
 * unsuccessful reclaims there were.
 */
static const unsigned int vmpressure_level_med = 60;
static const unsigned int vmpressure_level_critical = 95;

static unsigned long vmpressure_scale_max = 100;

/* vmpressure values >= this will be scaled based on allocstalls */
static unsigned long allocstall_threshold = 70;

static struct vmpressure global_vmpressure;
static BLOCKING_NOTIFIER_HEAD(vmpressure_notifier);

int vmpressure_notifier_register(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&vmpressure_notifier, nb);
}

int vmpressure_notifier_unregister(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&vmpressure_notifier, nb);
}

static void vmpressure_notify(unsigned long pressure)
{
	blocking_notifier_call_chain(&vmpressure_notifier, pressure, NULL);
}

/*
 * When there are too little pages left to scan, vmpressure() may miss the
 * critical pressure as number of pages will be less than "window size".
 * However, in that case the vmscan priority will raise fast as the
 * reclaimer will try to scan LRUs more deeply.
 *
 * The vmscan logic considers these special priorities:
 *
 * prio == DEF_PRIORITY (12): reclaimer starts with that value
 * prio <= DEF_PRIORITY - 2 : kswapd becomes somewhat overwhelmed
 * prio == 0                : close to OOM, kernel scans every page in an lru
 *
 * Any value in this range is acceptable for this tunable (i.e. from 12 to
 * 0). Current value for the vmpressure_level_critical_prio is chosen
 * empirically, but the number, in essence, means that we consider
 * critical level when scanning depth is ~10% of the lru size (vmscan
 * scans 'lru_size >> prio' pages, so it is actually 12.5%, or one
 * eights).
 */
static const unsigned int vmpressure_level_critical_prio = ilog2(100 / 10);

static struct vmpressure *work_to_vmpressure(struct work_struct *work)
{
	return container_of(work, struct vmpressure, work);
}

#ifdef CONFIG_MEMCG
static struct vmpressure *vmpressure_parent(struct vmpressure *vmpr)
{
	struct cgroup_subsys_state *css = vmpressure_to_css(vmpr);
	struct mem_cgroup *memcg = mem_cgroup_from_css(css);

	memcg = parent_mem_cgroup(memcg);
	if (!memcg)
		return NULL;
	return memcg_to_vmpressure(memcg);
}
#else
static struct vmpressure *vmpressure_parent(struct vmpressure *vmpr)
{
	return NULL;
}
#endif

enum vmpressure_levels {
	VMPRESSURE_LOW = 0,
	VMPRESSURE_MEDIUM,
	VMPRESSURE_CRITICAL,
	VMPRESSURE_NUM_LEVELS,
};

enum vmpressure_modes {
	VMPRESSURE_NO_PASSTHROUGH = 0,
	VMPRESSURE_HIERARCHY,
	VMPRESSURE_LOCAL,
	VMPRESSURE_NUM_MODES,
};

static const char * const vmpressure_str_levels[] = {
	[VMPRESSURE_LOW] = "low",
	[VMPRESSURE_MEDIUM] = "medium",
	[VMPRESSURE_CRITICAL] = "critical",
};

static const char * const vmpressure_str_modes[] = {
	[VMPRESSURE_NO_PASSTHROUGH] = "default",
	[VMPRESSURE_HIERARCHY] = "hierarchy",
	[VMPRESSURE_LOCAL] = "local",
};

static enum vmpressure_levels vmpressure_level(unsigned long pressure)
{
	if (pressure >= vmpressure_level_critical)
		return VMPRESSURE_CRITICAL;
	else if (pressure >= vmpressure_level_med)
		return VMPRESSURE_MEDIUM;
	return VMPRESSURE_LOW;
}

static unsigned long vmpressure_calc_pressure(unsigned long scanned,
						    unsigned long reclaimed)
{
	unsigned long scale = scanned + reclaimed;
	unsigned long pressure = 0;

	/*
	 * reclaimed can be greater than scanned for things such as reclaimed
	 * slab pages. shrink_node() just adds reclaimed pages without a
	 * related increment to scanned pages.
	 */
	if (reclaimed >= scanned)
		goto out;
	/*
	 * We calculate the ratio (in percents) of how many pages were
	 * scanned vs. reclaimed in a given time frame (window). Note that
	 * time is in VM reclaimer's "ticks", i.e. number of pages
	 * scanned. This makes it possible to set desired reaction time
	 * and serves as a ratelimit.
	 */
	pressure = scale - (reclaimed * scale / scanned);
	pressure = pressure * 100 / scale;

out:
	pr_debug("%s: %3lu  (s: %lu  r: %lu)\n", __func__, pressure,
		 scanned, reclaimed);

	return pressure;
}

static unsigned long vmpressure_account_stall(unsigned long pressure,
				unsigned long stall, unsigned long scanned)
{
	unsigned long scale;

	if (pressure < allocstall_threshold)
		return pressure;

	scale = ((vmpressure_scale_max - pressure) * stall) / scanned;

	return pressure + scale;
}

struct vmpressure_event {
	struct eventfd_ctx *efd;
	enum vmpressure_levels level;
	enum vmpressure_modes mode;
	struct list_head node;
};

static bool vmpressure_event(struct vmpressure *vmpr,
			     const enum vmpressure_levels level,
			     bool ancestor, bool signalled)
{
	struct vmpressure_event *ev;
	bool ret = false;

	mutex_lock(&vmpr->events_lock);
	list_for_each_entry(ev, &vmpr->events, node) {
		if (ancestor && ev->mode == VMPRESSURE_LOCAL)
			continue;
		if (signalled && ev->mode == VMPRESSURE_NO_PASSTHROUGH)
			continue;
		if (level < ev->level)
			continue;
		eventfd_signal(ev->efd, 1);
		ret = true;
	}
	mutex_unlock(&vmpr->events_lock);

	return ret;
}

static void vmpressure_work_fn(struct work_struct *work)
{
	struct vmpressure *vmpr = work_to_vmpressure(work);
	unsigned long scanned;
	unsigned long reclaimed;
	unsigned long pressure;
	unsigned long flags;
	enum vmpressure_levels level;
	bool ancestor = false;
	bool signalled = false;

	spin_lock_irqsave(&vmpr->sr_lock, flags);
	/*
	 * Several contexts might be calling vmpressure(), so it is
	 * possible that the work was rescheduled again before the old
	 * work context cleared the counters. In that case we will run
	 * just after the old work returns, but then scanned might be zero
	 * here. No need for any locks here since we don't care if
	 * vmpr->reclaimed is in sync.
	 */
	scanned = vmpr->tree_scanned;
	if (!scanned) {
		spin_unlock_irqrestore(&vmpr->sr_lock, flags);
		return;
	}

	reclaimed = vmpr->tree_reclaimed;
	vmpr->tree_scanned = 0;
	vmpr->tree_reclaimed = 0;
	spin_unlock_irqrestore(&vmpr->sr_lock, flags);

	pressure = vmpressure_calc_pressure(scanned, reclaimed);
	level = vmpressure_level(pressure);

	do {
		if (vmpressure_event(vmpr, level, ancestor, signalled))
			signalled = true;
		ancestor = true;
	} while ((vmpr = vmpressure_parent(vmpr)));
}

static unsigned long calculate_vmpressure_win(void)
{
	long x;

	x = global_node_page_state(NR_FILE_PAGES) -
			global_node_page_state(NR_SHMEM) -
			total_swapcache_pages() +
			global_zone_page_state(NR_FREE_PAGES);
	if (x < 1)
		return 1;
	/*
	 * For low (free + cached), vmpressure window should be
	 * small, and high for higher values of (free + cached).
	 * But it should not be linear as well. This ensures
	 * timely vmpressure notifications when system is under
	 * memory pressure, and optimal number of events when
	 * cached is high. The sqaure root function is empirically
	 * found to serve the purpose.
	 */
	return int_sqrt(x);
}

#ifdef CONFIG_MEMCG
static void vmpressure_memcg(gfp_t gfp, struct mem_cgroup *memcg, bool critical,
			     bool tree, unsigned long scanned,
			     unsigned long reclaimed)
{
	struct vmpressure *vmpr;
	unsigned long flags;
	bool bypass = false;

	if (mem_cgroup_disabled())
		return;

	vmpr = memcg_to_vmpressure(memcg);

	trace_android_vh_vmpressure(memcg, &bypass);
	if (unlikely(bypass))
		return;

	/*
	 * If we got here with no pages scanned, then that is an indicator
	 * that reclaimer was unable to find any shrinkable LRUs at the
	 * current scanning depth. But it does not mean that we should
	 * report the critical pressure, yet. If the scanning priority
	 * (scanning depth) goes too high (deep), we will be notified
	 * through vmpressure_prio(). But so far, keep calm.
	 */
	if (critical)
		scanned = calculate_vmpressure_win();
	else if (!scanned)
		return;

	if (tree) {
		spin_lock_irqsave(&vmpr->sr_lock, flags);
		scanned = vmpr->tree_scanned += scanned;
		vmpr->tree_reclaimed += reclaimed;
		spin_unlock_irqrestore(&vmpr->sr_lock, flags);

		if (!critical && scanned < calculate_vmpressure_win())
			return;
		schedule_work(&vmpr->work);
	} else {
		enum vmpressure_levels level;
		unsigned long pressure;

		/* For now, no users for root-level efficiency */
		if (!memcg || mem_cgroup_is_root(memcg))
			return;

		spin_lock_irqsave(&vmpr->sr_lock, flags);
		scanned = vmpr->scanned += scanned;
		reclaimed = vmpr->reclaimed += reclaimed;
		if (!critical && scanned < calculate_vmpressure_win()) {
			spin_unlock_irqrestore(&vmpr->sr_lock, flags);
			return;
		}
		vmpr->scanned = vmpr->reclaimed = 0;
		spin_unlock_irqrestore(&vmpr->sr_lock, flags);

		pressure = vmpressure_calc_pressure(scanned, reclaimed);
		level = vmpressure_level(pressure);

		if (level > VMPRESSURE_LOW) {
			/*
			 * Let the socket buffer allocator know that
			 * we are having trouble reclaiming LRU pages.
			 *
			 * For hysteresis keep the pressure state
			 * asserted for a second in which subsequent
			 * pressure events can occur.
			 */
			memcg->socket_pressure = jiffies + HZ;
		}
	}
}
#else
static void vmpressure_memcg(gfp_t gfp, struct mem_cgroup *memcg, bool critical,
			     bool tree, unsigned long scanned,
			     unsigned long reclaimed) { }
#endif

bool vmpressure_inc_users(int order)
{
	struct vmpressure *vmpr = &global_vmpressure;
	unsigned long flags;

	if (order > PAGE_ALLOC_COSTLY_ORDER)
		return false;

	write_lock_irqsave(&vmpr->users_lock, flags);
	if (atomic_long_inc_return_relaxed(&vmpr->users) == 1) {
		/* Clear out stale vmpressure data when reclaim begins */
		spin_lock(&vmpr->sr_lock);
		vmpr->scanned = 0;
		vmpr->reclaimed = 0;
		vmpr->stall = 0;
		spin_unlock(&vmpr->sr_lock);
	}
	write_unlock_irqrestore(&vmpr->users_lock, flags);

	return true;
}

void vmpressure_dec_users(void)
{
	struct vmpressure *vmpr = &global_vmpressure;

	/* Decrement the vmpressure user count with release semantics */
	smp_mb__before_atomic();
	atomic_long_dec(&vmpr->users);
}

static void vmpressure_global(gfp_t gfp, unsigned long scanned, bool critical,
			      unsigned long reclaimed)
{
	struct vmpressure *vmpr = &global_vmpressure;
	unsigned long pressure;
	unsigned long stall;
	unsigned long flags;

	if (critical)
		scanned = calculate_vmpressure_win();

	spin_lock_irqsave(&vmpr->sr_lock, flags);
	if (scanned) {
		vmpr->scanned += scanned;
		vmpr->reclaimed += reclaimed;

		if (!current_is_kswapd())
			vmpr->stall += scanned;

		stall = vmpr->stall;
		scanned = vmpr->scanned;
		reclaimed = vmpr->reclaimed;

		if (!critical && scanned < calculate_vmpressure_win()) {
			spin_unlock_irqrestore(&vmpr->sr_lock, flags);
			return;
		}
	}
	vmpr->scanned = 0;
	vmpr->reclaimed = 0;
	vmpr->stall = 0;
	spin_unlock_irqrestore(&vmpr->sr_lock, flags);

	if (scanned) {
		pressure = vmpressure_calc_pressure(scanned, reclaimed);
		pressure = vmpressure_account_stall(pressure, stall, scanned);
	} else {
		pressure = 100;
	}
	vmpressure_notify(pressure);
}

static void __vmpressure(gfp_t gfp, struct mem_cgroup *memcg, bool critical,
			 bool tree, unsigned long scanned,
			 unsigned long reclaimed)
{
	if (!memcg && tree)
		vmpressure_global(gfp, scanned, critical, reclaimed);

	if (IS_ENABLED(CONFIG_MEMCG))
		vmpressure_memcg(gfp, memcg, critical, tree, scanned, reclaimed);
}

/**
 * vmpressure() - Account memory pressure through scanned/reclaimed ratio
 * @gfp:	reclaimer's gfp mask
 * @memcg:	cgroup memory controller handle
 * @tree:	legacy subtree mode
 * @scanned:	number of pages scanned
 * @reclaimed:	number of pages reclaimed
 *
 * This function should be called from the vmscan reclaim path to account
 * "instantaneous" memory pressure (scanned/reclaimed ratio). The raw
 * pressure index is then further refined and averaged over time.
 *
 * If @tree is set, vmpressure is in traditional userspace reporting
 * mode: @memcg is considered the pressure root and userspace is
 * notified of the entire subtree's reclaim efficiency.
 *
 * If @tree is not set, reclaim efficiency is recorded for @memcg, and
 * only in-kernel users are notified.
 *
 * This function does not return any value.
 */
void vmpressure(gfp_t gfp, struct mem_cgroup *memcg, bool tree,
		unsigned long scanned, unsigned long reclaimed, int order)
{
	struct vmpressure *vmpr = &global_vmpressure;
	unsigned long flags;

	if (order > PAGE_ALLOC_COSTLY_ORDER)
		return;

	/*
	 * It's possible for kswapd to keep doing reclaim even though memory
	 * pressure isn't high anymore. We should only track vmpressure when
	 * there are failed memory allocations actively stuck in the page
	 * allocator's slow path. No failed allocations means pressure is fine.
	 */
	read_lock_irqsave(&vmpr->users_lock, flags);
	if (!atomic_long_read(&vmpr->users)) {
		read_unlock_irqrestore(&vmpr->users_lock, flags);
		return;
	}
	read_unlock_irqrestore(&vmpr->users_lock, flags);

	__vmpressure(gfp, memcg, false, tree, scanned, reclaimed);
}

/**
 * vmpressure_prio() - Account memory pressure through reclaimer priority level
 * @gfp:	reclaimer's gfp mask
 * @memcg:	cgroup memory controller handle
 * @prio:	reclaimer's priority
 *
 * This function should be called from the reclaim path every time when
 * the vmscan's reclaiming priority (scanning depth) changes.
 *
 * This function does not return any value.
 */
void vmpressure_prio(gfp_t gfp, struct mem_cgroup *memcg, int prio, int order)
{
	if (order > PAGE_ALLOC_COSTLY_ORDER)
		return;

	/*
	 * We only use prio for accounting critical level. For more info
	 * see comment for vmpressure_level_critical_prio variable above.
	 */
	if (prio > vmpressure_level_critical_prio)
		return;

	/*
	 * OK, the prio is below the threshold, updating vmpressure
	 * information before shrinker dives into long shrinking of long
	 * range vmscan. Passing scanned = vmpressure_win, reclaimed = 0
	 * to the vmpressure() basically means that we signal 'critical'
	 * level.
	 */
	__vmpressure(gfp, memcg, true, true, 0, 0);
}

#define MAX_VMPRESSURE_ARGS_LEN	(strlen("critical") + strlen("hierarchy") + 2)

/**
 * vmpressure_register_event() - Bind vmpressure notifications to an eventfd
 * @memcg:	memcg that is interested in vmpressure notifications
 * @eventfd:	eventfd context to link notifications with
 * @args:	event arguments (pressure level threshold, optional mode)
 *
 * This function associates eventfd context with the vmpressure
 * infrastructure, so that the notifications will be delivered to the
 * @eventfd. The @args parameter is a comma-delimited string that denotes a
 * pressure level threshold (one of vmpressure_str_levels, i.e. "low", "medium",
 * or "critical") and an optional mode (one of vmpressure_str_modes, i.e.
 * "hierarchy" or "local").
 *
 * To be used as memcg event method.
 *
 * Return: 0 on success, -ENOMEM on memory failure or -EINVAL if @args could
 * not be parsed.
 */
int vmpressure_register_event(struct mem_cgroup *memcg,
			      struct eventfd_ctx *eventfd, const char *args)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);
	struct vmpressure_event *ev;
	enum vmpressure_modes mode = VMPRESSURE_NO_PASSTHROUGH;
	enum vmpressure_levels level;
	char *spec, *spec_orig;
	char *token;
	int ret = 0;

	spec_orig = spec = kstrndup(args, MAX_VMPRESSURE_ARGS_LEN, GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* Find required level */
	token = strsep(&spec, ",");
	ret = match_string(vmpressure_str_levels, VMPRESSURE_NUM_LEVELS, token);
	if (ret < 0)
		goto out;
	level = ret;

	/* Find optional mode */
	token = strsep(&spec, ",");
	if (token) {
		ret = match_string(vmpressure_str_modes, VMPRESSURE_NUM_MODES, token);
		if (ret < 0)
			goto out;
		mode = ret;
	}

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev) {
		ret = -ENOMEM;
		goto out;
	}

	ev->efd = eventfd;
	ev->level = level;
	ev->mode = mode;

	mutex_lock(&vmpr->events_lock);
	list_add(&ev->node, &vmpr->events);
	mutex_unlock(&vmpr->events_lock);
	ret = 0;
out:
	kfree(spec_orig);
	return ret;
}

/**
 * vmpressure_unregister_event() - Unbind eventfd from vmpressure
 * @memcg:	memcg handle
 * @eventfd:	eventfd context that was used to link vmpressure with the @cg
 *
 * This function does internal manipulations to detach the @eventfd from
 * the vmpressure notifications, and then frees internal resources
 * associated with the @eventfd (but the @eventfd itself is not freed).
 *
 * To be used as memcg event method.
 */
void vmpressure_unregister_event(struct mem_cgroup *memcg,
				 struct eventfd_ctx *eventfd)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);
	struct vmpressure_event *ev;

	mutex_lock(&vmpr->events_lock);
	list_for_each_entry(ev, &vmpr->events, node) {
		if (ev->efd != eventfd)
			continue;
		list_del(&ev->node);
		kfree(ev);
		break;
	}
	mutex_unlock(&vmpr->events_lock);
}

/**
 * vmpressure_init() - Initialize vmpressure control structure
 * @vmpr:	Structure to be initialized
 *
 * This function should be called on every allocated vmpressure structure
 * before any usage.
 */
void vmpressure_init(struct vmpressure *vmpr)
{
	spin_lock_init(&vmpr->sr_lock);
	mutex_init(&vmpr->events_lock);
	INIT_LIST_HEAD(&vmpr->events);
	INIT_WORK(&vmpr->work, vmpressure_work_fn);
	atomic_long_set(&vmpr->users, 0);
	rwlock_init(&vmpr->users_lock);
}

/**
 * vmpressure_cleanup() - shuts down vmpressure control structure
 * @vmpr:	Structure to be cleaned up
 *
 * This function should be called before the structure in which it is
 * embedded is cleaned up.
 */
void vmpressure_cleanup(struct vmpressure *vmpr)
{
	/*
	 * Make sure there is no pending work before eventfd infrastructure
	 * goes away.
	 */
	flush_work(&vmpr->work);
}

static int vmpressure_global_init(void)
{
	vmpressure_init(&global_vmpressure);
	return 0;
}
late_initcall(vmpressure_global_init);
