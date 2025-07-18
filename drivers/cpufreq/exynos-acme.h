/*
 * Copyright (c) 2016 Park Bumgyu, Samsung Electronics Co., Ltd <bumgyu.park@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Exynos ACME(A Cpufreq that Meets Every chipset) driver implementation
 */

#include <soc/samsung/exynos-dm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>

struct exynos_cpufreq_dm {
	struct list_head		list;
	struct exynos_dm_constraint	c;
	int				master_cal_id;
	int				slave_cal_id;

	bool				multi_table;
};

struct exynos_cpufreq_file_operations {
	struct file_operations		fops;
	struct miscdevice		miscdev;
	struct freq_constraints		*freq_constraints;
	enum				freq_qos_req_type req_type;
	unsigned int			default_value;
};

enum {
	NON_BLOCKING = 0,
	BLOCKING,
};

struct exynos_cpufreq_domain {
	/* list of domain */
	struct list_head		list;

	/* lock */
	struct mutex			lock;

	/* dt node */
	struct device_node		*dn;

	/* domain identity */
	unsigned int			id;
	struct cpumask			cpus;
	unsigned int			cal_id;
	int				dm_type;
	unsigned int			dss_type;

	/* frequency scaling */
	bool				enabled;

	unsigned int			table_size;
	struct cpufreq_frequency_table	*freq_table;

	unsigned int			max_freq;
	unsigned int			min_freq;
	unsigned int			boot_freq;
	unsigned int			resume_freq;
	unsigned int			old;

	/* freq qos */
	struct freq_qos_request		min_qos_req;
	struct freq_qos_request		max_qos_req;
	struct freq_qos_request		user_min_qos_req;
	struct freq_qos_request		user_max_qos_req;
	
	unsigned int			user_default_qos;
	
	struct delayed_work		work;

	/* fops node */
	struct exynos_cpufreq_file_operations	min_qos_fops;
	struct exynos_cpufreq_file_operations	max_qos_fops;

	/* fast-switch */
	bool				fast_switch_possible;
	bool				work_in_progress;
	unsigned int			cached_fast_switch_freq;

	struct irq_work			fast_switch_irq_work;
	struct kthread_work		fast_switch_work;
	struct kthread_worker		fast_switch_worker;
	struct task_struct		*thread;
	raw_spinlock_t			fast_switch_update_lock;

	/* list head of DVFS Manager constraints */
	struct list_head		dm_list;

	bool				dvfs_mode;

	/* per-domain sysfs support */
	struct kobject			kobj;

	/* fake boot freq flag */
	bool				valid_freq_flag;
};

/*
 * the time it takes on this CPU to switch between
 * two frequencies in nanoseconds
 */
#define TRANSITION_LATENCY	5000000
