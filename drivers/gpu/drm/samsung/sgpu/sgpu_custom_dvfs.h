/*
 * @file sgpu_custom_dvfs.h
 *
 * Custom DVFS table definitions.
 */

#ifndef _SGPU_CUSTOM_DVFS_H_
#define _SGPU_CUSTOM_DVFS_H_

#include <linux/types.h>

struct custom_dvfs_info {
	unsigned long freq;
	unsigned long volt;
};

#define CUSTOM_DVFS_TABLE_SIZE 12

extern const struct custom_dvfs_info custom_dvfs_table[CUSTOM_DVFS_TABLE_SIZE];

#endif /* _SGPU_CUSTOM_DVFS_H_ */


