# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel block layer
#

obj-$(CONFIG_BLOCK) := bio.o elevator.o blk-core.o blk-sysfs.o \
			blk-flush.o blk-settings.o blk-ioc.o blk-map.o \
			blk-exec.o blk-merge.o blk-timeout.o \
			blk-lib.o blk-mq.o blk-mq-tag.o blk-stat.o \
			blk-mq-sysfs.o blk-mq-cpumap.o blk-mq-sched.o ioctl.o \
			genhd.o ioprio.o badblocks.o partitions/ blk-rq-qos.o

obj-$(CONFIG_BOUNCE)		+= bounce.o
obj-$(CONFIG_BLK_SCSI_REQUEST)	+= scsi_ioctl.o
obj-$(CONFIG_BLK_DEV_BSG)	+= bsg.o
obj-$(CONFIG_BLK_DEV_BSGLIB)	+= bsg-lib.o
obj-$(CONFIG_BLK_CGROUP)	+= blk-cgroup.o
obj-$(CONFIG_BLK_CGROUP_RWSTAT)	+= blk-cgroup-rwstat.o
obj-$(CONFIG_BLK_DEV_THROTTLING)	+= blk-throttle.o
obj-$(CONFIG_BLK_CGROUP_IOPRIO)	+= blk-ioprio.o
obj-$(CONFIG_BLK_CGROUP_IOLATENCY)	+= blk-iolatency.o
obj-$(CONFIG_BLK_CGROUP_IOCOST)	+= blk-iocost.o
obj-$(CONFIG_MQ_IOSCHED_DEADLINE)	+= mq-deadline.o
mq-deadline-y += mq-deadline-main.o
mq-deadline-$(CONFIG_MQ_IOSCHED_DEADLINE_CGROUP)+= mq-deadline-cgroup.o
obj-$(CONFIG_MQ_IOSCHED_KYBER)	+= kyber-iosched.o
bfq-y				:= bfq-iosched.o bfq-wf2q.o bfq-cgroup.o
obj-$(CONFIG_IOSCHED_BFQ)	+= bfq.o
ssg-$(CONFIG_MQ_IOSCHED_SSG)	:= ssg-iosched.o
ssg-$(CONFIG_MQ_IOSCHED_SSG_CGROUP)	+= ssg-cgroup.o
obj-$(CONFIG_MQ_IOSCHED_SSG)	+= ssg.o

wessel-$(CONFIG_MQ_IOSCHED_WESSEL)	:= wessel-iosched.o
wessel-$(CONFIG_MQ_IOSCHED_WESSEL_CGROUP)	+= wessel-cgroup.o
obj-$(CONFIG_MQ_IOSCHED_WESSEL)	+= wessel.o

obj-$(CONFIG_BLK_CMDLINE_PARSER)	+= cmdline-parser.o
obj-$(CONFIG_BLK_DEV_INTEGRITY) += bio-integrity.o blk-integrity.o
obj-$(CONFIG_BLK_DEV_INTEGRITY_T10)	+= t10-pi.o
obj-$(CONFIG_BLK_MQ_PCI)	+= blk-mq-pci.o
obj-$(CONFIG_BLK_MQ_VIRTIO)	+= blk-mq-virtio.o
obj-$(CONFIG_BLK_MQ_RDMA)	+= blk-mq-rdma.o
obj-$(CONFIG_BLK_DEV_ZONED)	+= blk-zoned.o
obj-$(CONFIG_BLK_WBT)		+= blk-wbt.o
obj-$(CONFIG_BLK_DEBUG_FS)	+= blk-mq-debugfs.o
obj-$(CONFIG_BLK_DEBUG_FS_ZONED)+= blk-mq-debugfs-zoned.o
obj-$(CONFIG_BLK_SED_OPAL)	+= sed-opal.o
obj-$(CONFIG_BLK_PM)		+= blk-pm.o
obj-$(CONFIG_BLK_INLINE_ENCRYPTION)	+= keyslot-manager.o blk-crypto.o
obj-$(CONFIG_BLK_INLINE_ENCRYPTION_FALLBACK)	+= blk-crypto-fallback.o
obj-$(CONFIG_BLK_SEC_STATS)	+= blk-sec-stats.o

ifdef CONFIG_SEC_KUNIT
GCOV_PROFILE_blk-sec-stats.o	:=y
endif
