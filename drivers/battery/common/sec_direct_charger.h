/*
 * sec_direct_charger.h
 * Samsung Mobile Charger Header
 *
 * Copyright (C) 2018 Samsung Electronics, Inc.
 *
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __SEC_DIRECT_CHARGER_H
#define __SEC_DIRECT_CHARGER_H __FILE__

#include "sec_battery.h"
#include "sec_charging_common.h"
#include "sb_pass_through.h"

#define SEC_DIRECT_CHG_MIN_IOUT			2000
#define SEC_DIRECT_CHG_MIN_VBAT			3500
#define SEC_DIRECT_CHG_MAX_VBAT			4200
#define FPDO_DC_MIN_VBAT			3500
#define FPDO_DC_MAX_VBAT			5000
#if IS_ENABLED(CONFIG_SEC_ABC)
#define ABC_DC_CNT	5
#endif

typedef enum _sec_direct_chg_src {
	SEC_CHARGING_SOURCE_SWITCHING = 0,
	SEC_CHARGING_SOURCE_DIRECT,
} sec_direct_chg_src_t;

typedef enum _sec_direct_chg_mode {
	SEC_DIRECT_CHG_MODE_DIRECT_OFF = 0,
	SEC_DIRECT_CHG_MODE_DIRECT_CHECK_VBAT,
	SEC_DIRECT_CHG_MODE_DIRECT_PRESET,
	SEC_DIRECT_CHG_MODE_DIRECT_ON_ADJUST,
	SEC_DIRECT_CHG_MODE_DIRECT_ON,
	SEC_DIRECT_CHG_MODE_DIRECT_DONE,
	SEC_DIRECT_CHG_MODE_DIRECT_BYPASS,
	SEC_DIRECT_CHG_MODE_MAX,
} sec_direct_chg_mode_t;

enum {
	LOW_VBAT_SET = 0,
	LOW_VBAT_NONE,
	LOW_VBAT_OFF,
};

enum {
	DC_NORMAL_MODE = 0,
	DC_BYPASS_MODE,
};

#define is_direct_chg_mode_on(direct_chg_mode) ( \
	direct_chg_mode == SEC_DIRECT_CHG_MODE_DIRECT_PRESET || \
	direct_chg_mode == SEC_DIRECT_CHG_MODE_DIRECT_ON) || \
	direct_chg_mode == SEC_DIRECT_CHG_MODE_DIRECT_ON_ADJUST

struct sec_direct_charger_platform_data {
	char *battery_name;
	char *main_charger_name;
	char *direct_charger_name;
	char *direct_sub_charger_name;

	int dchg_min_current;
	int dchg_min_vbat;
	int dchg_temp_low_threshold;
	int dchg_temp_high_threshold;
	int dchg_end_soc;
	int dchg_dc_in_swelling;
	int swelling_high_rechg_voltage;
	int fpdo_dc_min_vbat;
	int fpdo_dc_max_vbat;
#if IS_ENABLED(CONFIG_DUAL_BATTERY)
	int fpdo_dc_max_main_vbat;
	int fpdo_dc_max_sub_vbat;
#endif
	bool chgen_over_swell_rechg_vol;
};

struct sec_direct_charger_info {
	struct device *dev;
	struct sec_direct_charger_platform_data *pdata;
	struct power_supply*	psy_chg;
	struct mutex charger_mutex;

	struct sb_pt	*pt;

	sec_direct_chg_mode_t direct_chg_mode;
	unsigned int charger_mode;
	unsigned int charger_mode_main;
	unsigned int charger_mode_direct;
	unsigned int dc_retry_cnt;

	int cable_type;
	int input_current;
	int charging_current;
	int topoff_current;
	int float_voltage;
	bool dc_err;
	bool ta_alert_wa;
	int ta_alert_mode;
	bool is_charging;
	int batt_status;
	int capacity;
	bool direct_chg_done;
	bool wc_tx_enable;
	bool now_isApdo;
	bool store_mode;
	int vbat_min_src;
	bool dc_rcp;

	int bat_temp;

	sec_direct_chg_src_t charging_source;
	int fpdo_pos;
	int dc_input_current;
	int dc_charging_current;
	int test_mode_source;
#if IS_ENABLED(CONFIG_SEC_ABC)
	int abc_dc_current_cnt;
#endif
	bool dc_err_test;
};
#endif /* __SEC_DIRECT_CHARGER_H */
