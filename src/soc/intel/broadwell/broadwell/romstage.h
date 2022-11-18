/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2014 Google Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _BROADWELL_ROMSTAGE_H_
#define _BROADWELL_ROMSTAGE_H_

#include <stdint.h>
#include <arch/cpu.h>

#define NUM_ROMSTAGE_TS 4
struct romstage_timestamps {
	uint64_t times[NUM_ROMSTAGE_TS];
	int count;
};

struct chipset_power_state;
struct pei_data;
struct romstage_params {
	struct romstage_timestamps ts;
	unsigned long bist;
	struct chipset_power_state *power_state;
	struct pei_data *pei_data;
};

void mainboard_romstage_entry(struct romstage_params *params);
void romstage_common(struct romstage_params *params);
void *asmlinkage romstage_main(unsigned long bist, uint32_t tsc_lo,
			       uint32_t tsc_high);
void asmlinkage romstage_after_car(void);
void raminit(struct pei_data *pei_data);
void *setup_stack_and_mttrs(void);

struct chipset_power_state;
struct chipset_power_state *fill_power_state(void);
void report_platform_info(void);
void report_memory_config(void);

void set_max_freq(void);

void systemagent_early_init(void);
void pch_early_init(void);
void pch_uart_init(void);
void intel_early_me_status(void);

void enable_smbus(void);
int smbus_read_byte(unsigned device, unsigned address);

int early_spi_read(u32 offset, u32 size, u8 *buffer);
int early_spi_read_wpsr(u8 *sr);

#endif
