/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2008-2009 coresystems GmbH
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

#ifndef _BROADWELL_NVS_H_
#define _BROADWELL_NVS_H_

#include <vendorcode/google/chromeos/gnvs.h>
#include <broadwell/device_nvs.h>

typedef struct {
	/* Miscellaneous */
	u16	osys; /* 0x00 - Operating System */
	u8	smif; /* 0x02 - SMI function call ("TRAP") */
	u8	prm0; /* 0x03 - SMI function call parameter */
	u8	prm1; /* 0x04 - SMI function call parameter */
	u8	scif; /* 0x05 - SCI function call (via _L00) */
	u8	prm2; /* 0x06 - SCI function call parameter */
	u8	prm3; /* 0x07 - SCI function call parameter */
	u8	lckf; /* 0x08 - Global Lock function for EC */
	u8	prm4; /* 0x09 - Lock function parameter */
	u8	prm5; /* 0x0a - Lock function parameter */
	u8      pcnt; /* 0x0b - Processor Count */
	u8	ppcm; /* 0x0c - Max PPC State */
	u8	tmps; /* 0x0d - Temperature Sensor ID */
	u8	tlvl; /* 0x0e - Throttle Level Limit */
	u8	flvl; /* 0x0f - Current FAN Level */
	u8	tcrt; /* 0x10 - Critical Threshold */
	u8	tpsv; /* 0x11 - Passive Threshold */
	u8	tmax; /* 0x12 - CPU Tj_max */
	u8	tpmp; /* 0x13 - TPM Present */
	u8	s5u0; /* 0x14 - Enable USB in S5 */
	u8	s3u0; /* 0x15 - Enable USB in S3 */
	u8	s33g; /* 0x16 - Enable 3G in S3 */
	u8	lids; /* 0x17 - LID State */
	u8	pwrs; /* 0x18 - AC Power State */
	u32	obsolete_cmem; /* 0x19 - 0x1c - CBMEM TOC */
	u32	cbmc; /* 0x1d - 0x20 - Coreboot Memory Console */
	u32	pm1i; /* 0x21 - 0x24 - PM1 wake status bit */
	u8	rsvd3[219];

	/* ChromeOS specific (0x100 - 0xfff) */
	chromeos_acpi_t chromeos;

	/* Device specific (0x1000) */
	device_nvs_t dev;
} __attribute__((packed)) global_nvs_t;

void acpi_create_gnvs(global_nvs_t *gnvs);
#ifdef __SMM__
/* Used in SMM to find the ACPI GNVS address */
global_nvs_t *smm_get_gnvs(void);
#endif

#endif
