/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2007-2009 coresystems GmbH
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

#include <types.h>
#include <string.h>
#include <cbmem.h>
#include <console/console.h>
#include <arch/acpi.h>
#include <arch/ioapic.h>
#include <arch/acpigen.h>
#include <arch/smp/mpspec.h>
#include <device/device.h>
#include <device/pci.h>
#include <device/pci_ids.h>
#include <cpu/x86/msr.h>
#include <vendorcode/google/chromeos/gnvs.h>

#include "southbridge/intel/bd82x6x/nvs.h"
#include "thermal.h"

static global_nvs_t *gnvs_;

static void acpi_update_thermal_table(global_nvs_t *gnvs)
{
	gnvs->f4of = FAN4_THRESHOLD_OFF;
	gnvs->f4on = FAN4_THRESHOLD_ON;
	gnvs->f4pw = FAN4_PWM;

	gnvs->f3of = FAN3_THRESHOLD_OFF;
	gnvs->f3on = FAN3_THRESHOLD_ON;
	gnvs->f3pw = FAN3_PWM;

	gnvs->f2of = FAN2_THRESHOLD_OFF;
	gnvs->f2on = FAN2_THRESHOLD_ON;
	gnvs->f2pw = FAN2_PWM;

	gnvs->f1of = FAN1_THRESHOLD_OFF;
	gnvs->f1on = FAN1_THRESHOLD_ON;
	gnvs->f1pw = FAN1_PWM;

	gnvs->f0of = FAN0_THRESHOLD_OFF;
	gnvs->f0on = FAN0_THRESHOLD_ON;
	gnvs->f0pw = FAN0_PWM;

	gnvs->tcrt = CRITICAL_TEMPERATURE;
	gnvs->tpsv = PASSIVE_TEMPERATURE;
	gnvs->tmax = MAX_TEMPERATURE;
	gnvs->flvl = 5;
}

void acpi_create_gnvs(global_nvs_t *gnvs)
{
	gnvs_ = gnvs;

	/* Enable Front USB ports in S3 by default */
	gnvs->s3u0 = 1;
	gnvs->s3u1 = 1;

	/*
	 * Enable Front USB ports in S5 by default
	 * to be consistent with back port behavior
	 */
	gnvs->s5u0 = 1;
	gnvs->s5u1 = 1;

	/* IGD Displays */
	gnvs->ndid = 3;
	gnvs->did[0] = 0x80000100;
	gnvs->did[1] = 0x80000240;
	gnvs->did[2] = 0x80000410;
	gnvs->did[3] = 0x80000410;
	gnvs->did[4] = 0x00000005;

	acpi_update_thermal_table(gnvs);

	// Stumpy has no arms^H^H^H^HEC.
	gnvs->chromeos.vbt2 = ACTIVE_ECFW_RO;
}

unsigned long acpi_fill_slit(unsigned long current)
{
	// Not implemented
	return current;
}

unsigned long acpi_fill_srat(unsigned long current)
{
	/* No NUMA, no SRAT */
	return current;
}
