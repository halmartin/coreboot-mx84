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
#include <cpu/cpu.h>
#include <cpu/x86/msr.h>
#include <vendorcode/google/chromeos/gnvs.h>
#include <ec/google/chromeec/ec.h>

#include <northbridge/intel/sandybridge/sandybridge.h>
#include <southbridge/intel/bd82x6x/pch.h>
#include <southbridge/intel/bd82x6x/nvs.h>
#include "thermal.h"

static void acpi_update_thermal_table(global_nvs_t *gnvs)
{
	gnvs->tmps = CTDP_SENSOR_ID;

	gnvs->f1of = CTDP_NOMINAL_THRESHOLD_OFF;
	gnvs->f1on = CTDP_NOMINAL_THRESHOLD_ON;

	gnvs->f0of = CTDP_DOWN_THRESHOLD_OFF;
	gnvs->f0on = CTDP_DOWN_THRESHOLD_ON;

	gnvs->tcrt = CRITICAL_TEMPERATURE;
	gnvs->tpsv = PASSIVE_TEMPERATURE;
	gnvs->tmax = MAX_TEMPERATURE;
	gnvs->flvl = 1;
}

void acpi_create_gnvs(global_nvs_t *gnvs)
{
	/* Disable USB ports in S3 by default */
	gnvs->s3u0 = 0;
	gnvs->s3u1 = 0;

	/* Disable USB ports in S5 by default */
	gnvs->s5u0 = 0;
	gnvs->s5u1 = 0;

	/* IGD Displays */
	gnvs->ndid = 1;
	gnvs->did[0] = 0x80000000;
	gnvs->did[1] = 0x80000000;
	gnvs->did[2] = 0x00000000;
	gnvs->did[3] = 0x00000000;
	gnvs->did[4] = 0x00000000;

#if CONFIG_CHROMEOS
	gnvs->chromeos.vbt2 = google_ec_running_ro() ?
		ACTIVE_ECFW_RO : ACTIVE_ECFW_RW;
#endif

	acpi_update_thermal_table(gnvs);

	// the lid is open by default.
	gnvs->lids = 1;
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
