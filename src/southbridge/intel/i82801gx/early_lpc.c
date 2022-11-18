/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2008-2009 coresystems GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of
 * the License.
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

#include <arch/io.h>
#include <timestamp.h>
#include <console/console.h>
#include <arch/acpi.h>
#include "i82801gx.h"

#if CONFIG_COLLECT_TIMESTAMPS
tsc_t get_initial_timestamp(void)
{
	tsc_t base_time = {
		.lo = pci_read_config32(PCI_DEV(0, 0x00, 0), 0xdc),
		.hi = pci_read_config32(PCI_DEV(0, 0x1f, 2), 0xd0)
	};
	return base_time;
}
#endif

int southbridge_detect_s3_resume(void)
{
	u32 reg32;

	/* Read PM1_CNT */
	reg32 = inl(DEFAULT_PMBASE + 0x04);
	printk(BIOS_DEBUG, "PM1_CNT: %08x\n", reg32);
	if (((reg32 >> 10) & 7) == 5) {
		if (acpi_s3_resume_allowed()) {
			printk(BIOS_DEBUG, "Resume from S3 detected.\n");
			/* Clear SLP_TYPE. This will break stage2 but
			 * we care for that when we get there.
			 */
			outl(reg32 & ~(7 << 10), DEFAULT_PMBASE + 0x04);
			return 1;
		} else {
			printk(BIOS_DEBUG, "Resume from S3 detected, but disabled.\n");
		}
	}

	return 0;
}
