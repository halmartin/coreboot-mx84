/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2012 Advanced Micro Devices, Inc.
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

#include <stdint.h>
#include <string.h>
#include <device/pci_def.h>
#include <device/pci_ids.h>
#include <arch/acpi.h>
#include <arch/io.h>
#include <arch/stages.h>
#include <device/pnp_def.h>
#include <arch/cpu.h>
#include <cpu/x86/lapic.h>
#include <console/console.h>
#include <console/loglevel.h>
#include <cpu/amd/car.h>
#include <northbridge/amd/pi/agesawrapper.h>
#include <northbridge/amd/pi/agesawrapper_call.h>
#include "cpu/x86/bist.h"
#include "cpu/x86/lapic.h"
#include "southbridge/amd/pi/avalon/hudson.h"
#include "cpu/amd/pi/s3_resume.h"

void cache_as_ram_main(unsigned long bist, unsigned long cpu_init_detectedx)
{
	u32 val;
	volatile int halt = 0;

	/*
	 *  In Hudson RRG, PMIOxD2[5:4] is "Drive strength control for
	 *  LpcClk[1:0]".  This following register setting has been
	 *  replicated in every reference design since Parmer, so it is
	 *  believed to be required even though it is not documented in
	 *  the SoC BKDGs.  Without this setting, there is no serial
	 *  output.
	 */
	outb(0xD2, 0xcd6);
	outb(0x00, 0xcd7);

	AGESAWRAPPER_PRE_CONSOLE(amdinitmmio);

	hudson_lpc_port80();

	if (!cpu_init_detectedx && boot_cpu()) {
		post_code(0x30);

		post_code(0x31);
		console_init();
	}

	if(boot_cpu()) {
		while(halt);
	}
	/* Halt if there was a built in self test failure */
	post_code(0x34);
	report_bist_failure(bist);

	/* Load MPB */
	val = cpuid_eax(1);
	printk(BIOS_DEBUG, "BSP Family_Model: %08x \n", val);
	printk(BIOS_DEBUG, "cpu_init_detectedx = %08lx \n", cpu_init_detectedx);

	/*
	 * This refers to LpcClkDrvSth settling time.  Without this setting, processor
	 * initialization is slow or incorrect, so this wait has been replicated from
	 * earlier development boards.
	 */
	{
		int i;
		for(i = 0; i < 200000; i++) inb(0xCD6);
	}

	post_code(0x37);
	AGESAWRAPPER(amdinitreset);

	post_code(0x38);
	printk(BIOS_DEBUG, "Got past avalon_early_setup\n");

	post_code(0x39);
	AGESAWRAPPER(amdinitearly);
	int s3resume = acpi_is_wakeup_early() && acpi_s3_resume_allowed();
	if (!s3resume) {
		post_code(0x40);
		AGESAWRAPPER(amdinitpost);

		//PspMboxBiosCmdDramInfo();
		post_code(0x41);
		AGESAWRAPPER(amdinitenv);
		/*
		  If code hangs here, please check cahaltasm.S
		*/
		disable_cache_as_ram();
	} else { /* S3 detect */
		printk(BIOS_INFO, "S3 detected\n");

		post_code(0x60);
		AGESAWRAPPER(amdinitresume);

		AGESAWRAPPER(amds3laterestore);

		post_code(0x61);
		prepare_for_resume();
	}

	outb(0xEA, 0xCD6);
	outb(0x1, 0xcd7);

	post_code(0x50);
	copy_and_run();

	post_code(0x54);  /* Should never see this post code. */
}
