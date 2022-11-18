/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2012 secunet Security Networks AG
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

// __PRE_RAM__ means: use "unsigned" for device, not a struct.

#include <stdint.h>
#include <string.h>
#include <arch/io.h>
#include <cpu/x86/lapic.h>
#include <cpu/x86/msr.h>
#include <cpu/x86/tsc.h>
#include <cbmem.h>
#include <lib.h>
#include <pc80/mc146818rtc.h>
#include <console/console.h>
#include <southbridge/intel/i82801ix/i82801ix.h>
#include <northbridge/intel/gm45/gm45.h>
#include <cpu/intel/romstage.h>

#define LPC_DEV PCI_DEV(0, 0x1f, 0)
#define MCH_DEV PCI_DEV(0, 0, 0)

static void default_southbridge_gpio_setup(void)
{
	outl(0x197e23fe, DEFAULT_GPIOBASE + 0x00);
	outl(0xe1a66dfe, DEFAULT_GPIOBASE + 0x04);
	outl(0xe3faef3f, DEFAULT_GPIOBASE + 0x0c);

	/* Disable blink [31:0]. */
	outl(0x00000000, DEFAULT_GPIOBASE + 0x18);
	/* Set input inversion [31:0]. */
	outl(0x00000102, DEFAULT_GPIOBASE + 0x2c);

	/* Enable GPIOs [60:32]. */
	outl(0x030306f6, DEFAULT_GPIOBASE + 0x30);
	/* Set input/output mode [60:32] (0 == out, 1 == in). */
	outl(0x1f55f9f1, DEFAULT_GPIOBASE + 0x34);
	/* Set gpio levels [60:32].  */
	outl(0x1dffff53, DEFAULT_GPIOBASE + 0x38);
}

static void early_lpc_setup(void)
{
	/* Set up SuperIO LPC forwards */

	/* Configure serial IRQs.*/
	pci_write_config8(LPC_DEV, D31F0_SERIRQ_CNTL, 0xd0);
	/* Map COMa on 0x3f8, COMb on 0x2f8. */
	pci_write_config16(LPC_DEV, D31F0_LPC_IODEC, 0x0010);
	pci_write_config16(LPC_DEV, D31F0_LPC_EN, 0x3f0f);
	pci_write_config32(LPC_DEV, D31F0_GEN1_DEC, 0x7c1601);
	pci_write_config32(LPC_DEV, D31F0_GEN2_DEC, 0xc15e1);
	pci_write_config32(LPC_DEV, D31F0_GEN3_DEC, 0x1c1681);
}

void main(unsigned long bist)
{
	sysinfo_t sysinfo;
	int s3resume = 0;
	int cbmem_initted;
	u16 reg16;

	/* basic northbridge setup, including MMCONF BAR */
	gm45_early_init();

	if (bist == 0)
		enable_lapic();

	/* First, run everything needed for console output. */
	i82801ix_early_init();
	early_lpc_setup();
	console_init();
	printk(BIOS_DEBUG, "running main(bist = %lu)\n", bist);

	reg16 = pci_read_config16(LPC_DEV, D31F0_GEN_PMCON_3);
	pci_write_config16(LPC_DEV, D31F0_GEN_PMCON_3, reg16);
	if ((MCHBAR16(SSKPD_MCHBAR) == 0xCAFE) && !(reg16 & (1 << 9))) {
		printk(BIOS_DEBUG, "soft reset detected, rebooting properly\n");
		gm45_early_reset();
	}

	default_southbridge_gpio_setup();

	/* ASPM related setting, set early by original BIOS. */
	DMIBAR16(0x204) &= ~(3 << 10);

	/* Check for S3 resume. */
	const u32 pm1_cnt = inl(DEFAULT_PMBASE + 0x04);
	if (((pm1_cnt >> 10) & 7) == 5) {
#if CONFIG_HAVE_ACPI_RESUME
		printk(BIOS_DEBUG, "Resume from S3 detected.\n");
		s3resume = 1;
		/* Clear SLP_TYPE. This will break stage2 but
		 * we care for that when we get there.
		 */
		outl(pm1_cnt & ~(7 << 10), DEFAULT_PMBASE + 0x04);
#else
		printk(BIOS_DEBUG, "Resume from S3 detected, but disabled.\n");
#endif
	}

	/* RAM initialization */
	enter_raminit_or_reset();
	memset(&sysinfo, 0, sizeof(sysinfo));
	sysinfo.spd_map[0] = 0x50;
	sysinfo.spd_map[2] = 0x51;
	sysinfo.enable_igd = 1;
	sysinfo.enable_peg = 0;
	get_gmch_info(&sysinfo);
	raminit(&sysinfo, s3resume);

	const u32 deven = pci_read_config32(MCH_DEV, D0F0_DEVEN);
	/* Disable D4F0 (unknown signal controller). */
	pci_write_config32(MCH_DEV, D0F0_DEVEN, deven & ~0x4000);

	init_pm(&sysinfo, 0);

	i82801ix_dmi_setup();
	gm45_late_init(sysinfo.stepping);
	i82801ix_dmi_poll_vc1();

	MCHBAR16(SSKPD_MCHBAR) = 0xCAFE;
	/* Enable ethernet.  */
	RCBA32(0x3414) &= ~0x20;

	RCBA32(0x0238) = 0x00543210;
	RCBA32(0x0240) = 0x009c0b02;
	RCBA32(0x0244) = 0x00a20b1a;
	RCBA32(0x0248) = 0x005402cb;
	RCBA32(0x0254) = 0x00470966;
	RCBA32(0x0258) = 0x00470473;
	RCBA32(0x0260) = 0x00e90825;
	RCBA32(0x0278) = 0x00bc0efb;
	RCBA32(0x027c) = 0x00c00f0b;
	RCBA32(0x0280) = 0x00670000;
	RCBA32(0x0284) = 0x006d0000;
	RCBA32(0x0288) = 0x00600b4e;
	RCBA32(0x1e10) = 0x00020800;
	RCBA32(0x1e18) = 0x36ea00a0;
	RCBA32(0x1e80) = 0x000c0801;
	RCBA32(0x1e84) = 0x000200f0;
	RCBA32(0x2028) = 0x04c8f95e;
	RCBA32(0x202c) = 0x055c095e;
	RCBA32(0x204c) = 0x001ffc00;
	RCBA32(0x2050) = 0x00100fff;
	RCBA32(0x2090) = 0x37000000;
	RCBA32(0x20b0) = 0x0c000000;
	RCBA32(0x20d0) = 0x09000000;
	RCBA32(0x20f0) = 0x05000000;
	RCBA32(0x3400) = 0x0000001c;
	RCBA32(0x3410) = 0x00100461;
	RCBA32(0x3414) = 0x00000000;
	RCBA32(0x341c) = 0xbf4f001f;
	RCBA32(0x3420) = 0x00000000;
	RCBA32(0x3430) = 0x00000001;

	init_iommu();

	/* FIXME: make a proper SMBUS mux support.  */
	outl(inl(DEFAULT_GPIOBASE + 0x38) & ~0x400, DEFAULT_GPIOBASE + 0x38);

	cbmem_initted = !cbmem_recovery(s3resume);
#if CONFIG_HAVE_ACPI_RESUME
	/* If there is no high memory area, we didn't boot before, so
	 * this is not a resume. In that case we just create the cbmem toc.
	 */
	if (s3resume && cbmem_initted) {
		void *resume_backup_memory = cbmem_find(CBMEM_ID_RESUME);

		/* copy 1MB - 64K to high tables ram_base to prevent memory corruption
		 * through stage 2. We could keep stuff like stack and heap in high tables
		 * memory completely, but that's a wonderful clean up task for another
		 * day.
		 */
		if (resume_backup_memory)
			memcpy(resume_backup_memory, (void *)CONFIG_RAMBASE, HIGH_MEMORY_SAVE);

		/* Magic for S3 resume */
		pci_write_config32(PCI_DEV(0, 0, 0), D0F0_SKPD, SKPAD_ACPI_S3_MAGIC);
	} else {
		/* Magic for S3 resume */
		pci_write_config32(PCI_DEV(0, 0, 0), D0F0_SKPD, SKPAD_NORMAL_BOOT_MAGIC);
	}
#endif
	printk(BIOS_SPEW, "exit main()\n");
}

