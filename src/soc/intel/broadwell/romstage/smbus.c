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

#include <arch/io.h>
#include <console/console.h>
#include <device/pci_ids.h>
#include <device/pci_def.h>
#include <reg_script.h>
#include <broadwell/iomap.h>
#include <broadwell/pci_devs.h>
#include <broadwell/smbus.h>
#include <broadwell/romstage.h>

static const struct reg_script smbus_init_script[] = {
	/* Set SMBUS I/O base address */
	REG_PCI_WRITE32(SMB_BASE, SMBUS_BASE_ADDRESS | 1),
	/* Set SMBUS enable */
	REG_PCI_WRITE8(HOSTC, HST_EN),
	/* Enable I/O access */
	REG_PCI_WRITE16(PCI_COMMAND, PCI_COMMAND_IO),
	/* Disable interrupts */
	REG_IO_WRITE8(SMBUS_BASE_ADDRESS + SMBHSTCTL, 0),
	/* Clear errors */
	REG_IO_WRITE8(SMBUS_BASE_ADDRESS + SMBHSTSTAT, 0xff),
};

void enable_smbus(void)
{
	reg_script_run_on_dev(PCH_DEV_SMBUS, smbus_init_script);
}

int smbus_read_byte(unsigned device, unsigned address)
{
	return do_smbus_read_byte(SMBUS_BASE_ADDRESS, device, address);
}
