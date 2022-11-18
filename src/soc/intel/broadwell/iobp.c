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

#include <console/console.h>
#include <delay.h>
#include <arch/io.h>
#include <broadwell/iobp.h>
#include <broadwell/rcba.h>

#define IOBP_RETRY 1000

static inline int iobp_poll(void)
{
	unsigned try;

	for (try = IOBP_RETRY; try > 0; try--) {
		u16 status = RCBA16(IOBPS);
		if ((status & IOBPS_READY) == 0)
			return 1;
		udelay(10);
	}

	printk(BIOS_ERR, "IOBP: timeout waiting for transaction to complete\n");
	return 0;
}

u32 pch_iobp_read(u32 address)
{
	u16 status;

	if (!iobp_poll())
		return 0;

	/* Set the address */
	RCBA32(IOBPIRI) = address;

	/* READ OPCODE */
	status = RCBA16(IOBPS);
	status &= ~IOBPS_MASK;
	status |= IOBPS_READ;
	RCBA16(IOBPS) = status;

	/* Undocumented magic */
	RCBA16(IOBPU) = IOBPU_MAGIC;

	/* Set ready bit */
	status = RCBA16(IOBPS);
	status |= IOBPS_READY;
	RCBA16(IOBPS) = status;

	if (!iobp_poll())
		return 0;

	/* Check for successful transaction */
	status = RCBA16(IOBPS);
	if (status & IOBPS_TX_MASK) {
		printk(BIOS_ERR, "IOBP: read 0x%08x failed\n", address);
		return 0;
	}

	/* Read IOBP data */
	return RCBA32(IOBPD);
}

void pch_iobp_write(u32 address, u32 data)
{
	u16 status;

	if (!iobp_poll())
		return;

	/* Set the address */
	RCBA32(IOBPIRI) = address;

	/* WRITE OPCODE */
	status = RCBA16(IOBPS);
	status &= ~IOBPS_MASK;
	status |= IOBPS_WRITE;
	RCBA16(IOBPS) = status;

	RCBA32(IOBPD) = data;

	/* Undocumented magic */
	RCBA16(IOBPU) = IOBPU_MAGIC;

	/* Set ready bit */
	status = RCBA16(IOBPS);
	status |= IOBPS_READY;
	RCBA16(IOBPS) = status;

	if (!iobp_poll())
		return;

	/* Check for successful transaction */
	status = RCBA16(IOBPS);
	if (status & IOBPS_TX_MASK)
		printk(BIOS_ERR, "IOBP: write 0x%08x failed\n", address);
}

void pch_iobp_update(u32 address, u32 andvalue, u32 orvalue)
{
	u32 data = pch_iobp_read(address);

	/* Update the data */
	data &= andvalue;
	data |= orvalue;

	pch_iobp_write(address, data);
}
