/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2014 Edward O'Callaghan <eocallaghan@alterapraxis.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <device/pnp.h>
#include <stdint.h>
#include "fintek.h"

static u8 f81216h_entry_key;
#define FINTEK_EXIT_KEY 0xAA

static void pnp_enter_conf_state(pnp_devfn_t dev)
{
	u16 port = dev >> 8;
	outb(f81216h_entry_key, port);
	outb(f81216h_entry_key, port);
}

static void pnp_exit_conf_state(pnp_devfn_t dev)
{
	u16 port = dev >> 8;
	outb(FINTEK_EXIT_KEY, port);
}

/* Bring up early serial debugging output before the RAM is initialized. */
void f81216h_enable_serial(pnp_devfn_t dev, u16 iobase, enum mode_key k)
{
	switch(k) {
	MODE_6767:
		f81216h_entry_key = 0x67;
		break;
	MODE_7777:
		f81216h_entry_key = 0x77;
		break;
	MODE_8787:
		f81216h_entry_key = 0x87;
		break;
	MODE_A0A0:
		f81216h_entry_key = 0xa0;
		break;
	default:
		f81216h_entry_key = 0x77; /* (safe to be hw default) */
	}

	pnp_enter_conf_state(dev);
	pnp_set_logical_device(dev);
	pnp_set_enable(dev, 0);
	pnp_set_iobase(dev, PNP_IDX_IO0, iobase);
	pnp_set_enable(dev, 1);
	pnp_exit_conf_state(dev);
}
