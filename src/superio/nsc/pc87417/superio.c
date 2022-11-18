/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2000 AG Electronics Ltd.
 * Copyright (C) 2003-2004 Linux Networx
 * Copyright (C) 2004 Tyan
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
#include <device/device.h>
#include <device/pnp.h>
#include <console/console.h>
#include <string.h>
#include <pc80/keyboard.h>
#include <stdlib.h>
#include "pc87417.h"

static void init(struct device *dev)
{

	if (!dev->enabled)
		return;

	switch(dev->path.pnp.device) {
	case PC87417_KBCK:
		pc_keyboard_init();
		break;
	}
}

static struct device_operations ops = {
	.read_resources   = pnp_read_resources,
	.set_resources    = pnp_set_resources,
	.enable_resources = pnp_enable_resources,
	.enable           = pnp_enable,
	.init             = init,
};

static struct pnp_info pnp_dev_info[] = {
	{ &ops, PC87417_FDC,  PNP_IO0 | PNP_IRQ0 | PNP_DRQ0, {0x07fa, 0}, },
	{ &ops, PC87417_PP,   PNP_IO0 | PNP_IRQ0 | PNP_DRQ0, {0x04f8, 0}, },
	{ &ops, PC87417_SP2,  PNP_IO0 | PNP_IRQ0 | PNP_DRQ0 | PNP_DRQ1, {0x07f8, 0}, },
	{ &ops, PC87417_SP1,  PNP_IO0 | PNP_IRQ0, {0x07f8, 0}, },
	{ &ops, PC87417_SWC,  PNP_IO0 | PNP_IRQ0, {0xfff0, 0}, },
	{ &ops, PC87417_KBCM, PNP_IRQ0, },
	{ &ops, PC87417_KBCK, PNP_IO0 | PNP_IO1 | PNP_IRQ0, {0x07f8, 0}, {0x07f8, 4}, },
	{ &ops, PC87417_GPIO, PNP_IO0 | PNP_IRQ0, {0xfff8, 0}, },
	{ &ops, PC87417_XBUS, PNP_IO0 | PNP_IRQ0, {0xffe0, 0}, },
	{ &ops, PC87417_RTC,  PNP_IO0 | PNP_IO1, {0xfffe, 0}, {0xfffe, 4}, },
};

static void enable_dev(struct device *dev)
{
	pnp_enable_devices(dev, &pnp_ops,
		ARRAY_SIZE(pnp_dev_info), pnp_dev_info);
}

struct chip_operations superio_nsc_pc87417_ops = {
	CHIP_NAME("NSC PC87417 Super I/O")
	.enable_dev = enable_dev,
};
