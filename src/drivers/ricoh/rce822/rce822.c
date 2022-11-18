/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2014 Vladimir Serbinenko
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

#include <kconfig.h>
#include <console/console.h>
#include <device/device.h>
#include <device/pci.h>
#include <device/pci_ids.h>
#include <arch/io.h>
#include "chip.h"

static void rce822_enable(struct device *dev)
{
	struct drivers_ricoh_rce822_config *config = dev->chip_info;

	pci_write_config8(dev, 0xca, 0x57);
	pci_write_config8(dev, 0xcb, config->disable_mask);
	pci_write_config8(dev, 0xca, 0x00);
}

static void rce822_init(struct device *dev)
{
	struct drivers_ricoh_rce822_config *config = dev->chip_info;

	pci_write_config8(dev, 0xf9, 0xfc);
	pci_write_config8(dev, 0xfb, config->sdwppol << 1);
	pci_write_config8(dev, 0xf9, 0x00);
}

static void rce822_set_subsystem(device_t dev, unsigned vendor, unsigned device)
{

	if (!vendor || !device) {
		pci_write_config32(dev, 0xac,
				pci_read_config32(dev, PCI_VENDOR_ID));
	} else {
		pci_write_config32(dev, 0xac,
				((device & 0xffff) << 16) | (vendor & 0xffff));
	}
}

static struct pci_operations lops_pci = {
	.set_subsystem	= &rce822_set_subsystem,
};

static struct device_operations usb_ehci_ops = {
	.read_resources		= pci_dev_read_resources,
	.set_resources		= pci_dev_set_resources,
	.enable_resources	= pci_dev_enable_resources,
	.init			= rce822_init,
	.enable			= rce822_enable,
	.scan_bus		= 0,
	.ops_pci		= &lops_pci,
};

static const unsigned short pci_device_ids[] = { 0xe822, 0xe823, 0 };

static const struct pci_driver pch_usb_ehci __pci_driver = {
	.ops	 = &usb_ehci_ops,
	.vendor	 = PCI_VENDOR_ID_RICOH,
	.devices = pci_device_ids,
};
