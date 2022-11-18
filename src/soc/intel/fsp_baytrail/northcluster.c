/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2013 Google Inc.
 * Copyright (C) 2013-2014 Sage Electronic Engineering, LLC.
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
#include <cpu/x86/smm.h>
#include <device/device.h>
#include <device/pci.h>
#include <device/pci_ids.h>
#include <cpu/x86/lapic.h>
#include <baytrail/iomap.h>
#include <baytrail/iosf.h>
#include <baytrail/pci_devs.h>
#include <baytrail/ramstage.h>
#include <device/pci.h>
#include <cbmem.h>
#include <baytrail/baytrail.h>
#include <drivers/intel/fsp/fsp_util.h>


static const int legacy_hole_base_k = 0xa0000 / 1024;
static const int legacy_hole_size_k = 384;

/* Host Memory Map:
 *
 * +--------------------------+ BMBOUND_HI
 * |     Usable DRAM          |
 * +--------------------------+ 4GiB
 * |     PCI Address Space    |
 * +--------------------------+ BMBOUND
 * |     TPM                  |
 * +--------------------------+ IMR2
 * |     TXE                  |
 * +--------------------------+ IMR1
 * |     iGD                  |
 * +--------------------------+
 * |     GTT                  |
 * +--------------------------+ SMMRRH, IRM0
 * |     TSEG                 |
 * +--------------------------+ SMMRRL
 * |     FSP                  |
 * +--------------------------+ SMMRRL - 2MB
 * |     Usable DRAM          |
 * +--------------------------+ FFFFF
 * |     ROM Area             |
 * +--------------------------+ A0000
 * |     Usable DRAM          |
 * +--------------------------+ 0
 *
 * Note that there are really only a few regions that need to enumerated w.r.t.
 * coreboot's resource model:
 *
 * +--------------------------+ BMBOUND_HI
 * |     Cacheable/Usable     |
 * +--------------------------+ 4GiB
 *
 * +--------------------------+ BMBOUND
 * |    Uncacheable/Reserved  |
 * +--------------------------+ SMMRRH
 * |    Cacheable/Reserved    |
 * +--------------------------+ SMMRRL - 2MB
 * |     Cacheable/Usable     |
 * +--------------------------+ 0
 */

/*
 * Get the top of low memory for use by ACPI
 */
uint32_t nc_read_top_of_low_memory(void)
{
	uint32_t fsp_mem_base = 0;
	GetLowMemorySize(&fsp_mem_base);

	return fsp_mem_base;
}

static int get_pcie_bar(u32 *base, u32 *len)
{
	device_t dev;
	u32 pciexbar_reg;

	*base = 0;
	*len = 0;

	dev = dev_find_slot(0, PCI_DEVFN(0, 0));
	if (!dev)
		return 0;

	pciexbar_reg = iosf_bunit_read(BUNIT_MMCONF_REG);

	if (!(pciexbar_reg & (1 << 0)))
		return 0;

	*base = pciexbar_reg & ((1 << 31) | (1 << 30) | (1 << 29) |
				(1 << 28));
	*len = 256 * 1024 * 1024; /* 256MB ECAM range */
	return 1;

}

static int add_fixed_resources(struct device *dev, int index)
{
	struct resource *resource;
	u32 pcie_config_base, pcie_config_size;


	if (get_pcie_bar(&pcie_config_base, &pcie_config_size)) {
		printk(BIOS_DEBUG, "Adding PCIe config bar base=0x%08x "
		       "size=0x%x\n", pcie_config_base, pcie_config_size);
		resource = new_resource(dev, index++);
		resource->base = (resource_t) pcie_config_base;
		resource->size = (resource_t) pcie_config_size;
		resource->flags = IORESOURCE_MEM | IORESOURCE_RESERVE |
		    IORESOURCE_FIXED | IORESOURCE_STORED | IORESOURCE_ASSIGNED;
	}

	resource = new_resource(dev, index++); /* Local APIC */
	resource->base = LAPIC_DEFAULT_BASE;
	resource->size = 0x00001000;
	resource->flags = IORESOURCE_MEM | IORESOURCE_RESERVE |
		    IORESOURCE_FIXED | IORESOURCE_STORED | IORESOURCE_ASSIGNED;

	mmio_resource(dev, index++, legacy_hole_base_k, legacy_hole_size_k);

	return index;
}

static void mc_add_dram_resources(device_t dev)
{
	u32 bmbound, bsmmrrl;
	int index = 0;
	uint64_t highmem_size = 0;
	uint32_t fsp_mem_base = 0;

	GetHighMemorySize(&highmem_size);
	GetLowMemorySize(&fsp_mem_base);


	bmbound = iosf_bunit_read(BUNIT_BMBOUND);
	bsmmrrl = iosf_bunit_read(BUNIT_SMRRL) << 20;

	if (bsmmrrl){
		printk(BIOS_DEBUG, "UMA, GTT & SMM memory location: 0x%x\n"
				"UMA, GTT & SMM memory size: %dM\n",
				bsmmrrl, (bmbound - bsmmrrl) >> 20);

		printk(BIOS_DEBUG, "FSP memory location: 0x%x\nFSP memory size: %dM\n",
				fsp_mem_base, (bsmmrrl - fsp_mem_base) >> 20);

		if ((bsmmrrl - fsp_mem_base ) != FSP_RESERVE_MEMORY_SIZE)
			printk(BIOS_WARNING, "Warning: Fsp memory size does not match "
					"expected memory size (%x).\n", FSP_RESERVE_MEMORY_SIZE);
	}

	printk(BIOS_INFO, "Available memory below 4GB: 0x%08x (%dM)\n",
			fsp_mem_base, fsp_mem_base >> 20);

	/* Report the memory regions. */
	ram_resource(dev, index++, 0, legacy_hole_base_k);
	ram_resource(dev, index++, legacy_hole_base_k + legacy_hole_size_k,
	     ((fsp_mem_base >> 10) - (legacy_hole_base_k + legacy_hole_size_k)));

	/* Mark SMM & FSP regions reserved */
	mmio_resource(dev, index++, fsp_mem_base >> 10,
			(bmbound - fsp_mem_base) >> 10);

	if (highmem_size) {
		ram_resource(dev, index++, 0x100000000 >> 10, highmem_size >> 10 );
	}
	printk(BIOS_INFO, "Available memory above 4GB: %lluM\n",
			highmem_size >> 20);

	index = add_fixed_resources(dev, index);
}

static void nc_read_resources(device_t dev)
{
	/* Call the normal read_resources */
	pci_dev_read_resources(dev);


	/* Calculate and add DRAM resources. */
	mc_add_dram_resources(dev);
}

static void nc_enable(device_t dev)
{
	print_fsp_info();
}

static struct device_operations nc_ops = {
	.read_resources   = nc_read_resources,
	.set_resources    = NULL,
	.enable_resources = NULL,
	.init             = NULL,
	.enable           = &nc_enable,
	.scan_bus         = NULL,
	.ops_pci          = &soc_pci_ops,
};

static const struct pci_driver nc_driver __pci_driver = {
	.ops    = &nc_ops,
	.vendor = PCI_VENDOR_ID_INTEL,
	.device = SOC_DEVID,
};
