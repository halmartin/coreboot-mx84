/*
 * This file is part of FILO.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */


/* Segmentation of the i386 architecture.
 *
 * 2003-07 by SONE Takeshi
 */

#include <libpayload.h>
#include <coreboot_tables.h>
#include "segment.h"

#define DEBUG_THIS 0
#include <debug.h>

/* i386 lgdt argument */
struct gdtarg {
	unsigned short limit;
	unsigned int base;
} __attribute__ ((packed));

/* How far the virtual address (used in C) is different from physical 
 * address. Since we start in flat mode, the initial value is zero. */
unsigned long virt_offset = 0;

/* GDT, the global descriptor table */
struct segment_desc gdt[NUM_SEG] = {
	/* 0x00: null segment */
	{0, 0, 0, 0, 0, 0},
	/* 0x08: flat code segment */
	{0xffff, 0, 0, 0x9f, 0xcf, 0},
	/* 0x10: flat data segment */
	{0xffff, 0, 0, 0x93, 0xcf, 0},
	/* 0x18: code segment for relocated execution */
	{0xffff, 0, 0, 0x9f, 0xcf, 0},
	/* 0x20: data segment for relocated execution */
	{0xffff, 0, 0, 0x93, 0xcf, 0},
};

extern char _start[], _end[];

void relocate(void)
{
	int i;
	unsigned long prog_addr;
	unsigned long prog_size;
	unsigned long addr, new_base;
	unsigned long long segsize;
	unsigned long new_offset;
	unsigned d0, d1, d2;
	struct gdtarg gdtarg;
	struct sysinfo_t *info = &lib_sysinfo;
#define ALIGNMENT 0x1000

	prog_addr = virt_to_phys(&_start);
	prog_size = virt_to_phys(&_end) - virt_to_phys(&_start);
	debug("Current location: %#lx-%#lx\n", prog_addr,
	      prog_addr + prog_size - 1);

	new_base = 0;
	for (i = 0; i < info->n_memranges; i++) {
		if (info->memrange[i].type != CB_MEM_RAM)
			continue;
		if (info->memrange[i].base >= 1ULL << 32)
			continue;
		segsize = info->memrange[i].size;
		if (info->memrange[i].base + segsize > 1ULL << 32)
			segsize = (1ULL << 32) - info->memrange[i].base;
		if (segsize < prog_size + ALIGNMENT)
			continue;
		addr = info->memrange[i].base + segsize - prog_size;
		addr &= ~(ALIGNMENT - 1);
		if (addr >= prog_addr && addr < prog_addr + prog_size)
			continue;
		if (prog_addr >= addr && prog_addr < addr + prog_size)
			continue;
		if (addr > new_base)
			new_base = addr;
	}
	if (new_base == 0) {
		printf("Can't find address to relocate\n");
		return;
	}

	debug("Relocating to %#lx-%#lx... ",
	      new_base, new_base + prog_size - 1);

	/* New virtual address offset */
	new_offset = new_base - (unsigned long) &_start;

	/* Tweak the GDT */
	gdt[RELOC_CODE].base_0 = (unsigned short) new_offset;
	gdt[RELOC_CODE].base_16 = (unsigned char) (new_offset >> 16);
	gdt[RELOC_CODE].base_24 = (unsigned char) (new_offset >> 24);
	gdt[RELOC_DATA].base_0 = (unsigned short) new_offset;
	gdt[RELOC_DATA].base_16 = (unsigned char) (new_offset >> 16);
	gdt[RELOC_DATA].base_24 = (unsigned char) (new_offset >> 24);

	/* Load new GDT and reload segments */
	gdtarg.base = new_offset + (unsigned long) gdt;
	gdtarg.limit = GDT_LIMIT;
	__asm__ __volatile__("rep; movsb\n\t"	/* copy everything */
			     "lgdt %3\n\t"
			     "ljmp %4, $1f\n1:\t"
			     "movw %5, %%ds\n\t"
			     "movw %5, %%es\n\t"
			     "movw %5, %%fs\n\t"
			     "movw %5, %%gs\n\t"
			     "movw %5, %%ss\n":"=&S"(d0), "=&D"(d1),
			     "=&c"(d2)
			     :"m"(gdtarg), "n"(RELOC_CS),
			     "q"((unsigned short) RELOC_DS), "0"(&_start),
			     "1"(new_base), "2"(prog_size));

	virt_offset = new_offset;	// for FILO
	virtual_offset = new_offset;	// for libpayload

	// Needs to be run again after relocation
	lib_get_sysinfo();

	debug("ok\n");
}
