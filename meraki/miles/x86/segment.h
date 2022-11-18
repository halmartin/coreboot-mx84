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

#ifndef SEGMENT_H
#define SEGMENT_H

/* Segment indexes. Must match the gdt definition in segment.c. */
enum {
	NULL_SEG,
	FLAT_CODE,
	FLAT_DATA,
	RELOC_CODE,
	RELOC_DATA,
	NUM_SEG,
};

/* Values for segment selector register */
#define FLAT_CS (FLAT_CODE << 3)
#define FLAT_DS (FLAT_DATA << 3)
#define RELOC_CS (RELOC_CODE << 3)
#define RELOC_DS (RELOC_DATA << 3)

/* i386 segment descriptor */
struct segment_desc {
	unsigned short limit_0;
	unsigned short base_0;
	unsigned char base_16;
	unsigned char types;
	unsigned char flags;
	unsigned char base_24;
};

extern struct segment_desc gdt[NUM_SEG];

#define GDT_LIMIT ((NUM_SEG << 3) - 1)

#endif
