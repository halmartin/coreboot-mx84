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


#ifndef i386_CONTEXT_H
#define i386_CONTEXT_H

struct context {
	/* Stack Segment, placed here because of the alignment issue... */
	u16 ss;
	/* Used with sgdt/lgdt */
	u16 gdt_limit;
	u32 gdt_base;
	/* General registers, accessed with pushal/popal */
	u32 edi;
	u32 esi;
	u32 ebp;
	u32 esp;		/* points just below eax */
	u32 ebx;
	u32 edx;
	u32 ecx;
	u32 eax;
#define ESP_LOC(ctx) (&(ctx)->gs)
	/* Segment registers */
	u32 gs;
	u32 fs;
	u32 es;
	u32 ds;
	/* Flags */
	u32 eflags;
	/* Code segment:offset */
	u32 eip;
	u32 cs;
	/* Optional stack contents */
	u32 return_addr;
	u32 param[0];
};

/* Create a new context in the given stack */
struct context *init_context(u8 * stack, u32 stack_size, int num_param);

/* Switch context */
struct context *switch_to(struct context *);

/* Holds physical address of boot context */
extern unsigned long __boot_ctx;

/* This can always be safely used to refer to the boot context */
#define boot_ctx ((struct context *) phys_to_virt(__boot_ctx))

#endif				/* i386_CONTEXT_H */
