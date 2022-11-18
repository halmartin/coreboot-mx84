/*
 * This file is part of the coreboot project.
 *
 * Copyright 2014 Google Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * cache.c: Cache maintenance routines for ARMv8 (aarch64)
 *
 * Reference: ARM Architecture Reference Manual, ARMv8-A edition
 */

#include <stdint.h>

#include <arch/cache.h>

void tlb_invalidate_all(void)
{
	 /* TLBIALL includes dTLB and iTLB on systems that have them. */
	 tlbiall(current_el());
	 dsb();
	 isb();
}

unsigned int dcache_line_bytes(void)
{
	uint32_t ccsidr;
	static unsigned int line_bytes = 0;

	if (line_bytes)
		return line_bytes;

	ccsidr = read_ccsidr();
	/* [2:0] - Indicates (Log2(number of words in cache line)) - 4 */
	line_bytes = 1 << ((ccsidr & 0x7) + 4);	/* words per line */
	line_bytes *= sizeof(uint32_t);	/* bytes per word */

	return line_bytes;
}

enum dcache_op {
	OP_DCCSW,
	OP_DCCISW,
	OP_DCISW,
	OP_DCCIVAC,
	OP_DCCVAC,
	OP_DCIVAC,
};

/*
 * Do a dcache operation by virtual address. This is useful for maintaining
 * coherency in drivers which do DMA transfers and only need to perform
 * cache maintenance on a particular memory range rather than the entire cache.
 */
static void dcache_op_va(void const *addr, size_t len, enum dcache_op op)
{
	uint64_t line, linesize;

	linesize = dcache_line_bytes();
	line = (uint64_t)addr & ~(linesize - 1);

	dsb();
	while ((void *)line < addr + len) {
		switch(op) {
		case OP_DCCIVAC:
			dccivac(line);
			break;
		case OP_DCCVAC:
			dccvac(line);
			break;
		case OP_DCIVAC:
			dcivac(line);
			break;
		default:
			break;
		}
		line += linesize;
	}
	isb();
}

void dcache_clean_by_va(void const *addr, size_t len)
{
	dcache_op_va(addr, len, OP_DCCVAC);
}

void dcache_clean_invalidate_by_va(void const *addr, size_t len)
{
	dcache_op_va(addr, len, OP_DCCIVAC);
}

void dcache_invalidate_by_va(void const *addr, size_t len)
{
	dcache_op_va(addr, len, OP_DCIVAC);
}

/*
 * CAUTION: This implementation assumes that coreboot never uses non-identity
 * page tables for pages containing executed code. If you ever want to violate
 * this assumption, have fun figuring out the associated problems on your own.
 */
void dcache_mmu_disable(void)
{
	uint32_t sctlr;

	flush_dcache_all();
	sctlr = read_sctlr(current_el());
	sctlr &= ~(SCTLR_C | SCTLR_M);
	write_sctlr(sctlr, current_el());
}

void dcache_mmu_enable(void)
{
	uint32_t sctlr;

	sctlr = read_sctlr(current_el());
	sctlr |= SCTLR_C | SCTLR_M;
	write_sctlr(sctlr, current_el());
}

void cache_sync_instructions(void)
{
	flush_dcache_all();	/* includes trailing DSB (in assembly) */
	iciallu();		/* includes BPIALLU (architecturally) */
	dsb();
	isb();
}
