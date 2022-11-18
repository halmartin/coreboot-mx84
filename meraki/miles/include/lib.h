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


#ifndef LIB_H
#define LIB_H

#include <libpayload.h>

unsigned long long simple_strtoull(const char *cp,char **endp,unsigned int base);
unsigned long long strtoull_with_suffix(const char *cp,char **endp,unsigned int base);

long long simple_strtoll(const char *cp,char **endp,unsigned int base);

#define abort() halt()

#define LOADER_NOT_SUPPORT 0xbadf11e

int linux_load(const uint8_t* kernel, size_t kernel_size,
	       const uint8_t* initrd, size_t initrd_size,
	       const uint8_t* fdt, size_t fdt_size,
	       const char *cmdline);

void relocate(void);

#endif /* LIB_H */
