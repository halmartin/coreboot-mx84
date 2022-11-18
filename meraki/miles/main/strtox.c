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


/*  Adapted from LinuxBIOS */

/*
 *
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 */

#include <libpayload.h>

unsigned long long simple_strtoull(const char *cp,char **endp,unsigned int base)
{
	unsigned long long result = 0,value;

	if (!base) {
		base = 10;
		if (*cp == '0') {
			base = 8;
			cp++;
			if ((*cp == 'x') && isxdigit(cp[1])) {
				cp++;
				base = 16;
			}
		}
	}
	while (isxdigit(*cp) && (value = isdigit(*cp) ? *cp-'0' : (islower(*cp)
	    ? toupper(*cp) : *cp)-'A'+10) < base) {
		result = result*base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;
	return result;
}

unsigned long long strtoull_with_suffix(const char *cp,char **endp,unsigned int base)
{
	unsigned long long result;

	if (!endp) {
	    printf("%s must be called with endp\n", __FUNCTION__);
	    return 0;
	}
	result = simple_strtoull(cp, endp, base);
	switch (toupper(**endp)) {
	case 'K':
		result <<= 10;
		++*endp;
		break;
	case 'M':
		result <<= 20;
		++*endp;
		break;
	case 'G':
		result <<= 30;
		++*endp;
		break;
	}
	return result;
}

