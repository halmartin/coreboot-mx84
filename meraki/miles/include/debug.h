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


#ifndef DEBUG_H
#define DEBUG_H

#include <lib.h>

/* Defining DEBUG_THIS before including this file enables debug() macro
 * for the file. CONFIG_DEBUG_ALL is for global control. */

#if ( defined(DEBUG_THIS) && (DEBUG_THIS == 1)) || (defined(CONFIG_DEBUG_ALL) && (CONFIG_DEBUG_ALL == 1))
#define DEBUG 1
#else
#undef DEBUG
#endif

#ifdef DEBUG
# define debug(...) \
    printf(__VA_ARGS__)
# define debug_hexdump hexdump
#else
# define debug(...) /* nothing */
# define debug_hexdump(...) /* nothing */
#endif

#ifdef CONFIG_USE_GRUB
extern int using_grub_interface;
void grub_printf (const char *format,...);
#define printf(x...) do { if (using_grub_interface) { grub_printf(x); } else { printf(x); } } while (0)
#endif

#endif /* DEBUG_H */
