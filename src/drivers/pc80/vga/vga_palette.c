/*
 * Copyright (C)  2007-2009  Luc Verhaegen <libv@skynet.be>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "vga.h"

/*
 * Basic palette.
 */
const struct palette
default_vga_palette[0x100] = {
        { 0x00, 0x00, 0x00},
        { 0x00, 0x00, 0x2A},
        { 0x00, 0x2A, 0x00},
        { 0x00, 0x2A, 0x2A},
        { 0x2A, 0x00, 0x00},
        { 0x2A, 0x00, 0x2A},
        { 0x2A, 0x15, 0x00},
        { 0x2A, 0x2A, 0x2A},
        { 0x15, 0x15, 0x15},
        { 0x15, 0x15, 0x3F},
        { 0x15, 0x3F, 0x15},
        { 0x15, 0x3F, 0x3F},
        { 0x3F, 0x15, 0x15},
        { 0x3F, 0x15, 0x3F},
        { 0x3F, 0x3F, 0x15},
        { 0x3F, 0x3F, 0x3F},
        { 0x00, 0x00, 0x00},
        { 0x05, 0x05, 0x05},
        { 0x08, 0x08, 0x08},
        { 0x0B, 0x0B, 0x0B},
        { 0x0E, 0x0E, 0x0E},
        { 0x11, 0x11, 0x11},
        { 0x16, 0x16, 0x16},
        { 0x18, 0x18, 0x18},
        { 0x1C, 0x1C, 0x1C},
        { 0x20, 0x20, 0x20},
        { 0x24, 0x24, 0x24},
        { 0x28, 0x28, 0x28},
        { 0x2D, 0x2D, 0x2D},
        { 0x32, 0x32, 0x32},
        { 0x38, 0x38, 0x38},
        { 0x3F, 0x3F, 0x3F},
        { 0x00, 0x00, 0x3F},
        { 0x20, 0x00, 0x3F},
        { 0x1F, 0x00, 0x3F},
        { 0x2F, 0x00, 0x3F},
        { 0x3F, 0x00, 0x3F},
        { 0x3F, 0x00, 0x2F},
        { 0x3F, 0x00, 0x1F},
        { 0x3F, 0x00, 0x20},
        { 0x3F, 0x00, 0x00},
        { 0x3F, 0x20, 0x00},
        { 0x3F, 0x1F, 0x00},
        { 0x3F, 0x2F, 0x00},
        { 0x3F, 0x3F, 0x00},
        { 0x2F, 0x3F, 0x00},
        { 0x1F, 0x3F, 0x00},
        { 0x20, 0x3F, 0x00},
        { 0x00, 0x3F, 0x00},
        { 0x00, 0x3F, 0x20},
        { 0x00, 0x3F, 0x1F},
        { 0x00, 0x3F, 0x2F},
        { 0x00, 0x3F, 0x3F},
        { 0x00, 0x2F, 0x3F},
        { 0x00, 0x1F, 0x3F},
        { 0x00, 0x20, 0x3F},
        { 0x1F, 0x1F, 0x3F},
        { 0x27, 0x1F, 0x3F},
        { 0x2F, 0x1F, 0x3F},
        { 0x37, 0x1F, 0x3F},
        { 0x3F, 0x1F, 0x3F},
        { 0x3F, 0x1F, 0x37},
        { 0x3F, 0x1F, 0x2F},
        { 0x3F, 0x1F, 0x27},
        { 0x3F, 0x1F, 0x1F},
        { 0x3F, 0x27, 0x1F},
        { 0x3F, 0x2F, 0x1F},
        { 0x3F, 0x37, 0x1F},
        { 0x3F, 0x3F, 0x1F},
        { 0x37, 0x3F, 0x1F},
        { 0x2F, 0x3F, 0x1F},
        { 0x27, 0x3F, 0x1F},
        { 0x1F, 0x3F, 0x1F},
        { 0x1F, 0x3F, 0x27},
        { 0x1F, 0x3F, 0x2F},
        { 0x1F, 0x3F, 0x37},
        { 0x1F, 0x3F, 0x3F},
        { 0x1F, 0x37, 0x3F},
        { 0x1F, 0x2F, 0x3F},
        { 0x1F, 0x27, 0x3F},
        { 0x2D, 0x2D, 0x3F},
        { 0x31, 0x2D, 0x3F},
        { 0x36, 0x2D, 0x3F},
        { 0x3A, 0x2D, 0x3F},
        { 0x3F, 0x2D, 0x3F},
        { 0x3F, 0x2D, 0x3A},
        { 0x3F, 0x2D, 0x36},
        { 0x3F, 0x2D, 0x31},
        { 0x3F, 0x2D, 0x2D},
        { 0x3F, 0x31, 0x2D},
        { 0x3F, 0x36, 0x2D},
        { 0x3F, 0x3A, 0x2D},
        { 0x3F, 0x3F, 0x2D},
        { 0x3A, 0x3F, 0x2D},
        { 0x36, 0x3F, 0x2D},
        { 0x31, 0x3F, 0x2D},
        { 0x2D, 0x3F, 0x2D},
        { 0x2D, 0x3F, 0x31},
        { 0x2D, 0x3F, 0x36},
        { 0x2D, 0x3F, 0x3A},
        { 0x2D, 0x3F, 0x3F},
        { 0x2D, 0x3A, 0x3F},
        { 0x2D, 0x36, 0x3F},
        { 0x2D, 0x31, 0x3F},
        { 0x00, 0x00, 0x1C},
        { 0x07, 0x00, 0x1C},
        { 0x0E, 0x00, 0x1C},
        { 0x15, 0x00, 0x1C},
        { 0x1C, 0x00, 0x1C},
        { 0x1C, 0x00, 0x15},
        { 0x1C, 0x00, 0x0E},
        { 0x1C, 0x00, 0x07},
        { 0x1C, 0x00, 0x00},
        { 0x1C, 0x07, 0x00},
        { 0x1C, 0x0E, 0x00},
        { 0x1C, 0x15, 0x00},
        { 0x1C, 0x1C, 0x00},
        { 0x15, 0x1C, 0x00},
        { 0x0E, 0x1C, 0x00},
        { 0x07, 0x1C, 0x00},
        { 0x00, 0x1C, 0x00},
        { 0x00, 0x1C, 0x07},
        { 0x00, 0x1C, 0x0E},
        { 0x00, 0x1C, 0x15},
        { 0x00, 0x1C, 0x1C},
        { 0x00, 0x15, 0x1C},
        { 0x00, 0x0E, 0x1C},
        { 0x00, 0x07, 0x1C},
        { 0x0E, 0x0E, 0x1C},
        { 0x11, 0x0E, 0x1C},
        { 0x15, 0x0E, 0x1C},
        { 0x18, 0x0E, 0x1C},
        { 0x1C, 0x0E, 0x1C},
        { 0x1C, 0x0E, 0x18},
        { 0x1C, 0x0E, 0x15},
        { 0x1C, 0x0E, 0x11},
        { 0x1C, 0x0E, 0x0E},
        { 0x1C, 0x11, 0x0E},
        { 0x1C, 0x15, 0x0E},
        { 0x1C, 0x18, 0x0E},
        { 0x1C, 0x1C, 0x0E},
        { 0x18, 0x1C, 0x0E},
        { 0x15, 0x1C, 0x0E},
        { 0x11, 0x1C, 0x0E},
        { 0x0E, 0x1C, 0x0E},
        { 0x0E, 0x1C, 0x11},
        { 0x0E, 0x1C, 0x15},
        { 0x0E, 0x1C, 0x18},
        { 0x0E, 0x1C, 0x1C},
        { 0x0E, 0x18, 0x1C},
        { 0x0E, 0x15, 0x1C},
        { 0x0E, 0x11, 0x1C},
        { 0x16, 0x16, 0x1C},
        { 0x16, 0x16, 0x1C},
        { 0x18, 0x16, 0x1C},
        { 0x1A, 0x16, 0x1C},
        { 0x1C, 0x16, 0x1C},
        { 0x1C, 0x16, 0x1A},
        { 0x1C, 0x16, 0x18},
        { 0x1C, 0x16, 0x16},
        { 0x1C, 0x16, 0x16},
        { 0x1C, 0x16, 0x16},
        { 0x1C, 0x18, 0x16},
        { 0x1C, 0x1A, 0x16},
        { 0x1C, 0x1C, 0x16},
        { 0x1A, 0x1C, 0x16},
        { 0x18, 0x1C, 0x16},
        { 0x16, 0x1C, 0x16},
        { 0x16, 0x1C, 0x16},
        { 0x16, 0x1C, 0x16},
        { 0x16, 0x1C, 0x18},
        { 0x16, 0x1C, 0x1A},
        { 0x16, 0x1C, 0x1C},
        { 0x16, 0x1A, 0x1C},
        { 0x16, 0x18, 0x1C},
        { 0x16, 0x16, 0x1C},
        { 0x00, 0x00, 0x20},
        { 0x04, 0x00, 0x20},
        { 0x08, 0x00, 0x20},
        { 0x0C, 0x00, 0x20},
        { 0x20, 0x00, 0x20},
        { 0x20, 0x00, 0x0C},
        { 0x20, 0x00, 0x08},
        { 0x20, 0x00, 0x04},
        { 0x20, 0x00, 0x00},
        { 0x20, 0x04, 0x00},
        { 0x20, 0x08, 0x00},
        { 0x20, 0x0C, 0x00},
        { 0x20, 0x20, 0x00},
        { 0x0C, 0x20, 0x00},
        { 0x08, 0x20, 0x00},
        { 0x04, 0x20, 0x00},
        { 0x00, 0x20, 0x00},
        { 0x00, 0x20, 0x04},
        { 0x00, 0x20, 0x08},
        { 0x00, 0x20, 0x0C},
        { 0x00, 0x20, 0x20},
        { 0x00, 0x0C, 0x20},
        { 0x00, 0x08, 0x20},
        { 0x00, 0x04, 0x20},
        { 0x08, 0x08, 0x20},
        { 0x0A, 0x08, 0x20},
        { 0x0C, 0x08, 0x20},
        { 0x0E, 0x08, 0x20},
        { 0x20, 0x08, 0x20},
        { 0x20, 0x08, 0x0E},
        { 0x20, 0x08, 0x0C},
        { 0x20, 0x08, 0x0A},
        { 0x20, 0x08, 0x08},
        { 0x20, 0x0A, 0x08},
        { 0x20, 0x0C, 0x08},
        { 0x20, 0x0E, 0x08},
        { 0x20, 0x20, 0x08},
        { 0x0E, 0x20, 0x08},
        { 0x0C, 0x20, 0x08},
        { 0x0A, 0x20, 0x08},
        { 0x08, 0x20, 0x08},
        { 0x08, 0x20, 0x0A},
        { 0x08, 0x20, 0x0C},
        { 0x08, 0x20, 0x0E},
        { 0x08, 0x20, 0x20},
        { 0x08, 0x0E, 0x20},
        { 0x08, 0x0C, 0x20},
        { 0x08, 0x0A, 0x20},
        { 0x0B, 0x0B, 0x20},
        { 0x0C, 0x0B, 0x20},
        { 0x0D, 0x0B, 0x20},
        { 0x0F, 0x0B, 0x20},
        { 0x20, 0x0B, 0x20},
        { 0x20, 0x0B, 0x0F},
        { 0x20, 0x0B, 0x0D},
        { 0x20, 0x0B, 0x0C},
        { 0x20, 0x0B, 0x0B},
        { 0x20, 0x0C, 0x0B},
        { 0x20, 0x0D, 0x0B},
        { 0x20, 0x0F, 0x0B},
        { 0x20, 0x20, 0x0B},
        { 0x0F, 0x20, 0x0B},
        { 0x0D, 0x20, 0x0B},
        { 0x0C, 0x20, 0x0B},
        { 0x0B, 0x20, 0x0B},
        { 0x0B, 0x20, 0x0C},
        { 0x0B, 0x20, 0x0D},
        { 0x0B, 0x20, 0x0F},
        { 0x0B, 0x20, 0x20},
        { 0x0B, 0x0F, 0x20},
        { 0x0B, 0x0D, 0x20},
        { 0x0B, 0x0C, 0x20},
        /* Pad with NULL */
};
