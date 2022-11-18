/*
 * miles - the Meraki Intermediate Loader for Embedded Systems
 *
 * Copyright (C) 2015 Cisco Systems, Inc.
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

#ifndef MPLATFORM_H
#define MPLATFORM_H

struct miles_buffer
{
    void* ptr;
    size_t size;
};

#define MILES_FDT_NAME_MAX  255

struct miles_platform_info
{
    struct miles_buffer bootkernels[2];
    char itb_config_name[MILES_FDT_NAME_MAX];  // If empty, default config is used.
};

extern int platform_get_info(struct miles_platform_info* info);

#endif
