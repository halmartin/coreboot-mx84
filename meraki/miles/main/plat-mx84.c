/*
 * miles - the Meraki Intermediate Loader for Embedded Systems
 *
 * Platform-specific code for the MS350 (Big Pony)
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

#include <libpayload-config.h>
#include <libpayload.h>
#include "mplatform.h"

#define BIGPONY_FLASH_SIZE    0x1000000   // 16MiB

/* Flash is mapped to the end of 32-bit address space. */
#define BIGPONY_FLASH_BASE    0x100000000 - BIGPONY_FLASH_SIZE

#define BIGPONY_BOOTKERNEL_1_LOC      BIGPONY_FLASH_BASE + 0x10000
#define BIGPONY_BOOTKERNEL_2_LOC      BIGPONY_FLASH_BASE + 0x710000
#define BIGPONY_BOOTKERNEL_SIZE       BIGPONY_BOOTKERNEL_2_LOC - BIGPONY_BOOTKERNEL_1_LOC

/* This corresponds to the meraki_bootkernel entry in src/mainboard/meraki/bigpony/cmos.layout
 * bit 416 = byte 52 (0x34), bit 0 */
#define BIGPONY_BOOTKERNEL_NVRAM_LOC  0x34
#define BIGPONY_BOOTKERNEL_NVRAM_MASK 0x03

int
platform_get_info(struct miles_platform_info* info)
{
    if (!info)
        return -1;

    info->bootkernels[0].ptr = phys_to_virt(BIGPONY_BOOTKERNEL_1_LOC);
    info->bootkernels[0].size = BIGPONY_BOOTKERNEL_SIZE;
    info->bootkernels[1].ptr = phys_to_virt(BIGPONY_BOOTKERNEL_2_LOC);
    info->bootkernels[1].size = BIGPONY_BOOTKERNEL_SIZE;
    info->itb_config_name[0] = '\0';  // use default

    return 0;
}

void
platform_record_bootkernel(int bknum)
{
    uint8_t data = nvram_read(BIGPONY_BOOTKERNEL_NVRAM_LOC);
    data &= ~BIGPONY_BOOTKERNEL_NVRAM_MASK;
    nvram_write(data | ((uint8_t)bknum), BIGPONY_BOOTKERNEL_NVRAM_LOC);
};
