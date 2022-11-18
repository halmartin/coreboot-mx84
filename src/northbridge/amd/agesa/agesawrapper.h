/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2011 Advanced Micro Devices, Inc.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _AGESAWRAPPER_H_
#define _AGESAWRAPPER_H_

#include <stdint.h>
#include "Porting.h"
#include "AGESA.h"

/* Define AMD Ontario APPU SSID/SVID */
#define AMD_APU_SVID		0x1022
#define AMD_APU_SSID		0x1234
#define PCIE_BASE_ADDRESS	 CONFIG_MMCONF_BASE_ADDRESS

enum {
	PICK_DMI,       /* DMI Interface */
	PICK_PSTATE,    /* Acpi Pstate SSDT Table */
	PICK_SRAT,      /* SRAT Table */
	PICK_SLIT,      /* SLIT Table */
	PICK_WHEA_MCE,  /* WHEA MCE table */
	PICK_WHEA_CMC,  /* WHEA CMV table */
	PICK_ALIB,      /* SACPI SSDT table with ALIB implementation */
	PICK_IVRS,      /* IOMMU ACPI IVRS(I/O Virtualization Reporting Structure) table */
};

AGESA_STATUS agesawrapper_amdinitreset(void);
AGESA_STATUS agesawrapper_amdinitearly(void);
AGESA_STATUS agesawrapper_amdinitenv(void);
AGESA_STATUS agesawrapper_amdinitlate(void);
AGESA_STATUS agesawrapper_amdinitpost(void);
AGESA_STATUS agesawrapper_amdinitmid(void);

void agesawrapper_trace(AGESA_STATUS ret, AMD_CONFIG_PARAMS *StdHeader, const char *func);
#define AGESA_EVENTLOG(status, stdheader) \
	agesawrapper_trace(status, stdheader, __func__)

AGESA_STATUS agesawrapper_amdinitcpuio(void);
AGESA_STATUS agesawrapper_amdinitmmio(void);
AGESA_STATUS agesawrapper_amdinitresume(void);
AGESA_STATUS agesawrapper_amdS3Save(void);
AGESA_STATUS agesawrapper_amds3laterestore(void);
AGESA_STATUS agesawrapper_amdlaterunaptask (UINT32 Func, UINT32 Data, VOID *ConfigPtr);
void *agesawrapper_getlateinitptr (int pick);

AGESA_STATUS agesawrapper_fchs3earlyrestore(void);
AGESA_STATUS agesawrapper_fchs3laterestore(void);

void OemCustomizeInitEarly(AMD_EARLY_PARAMS *InitEarly);
void OemCustomizeInitPost(AMD_POST_PARAMS *InitPost);

#endif /* _AGESAWRAPPER_H_ */
