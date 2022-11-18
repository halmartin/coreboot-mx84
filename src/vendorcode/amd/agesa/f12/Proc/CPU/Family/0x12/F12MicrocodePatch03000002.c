/* $NoKeywords:$ */
/**
 * @file
 *
 * AMD Family_12 Microcode patch.
 *
 * Fam12 Microcode Patch rev 03000002 for 1200 or equivalent.
 *
 * @xrefitem bom "File Content Label" "Release Content"
 * @e project:      AGESA
 * @e sub-project:  CPU/FAMILY/0x12
 * @e \$Revision: 44324 $   @e \$Date: 2010-12-22 17:16:51 +0800 (Wed, 22 Dec 2010) $
 *
 */
/*
 ******************************************************************************
 *
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Advanced Micro Devices, Inc. nor the names of
 *       its contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ADVANCED MICRO DEVICES, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************
 */
/*----------------------------------------------------------------------------------------
 *                             M O D U L E S    U S E D
 *----------------------------------------------------------------------------------------
 */
#include "AGESA.h"
#include "cpuRegisters.h"
#include "cpuEarlyInit.h"

/*----------------------------------------------------------------------------------------
 *                   D E F I N I T I O N S    A N D    M A C R O S
 *----------------------------------------------------------------------------------------
 */

/*----------------------------------------------------------------------------------------
 *                  T Y P E D E F S     A N D     S T R U C T U R E S
 *----------------------------------------------------------------------------------------
 */

// Patch code 03000002 for 1200 and equivalent
CONST MICROCODE_PATCHES ROMDATA CpuF12MicrocodePatch03000002 =
{{
0x10,
0x20,
0x24,
0x03,
0x02,
0x00,
0x00,
0x03,
0x03,
0x80,
0x20,
0x00,
0x49,
0xb8,
0x03,
0x43,
0x00,
0x00,
0x00,
0x00,
0x00,
0x00,
0x00,
0x00,
0x00,
0x12,
0x00,
0x00,
0x00,
0xaa,
0xaa,
0xaa,
0x6d,
0x10,
0xd8,
0x0b,
0x51,
0x0a,
0x38,
0x29,
0xff,
0xff,
0x72,
0x0a,
0xfc,
0x03,
0xa7,
0x7c,
0xff,
0xff,
0xb8,
0x1c,
0xff,
0xff,
0x59,
0x6b,
0xff,
0xff,
0xf9,
0xa9,
0xff,
0xff,
0xc8,
0x1a,
0x6f,
0x58,
0x39,
0x00,
0x81,
0x3f,
0xa0,
0xd7,
0xfc,
0xff,
0xff,
0x03,
0x0f,
0xef,
0x58,
0xc8,
0xf0,
0xfe,
0xff,
0x4f,
0x3a,
0xfc,
0x31,
0xe8,
0xc0,
0x87,
0x93,
0x01,
0x80,
0xff,
0xc0,
0x3f,
0xbf,
0xe1,
0x1f,
0xc0,
0x00,
0xfe,
0x03,
0xff,
0xff,
0x86,
0x7f,
0x00,
0x03,
0xf8,
0x0f,
0xfc,
0xfc,
0x1b,
0xfe,
0x01,
0x00,
0xe0,
0xff,
0xf7,
0xbf,
0x4b,
0xff,
0xff,
0xf0,
0xf3,
0xf0,
0x0f,
0x38,
0x00,
0x4f,
0xdb,
0xa0,
0xd7,
0x81,
0x3f,
0xeb,
0x01,
0xfc,
0x77,
0x5a,
0x3e,
0x0f,
0xfd,
0x69,
0x00,
0x70,
0x41,
0xfd,
0xdf,
0x03,
0xdc,
0x07,
0xf8,
0x79,
0xf8,
0xfa,
0x7f,
0x14,
0xd6,
0x1f,
0xe0,
0xe7,
0xe1,
0xeb,
0xff,
0x4f,
0x56,
0x7f,
0x80,
0x9f,
0x87,
0xff,
0x3d,
0x00,
0xe8,
0x20,
0xf0,
0x6f,
0x82,
0xfc,
0x03,
0xfc,
0x1c,
0xf9,
0xff,
0xbf,
0xc9,
0xf0,
0xcf,
0x74,
0x7d,
0xff,
0x3f,
0xff,
0x25,
0xc3,
0xbf,
0xd2,
0xfd,
0xac,
0x56,
0x19,
0x00,
0xf8,
0x0f,
0xfc,
0x03,
0x1b,
0xfe,
0x01,
0xfc,
0xe0,
0x3f,
0xf0,
0x0f,
0x6f,
0xf8,
0x07,
0xf0,
0x80,
0xff,
0xc0,
0x3f,
0xbf,
0xe1,
0x1f,
0xc0,
0x00,
0xfe,
0x7f,
0x0f,
0x00,
0x18,
0x60,
0xe5,
0x3e,
0x07,
0xfd,
0x00,
0xff,
0xf2,
0xfd,
0xff,
0xfc,
0x3c,
0xfc,
0x03,
0x0e,
0xc0,
0x81,
0x57,
0xe0,
0x73,
0xd0,
0x0f,
0x06,
0x00,
0xb2,
0x5d,
0xff,
0x00,
0xfe,
0x03,
0x00,
0xff,
0x86,
0x7f,
0xfc,
0x03,
0xf8,
0x0f,
0x01,
0xfc,
0x1b,
0xfe,
0xf0,
0x0f,
0xe0,
0x3f,
0x07,
0xf0,
0x6f,
0xf8,
0xdf,
0x03,
0x80,
0xff,
0x81,
0x7f,
0x00,
0xff,
0x3f,
0x80,
0x7f,
0xc3,
0x07,
0xfe,
0x01,
0xfc,
0xff,
0x00,
0xfe,
0x0d,
0x1f,
0xf8,
0x07,
0xf0,
0xfc,
0x03,
0xf8,
0x37,
0xff,
0xef,
0x01,
0xc0,
0xff,
0xc0,
0x3f,
0x80,
0xe1,
0x1f,
0xc0,
0xbf,
0xfe,
0x03,
0xff,
0x00,
0x86,
0x7f,
0x00,
0xff,
0xf8,
0x0f,
0xfc,
0x03,
0x1b,
0xfe,
0x01,
0xfc,
0xe0,
0xff,
0xf7,
0x00,
0xc0,
0x7f,
0xe0,
0x1f,
0xdf,
0xf0,
0x0f,
0xe0,
0x00,
0xff,
0x81,
0x7f,
0x7f,
0xc3,
0x3f,
0x80,
0x01,
0xfc,
0x07,
0xfe,
0xfe,
0x0d,
0xff,
0x00,
0x00,
0xf0,
0xff,
0x7b,
0x0f,
0xe0,
0x3f,
0xf0,
0xf0,
0x6f,
0xf8,
0x07,
0x3f,
0x80,
0xff,
0xc0,
0xc0,
0xbf,
0xe1,
0x1f,
0xff,
0x00,
0xfe,
0x03,
0x00,
0xff,
0x86,
0x7f,
0x3d,
0x00,
0xf8,
0xff,
0xf8,
0x07,
0xf0,
0x1f,
0x03,
0xf8,
0x37,
0xfc,
0xe0,
0x1f,
0xc0,
0x7f,
0x0f,
0xe0,
0xdf,
0xf0,
0x81,
0x7f,
0x00,
0xff,
0x3f,
0x80,
0x7f,
0xc3,
0xff,
0x1e,
0x00,
0xfc,
0x0f,
0xfc,
0x03,
0xf8,
0xfe,
0x01,
0xfc,
0x1b,
0x3f,
0xf0,
0x0f,
0xe0,
0xf8,
0x07,
0xf0,
0x6f,
0xff,
0xc0,
0x3f,
0x80,
0xe1,
0x1f,
0xc0,
0xbf,
0xfe,
0x7f,
0x0f,
0x00,
0xfc,
0x07,
0xfe,
0x01,
0x0d,
0xff,
0x00,
0xfe,
0xf0,
0x1f,
0xf8,
0x07,
0x37,
0xfc,
0x03,
0xf8,
0xc0,
0x7f,
0xe0,
0x1f,
0xdf,
0xf0,
0x0f,
0xe0,
0x00,
0xff,
0xbf,
0x07,
0x00,
0xfe,
0x03,
0xff,
0xff,
0x86,
0x7f,
0x00,
0x03,
0xf8,
0x0f,
0xfc,
0xfc,
0x1b,
0xfe,
0x01,
0x0f,
0xe0,
0x3f,
0xf0,
0xf0,
0x6f,
0xf8,
0x07,
0x03,
0x80,
0xff,
0xdf,
0x7f,
0x00,
0xff,
0x81,
0x80,
0x7f,
0xc3,
0x3f,
0xfe,
0x01,
0xfc,
0x07,
0x00,
0xfe,
0x0d,
0xff,
0xf8,
0x07,
0xf0,
0x1f,
0x03,
0xf8,
0x37,
0xfc,
0xef,
0x01,
0xc0,
0xff,
0xff,
0x7f,
0x16,
0xff,
0x9f,
0x6b,
0xf1,
0xe0,
0xff,
0xff,
0x5b,
0x98,
0x7f,
0x80,
0xb3,
0x86,
0xdf,
0xfe,
0x63,
0xf9,
0xfe,
0xb1,
0x16,
0x0f,
0x98,
0xd6,
0x00,
0x80,
0x01,
0x56,
0x0e,
0x80,
0xd0,
0x0f,
0xe0,
0x73,
0xdf,
0xff,
0xff,
0x2c,
0xc3,
0x3f,
0xc0,
0xcf,
0x1c,
0x60,
0xe5,
0x00,
0x07,
0xfd,
0x00,
0x3e,
0xc0,
0x3d,
0x6b,
0x00,
0xe0,
0x3f,
0xf0,
0x0f,
0x6f,
0xf8,
0x07,
0xf0,
0x80,
0xff,
0xc0,
0x3f,
0xbf,
0xe1,
0x1f,
0xc0,
0x00,
0xfe,
0x03,
0xff,
0xff,
0x86,
0x7f,
0x00,
0x00,
0xf8,
0xff,
0x3d,
0x07,
0xf0,
0x1f,
0xf8,
0xf8,
0x37,
0xfc,
0x03,
0x1f,
0xc0,
0x7f,
0xe0,
0xe0,
0xdf,
0xf0,
0x0f,
0x7f,
0x00,
0xff,
0x81,
0x80,
0x7f,
0xc3,
0x3f,
0x1e,
0x00,
0xfc,
0xff,
0xfc,
0x03,
0xf8,
0x0f,
0x01,
0xfc,
0x1b,
0xfe,
0xf0,
0x0f,
0xe0,
0x3f,
0x07,
0xf0,
0x6f,
0xf8,
0xc0,
0x3f,
0x80,
0xff,
0x1f,
0xc0,
0xbf,
0xe1,
0x7f,
0x0f,
0x00,
0xfe,
0x07,
0xfe,
0x01,
0xfc,
0xff,
0x00,
0xfe,
0x0d,
0x1f,
0xf8,
0x07,
0xf0,
0xfc,
0x03,
0xf8,
0x37,
0x7f,
0xe0,
0x1f,
0xc0,
0xf0,
0x0f,
0xe0,
0xdf,
0xff,
0xbf,
0x07,
0x00,
0xfe,
0x03,
0xff,
0x00,
0x86,
0x7f,
0x00,
0xff,
0xf8,
0x0f,
0xfc,
0x03,
0x1b,
0xfe,
0x01,
0xfc,
0xe0,
0x3f,
0xf0,
0x0f,
0x6f,
0xf8,
0x07,
0xf0,
0x80,
0xff,
0xdf,
0x03,
0x00,
0xff,
0x81,
0x7f,
0x7f,
0xc3,
0x3f,
0x80,
0x01,
0xfc,
0x07,
0xfe,
0xfe,
0x0d,
0xff,
0x00,
0x07,
0xf0,
0x1f,
0xf8,
0xf8,
0x37,
0xfc,
0x03,
0x01,
0xc0,
0xff,
0xef,
0x3f,
0x80,
0xff,
0xc0,
0xc0,
0xbf,
0xe1,
0x1f,
0xff,
0x00,
0xfe,
0x03,
0x00,
0xff,
0x86,
0x7f,
0xfc,
0x03,
0xf8,
0x0f,
0x01,
0xfc,
0x1b,
0xfe,
0xf7,
0x00,
0xe0,
0xff,
0xe0,
0x1f,
0xc0,
0x7f,
0x0f,
0xe0,
0xdf,
0xf0,
0x81,
0x7f,
0x00,
0xff,
0x3f,
0x80,
0x7f,
0xc3,
0x07,
0xfe,
0x01,
0xfc,
0xff,
0x00,
0xfe,
0x0d,
0xff,
0x7b,
0x00,
0xf0,
0x3f,
0xf0,
0x0f,
0xe0,
0xf8,
0x07,
0xf0,
0x6f,
0xff,
0xc0,
0x3f,
0x80,
0xe1,
0x1f,
0xc0,
0xbf,
0xfe,
0x03,
0xff,
0x00,
0x86,
0x7f,
0x00,
0xff,
0xf8,
0xff,
0x3d,
0x00,
0xf0,
0x1f,
0xf8,
0x07,
0x37,
0xfc,
0x03,
0xf8,
0xc0,
0x7f,
0xe0,
0x1f,
0xdf,
0xf0,
0x0f,
0xe0,
0x00,
0xff,
0x81,
0x7f,
0x7f,
0xc3,
0x3f,
0x80,
0x00,
0xfc,
0xff,
0x1e,
0x03,
0xf8,
0x0f,
0xfc,
0xfc,
0x1b,
0xfe,
0x01,
0x0f,
0xe0,
0x3f,
0xf0,
0xf0,
0x6f,
0xf8,
0x07,
0x3f,
0x80,
0xff,
0xc0,
0xc0,
0xbf,
0xe1,
0x1f,
0x0f,
0x00,
0xfe,
0x7f,
0xfe,
0x01,
0xfc,
0x07,
0x00,
0xfe,
0x0d,
0xff,
0xf8,
0x07,
0xf0,
0x1f,
0x03,
0xf8,
0x37,
0xfc,
0xe0,
0x1f,
0xc0,
0x7f,
0x0f,
0xe0,
0xdf,
0xf0,
0xbf,
0x07,
0x00,
0xff,
0x03,
0xff,
0x00,
0xfe,
0x7f,
0x00,
0xff,
0x86,
0x0f,
0xfc,
0x03,
0xf8,
0xfe,
0x01,
0xfc,
0x1b,
0x3f,
0xf0,
0x0f,
0xe0,
0xf8,
0x07,
0xf0,
0x6f,
0xff,
0xdf,
0x03,
0x80
}};

/*----------------------------------------------------------------------------------------
 *           P R O T O T Y P E S     O F     L O C A L     F U N C T I O N S
 *----------------------------------------------------------------------------------------
 */

/*----------------------------------------------------------------------------------------
 *                          E X P O R T E D    F U N C T I O N S
 *----------------------------------------------------------------------------------------
 */
