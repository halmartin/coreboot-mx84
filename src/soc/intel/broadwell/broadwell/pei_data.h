/*
 * Broadwell UEFI PEI wrapper
 *
 * Copyright (C) 2014 Google Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE INC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PEI_DATA_H
#define PEI_DATA_H

#include <types.h>

#define PEI_VERSION 21

#define ABI_X86 __attribute__((regparm(0)))

typedef void ABI_X86 (*tx_byte_func)(unsigned char byte);

enum board_type {
	BOARD_TYPE_CRB_MOBILE = 0,	/* CRB Mobile */
	BOARD_TYPE_CRB_DESKTOP,		/* CRB Desktop */
	BOARD_TYPE_USER1,		/* SV mobile */
	BOARD_TYPE_USER2,		/* SV desktop */
	BOARD_TYPE_USER3,		/* SV server */
	BOARD_TYPE_ULT,			/* ULT */
	BOARD_TYPE_CRB_EMBDEDDED,	/* CRB Embedded */
	BOARD_TYPE_UNKNOWN,
};

#define MAX_USB2_PORTS 14
#define MAX_USB3_PORTS 6
#define USB_OC_PIN_SKIP 8

enum usb2_port_location {
	USB_PORT_BACK_PANEL = 0,
	USB_PORT_FRONT_PANEL,
	USB_PORT_DOCK,
	USB_PORT_MINI_PCIE,
	USB_PORT_FLEX,
	USB_PORT_INTERNAL,
	USB_PORT_SKIP,
	USB_PORT_NGFF_DEVICE_DOWN,
};

struct usb2_port_setting {
	/*
	 * Usb Port Length:
	 * [16:4] = length in inches in octal format
	 * [3:0]  = decimal point
	 */
	uint16_t length;
	uint8_t enable;
	uint8_t oc_pin;
	uint8_t location;
} __attribute__((packed));

struct usb3_port_setting {
	uint8_t enable;
	uint8_t oc_pin;
	/*
	 * Set to 0 if trace length is > 5 inches
	 * Set to 1 if trace length is <= 5 inches
	 */
	uint8_t fixed_eq;
} __attribute__((packed));

struct pei_data
{
	uint32_t pei_version;

	enum board_type board_type;
	int boot_mode;
	int ec_present;
	int usbdebug;

	/* Base addresses */
	uint32_t pciexbar;
	uint16_t smbusbar;
	uint32_t xhcibar;
	uint32_t ehcibar;
	uint32_t gttbar;
	uint32_t rcba;
	uint32_t pmbase;
	uint32_t gpiobase;
	uint32_t temp_mmio_base;
	uint32_t tseg_size;

	/*
	 * 0 = leave channel enabled
	 * 1 = disable dimm 0 on channel
	 * 2 = disable dimm 1 on channel
	 * 3 = disable dimm 0+1 on channel
	 */
	int dimm_channel0_disabled;
	int dimm_channel1_disabled;
	/* Set to 0 for memory down */
	uint8_t spd_addresses[4];
	/* Enable 2x Refresh Mode */
	int ddr_refresh_2x;
	/* DQ pins are interleaved on board */
	int dq_pins_interleaved;
	/* Limit DDR3 frequency */
	int max_ddr3_freq;
	/* Disable self refresh */
	int disable_self_refresh;

	/* USB port configuration */
	struct usb2_port_setting usb2_ports[MAX_USB2_PORTS];
	struct usb3_port_setting usb3_ports[MAX_USB3_PORTS];

	/* Console output function */
	tx_byte_func tx_byte;

	/*
	 * DIMM SPD data for memory down configurations
	 * [CHANNEL][SLOT][SPD]
	 */
	uint8_t spd_data[2][2][512];

	/*
	 * LPDDR3 DQ byte map
	 * [CHANNEL][ITERATION][2]
	 *
	 * Maps which PI clocks are used by what LPDDR DQ Bytes (from CPU side)
	 * DQByteMap[0] - ClkDQByteMap:
	 * - If clock is per rank, program to [0xFF, 0xFF]
	 * - If clock is shared by 2 ranks, program to [0xFF, 0] or [0, 0xFF]
	 * - If clock is shared by 2 ranks but does not go to all bytes,
	 *   Entry[i] defines which DQ bytes Group i services
	 * DQByteMap[1] - CmdNDQByteMap: [0] is CmdN/CAA and [1] is CmdN/CAB
	 * DQByteMap[2] - CmdSDQByteMap: [0] is CmdS/CAA and [1] is CmdS/CAB
	 * DQByteMap[3] - CkeDQByteMap : [0] is CKE /CAA and [1] is CKE /CAB
	 *                For DDR, DQByteMap[3:1] = [0xFF, 0]
	 * DQByteMap[4] - CtlDQByteMap : Always program to [0xFF, 0]
	 *                since we have 1 CTL / rank
	 * DQByteMap[5] - CmdVDQByteMap: Always program to [0xFF, 0]
	 *                since we have 1 CA Vref
	 */
	uint8_t dq_map[2][6][2];

	/*
	 * LPDDR3 Map from CPU DQS pins to SDRAM DQS pins
	 * [CHANNEL][MAX_BYTES]
	 */
	uint8_t dqs_map[2][8];

	/* Data read from flash and passed into MRC */
	const void *saved_data;
	int saved_data_size;

	/* Disable use of saved data (can be set by mainboard) */
	int disable_saved_data;

	/* Data from MRC that should be saved to flash */
	void *data_to_save;
	int data_to_save_size;
} __attribute__((packed));

typedef struct pei_data PEI_DATA;

#endif
