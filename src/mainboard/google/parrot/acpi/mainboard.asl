/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2011-2012 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

Scope (\_GPE) {
	Method(_L1F, 0x0, NotSerialized)
	{
		/*
		 * Invert the interrupt level bit for the lid GPIO
		 * so we don't get another _SB.LID0 until the state
		 * changes again. GIV1 is the interrupt level control
		 * register for GPIO bits 15:8
		 */
		Xor(GIV1, 0x80, GIV1)
		Notify(\_SB.LID0,0x80)
	}
}

Scope (\_SB) {
	Device (LID0)
	{
		Name(_HID, EisaId("PNP0C0D"))
		Method(_LID, 0)
		{
			Store (GP15, \LIDS)
			Return (\LIDS)
		}
	}

	Device (PWRB)
	{
		Name(_HID, EisaId("PNP0C0C"))
	}

	Device (TPAD)
	{
		Name (_ADR, 0x0)
		Name (_UID, 1)

		// Report as a Sleep Button device so Linux will
		// automatically enable it as a wake source
		Name(_HID, EisaId("PNP0C0E"))

		// Trackpad Wake is GPIO12, wake from S3
		Name(_PRW, Package(){0x1c, 0x03})

		Name(_CRS, ResourceTemplate()
		{

			// PIRQA -> GSI16
			Interrupt (ResourceConsumer, Level, ActiveLow) {16}

			// PIRQE -> GSI20
			Interrupt (ResourceConsumer, Edge, ActiveLow) {20}

			// SMBUS Address 0x67
			VendorShort (ADDR) {0x67}
		})
	}

	Device (MB) {
		/* Lid open */
		Method (LIDO) { /* Not needed on this board */ }
		/* Lid closed */
		Method (LIDC) { /* Not needed on this board */ }
		/* Increase brightness */
		Method (BRTU) { /* Not needed on this board */ }
		/* Decrease brightness */
		Method (BRTD) { /* Not needed on this board */ }
		/* Switch display */
		Method (DSPS) { /* Not needed on this board */ }
		/* Toggle wireless */
		Method (WLTG) { /* Not needed on this board */ }
		/* Return lid state */
		Method (LIDS)
		{
			Return (GP15)
		}
	}

}
