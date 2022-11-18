/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2012 Advanced Micro Devices, Inc.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arch/io.h>
#include <console/console.h>
#include <spi-generic.h>
#include <device/device.h>
#include <device/pci.h>
#include <device/pci_ops.h>

#if IS_ENABLED (CONFIG_HUDSON_IMC_FWM)
#include <Proc/Fch/FchPlatform.h>

static int bus_claimed = 0;
#endif

#define SPI_REG_OPCODE		0x0
#define SPI_REG_CNTRL01		0x1
#define SPI_REG_CNTRL02		0x2
 #define CNTRL02_FIFO_RESET	(1 << 4)
 #define CNTRL02_EXEC_OPCODE	(1 << 0)
#define SPI_REG_CNTRL03		0x3
 #define CNTRL03_SPIBUSY	(1 << 7)
#define SPI_REG_FIFO		0xc
#define SPI_REG_CNTRL11		0xd
 #define CNTRL11_FIFOPTR_MASK	0x07

#if IS_ENABLED(CONFIG_SOUTHBRIDGE_AMD_AGESA_YANGTZE)
#define AMD_SB_SPI_TX_LEN	64
#else
#define AMD_SB_SPI_TX_LEN	8
#endif

static u32 spibar;

static inline uint8_t spi_read(uint8_t reg)
{
	return read8(spibar + reg);
}

static inline void spi_write(uint8_t reg, uint8_t val)
{
	write8(spibar + reg, val);
}

static void reset_internal_fifo_pointer(void)
{
	uint8_t reg8;

	do {
		reg8 = spi_read(SPI_REG_CNTRL02);
		reg8 |= CNTRL02_FIFO_RESET;
		spi_write(SPI_REG_CNTRL02, reg8);
	} while (spi_read(SPI_REG_CNTRL11) & CNTRL11_FIFOPTR_MASK);
}

static void execute_command(void)
{
	uint8_t reg8;

	reg8 = spi_read(SPI_REG_CNTRL02);
	reg8 |= CNTRL02_EXEC_OPCODE;
	spi_write(SPI_REG_CNTRL02, reg8);

	while ((spi_read(SPI_REG_CNTRL02) & CNTRL02_EXEC_OPCODE) &&
	       (spi_read(SPI_REG_CNTRL03) & CNTRL03_SPIBUSY));
}

void spi_init(void)
{
	device_t dev;

	dev = dev_find_slot(0, PCI_DEVFN(0x14, 3));
	spibar = pci_read_config32(dev, 0xA0) & ~0x1F;
}

unsigned int spi_crop_chunk(unsigned int cmd_len, unsigned int buf_len)
{
	return min(AMD_SB_SPI_TX_LEN - cmd_len, buf_len);
}

int spi_xfer(struct spi_slave *slave, const void *dout,
		unsigned int bytesout, void *din, unsigned int bytesin)
{
	/* First byte is cmd which can not being sent through FIFO. */
	u8 cmd = *(u8 *)dout++;
	u8 readoffby1;
	u8 count;

	bytesout--;

	/*
	 * Check if this is a write command attempting to transfer more bytes
	 * than the controller can handle. Iterations for writes are not
	 * supported here because each SPI write command needs to be preceded
	 * and followed by other SPI commands, and this sequence is controlled
	 * by the SPI chip driver.
	 */
	if (bytesout > AMD_SB_SPI_TX_LEN) {
		printk(BIOS_DEBUG, "FCH SPI: Too much to write. Does your SPI chip driver use"
		     " spi_crop_chunk()?\n");
		return -1;
	}

	readoffby1 = bytesout ? 0 : 1;

#if CONFIG_SOUTHBRIDGE_AMD_AGESA_YANGTZE
	spi_write(0x1E, 5);
	spi_write(0x1F, bytesout); /* SpiExtRegIndx [5] - TxByteCount */
	spi_write(0x1E, 6);
	spi_write(0x1F, bytesin);  /* SpiExtRegIndx [6] - RxByteCount */
#else
	u8 readwrite = (bytesin + readoffby1) << 4 | bytesout;
	spi_write(SPI_REG_CNTRL01, readwrite);
#endif
	spi_write(SPI_REG_OPCODE, cmd);

	reset_internal_fifo_pointer();
	for (count = 0; count < bytesout; count++, dout++) {
		spi_write(SPI_REG_FIFO, *(uint8_t *)dout);
	}

	reset_internal_fifo_pointer();
	execute_command();

	reset_internal_fifo_pointer();
	/* Skip the bytes we sent. */
	for (count = 0; count < bytesout; count++) {
		cmd = spi_read(SPI_REG_FIFO);
	}

	reset_internal_fifo_pointer();
	for (count = 0; count < bytesin; count++, din++) {
		*(uint8_t *)din = spi_read(SPI_REG_FIFO);
	}

	return 0;
}
int spi_claim_bus(struct spi_slave *slave)
{
#if IS_ENABLED (CONFIG_HUDSON_IMC_FWM)

	if (slave->rw == SPI_WRITE_FLAG) {
		bus_claimed++;
		if (bus_claimed == 1)
			ImcSleep(NULL);
	}
#endif

	return 0;
}

void spi_release_bus(struct spi_slave *slave)
{
#if IS_ENABLED (CONFIG_HUDSON_IMC_FWM)

	if (slave->rw == SPI_WRITE_FLAG)  {
		bus_claimed--;
		if (bus_claimed <= 0) {
			bus_claimed = 0;
			ImcWakeup(NULL);
		}
	}
#endif
}

void spi_cs_activate(struct spi_slave *slave)
{
}

void spi_cs_deactivate(struct spi_slave *slave)
{
}

struct spi_slave *spi_setup_slave(unsigned int bus, unsigned int cs)
{
	struct spi_slave *slave = malloc(sizeof(*slave));

	if (!slave) {
		return NULL;
	}

	memset(slave, 0, sizeof(*slave));

	return slave;
}
