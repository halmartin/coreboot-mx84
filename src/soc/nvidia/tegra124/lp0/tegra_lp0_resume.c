/*
 * Copyright 2014 Google Inc.
 * Copyright 2013, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>

/* Function unit addresses. */
enum {
	UP_TAG_BASE = 0X60000000,
	TIMER_BASE = 0X60005000,
	CLK_RST_BASE = 0X60006000,
	FLOW_CTLR_BASE = 0X60007000,
	TEGRA_EVP_BASE = 0x6000f000,
	PMC_CTLR_BASE = 0X7000e400,
	MC_CTLR_BASE = 0X70019000,
	SYSCTR_CTLR_BASE = 0X700f0000
};



/* UP tag registers. */
static uint32_t *up_tag_ptr = (void *)(UP_TAG_BASE + 0x0);
enum {
	UP_TAG_AVP = 0xaaaaaaaa
};



/* Timer registers. */
static uint32_t *timer_us_ptr = (void *)(TIMER_BASE + 0x10);



/* Clock and reset controller registers. */
static uint32_t *clk_rst_rst_devices_l_ptr = (void *)(CLK_RST_BASE + 0x4);
enum {
	SWR_TRIG_SYS_RST = 0x1 << 2
};

static uint32_t *clk_rst_cclk_burst_policy_ptr = (void *)(CLK_RST_BASE + 0x20);
enum {
	CCLK_PLLP_BURST_POLICY = 0x20004444
};

static uint32_t *clk_rst_super_cclk_div_ptr = (void *)(CLK_RST_BASE + 0x24);
enum {
	SUPER_CDIV_ENB = 0x1 << 31
};

static uint32_t *clk_rst_osc_ctrl_ptr = (void *)(CLK_RST_BASE + 0x50);
enum {
	OSC_XOE = 0x1 << 0,
	OSC_XOFS_SHIFT = 4,
	OSC_XOFS_MASK = 0x3f << OSC_XOFS_SHIFT,
	OSC_FREQ_SHIFT = 28,
	OSC_FREQ_MASK = 0xf << OSC_FREQ_SHIFT
};
enum {
	OSC_FREQ_13 = 0,
	OSC_FREQ_16P8 = 1,
	OSC_FREQ_19P2 = 4,
	OSC_FREQ_38P4 = 5,
	OSC_FREQ_12 = 8,
	OSC_FREQ_48 = 9,
	OSC_FREQ_26 = 12
};

static uint32_t *clk_rst_pllu_base_ptr = (void *)(CLK_RST_BASE + 0xc0);
enum {
	PLLU_DIVM_SHIFT = 0,
	PLLU_DIVN_SHIFT = 8,
	PLLU_OVERRIDE = 0x1 << 24,
	PLLU_ENABLE = 0x1 << 30,
	PLLU_BYPASS = 0x1 << 31
};

static uint32_t *clk_rst_pllu_misc_ptr = (void *)(CLK_RST_BASE + 0xcc);
enum {
	PLLU_LFCON_SHIFT = 4,
	PLLU_CPCON_SHIFT = 8,
	PLLU_LOCK_ENABLE = 22
};

static uint32_t *clk_rst_pllx_base_ptr = (void *)(CLK_RST_BASE + 0xe0);
enum {
	PLLX_ENABLE = 0x1 << 30
};

static uint32_t *clk_rst_rst_dev_u_clr_ptr = (void *)(CLK_RST_BASE + 0x314);
enum {
	SWR_CSITE_RST = 0x1 << 9
};

static uint32_t *clk_rst_clk_enb_l_set_ptr = (void *)(CLK_RST_BASE + 0x320);
enum {
	CLK_ENB_CPU = 0x1 << 0
};

static uint32_t *clk_rst_clk_out_enb_u_set_ptr =
	(void *)(CLK_RST_BASE + 0x330);
enum {
	CLK_ENB_CSITE = 0x1 << 9
};

static uint32_t *clk_rst_cpu_softrst_ctrl2_ptr =
	(void *)(CLK_RST_BASE + 0x388);
enum {
	CAR2PMC_CPU_ACK_WIDTH_SHIFT = 0,
	CAR2PMC_CPU_ACK_WIDTH_MASK = 0xfff << CAR2PMC_CPU_ACK_WIDTH_SHIFT
};

static uint32_t *clk_rst_clk_src_mselect_ptr =
	(void *)(CLK_RST_BASE + 0x3b4);
enum {
	MSELECT_CLK_DIV_SHIFT = 0,
	MSELECT_CLK_SRC_SHIFT = 29,
	MSELECT_CLK_SRC_PLLP_OUT0 = 0x0 << MSELECT_CLK_SRC_SHIFT,
	MSELECT_CLK_SRC_PLLC2_OUT0 = 0x1 << MSELECT_CLK_SRC_SHIFT,
	MSELECT_CLK_SRC_PLLC_OUT0 = 0x2 << MSELECT_CLK_SRC_SHIFT,
	MSELECT_CLK_SRC_PLLC3_OUT0 = 0x3 << MSELECT_CLK_SRC_SHIFT
};

static uint32_t *clk_rst_rst_dev_v_clr_ptr = (void *)(CLK_RST_BASE + 0x434);
enum {
	SWR_MSELECT_RST = 0x1 << 3
};

static uint32_t *clk_rst_clk_enb_v_set_ptr = (void *)(CLK_RST_BASE + 0x440);
enum {
	CLK_ENB_CPUG = 0x1 << 0,
	CLK_ENB_CPULP = 0x1 << 1,
	CLK_ENB_MSELECT = 0x1 << 3
};

static uint32_t *clk_rst_rst_cpulp_cmplx_clr_ptr =
	(void *)(CLK_RST_BASE + 0x45c);
static uint32_t *clk_rst_rst_cpug_cmplx_clr_ptr =
	(void *)(CLK_RST_BASE + 0x454);
enum {
	CLR_CPURESET0 = 0x1 << 0,
	CLR_CPURESET1 = 0x1 << 1,
	CLR_CPURESET2 = 0x1 << 2,
	CLR_CPURESET3 = 0x1 << 3,
	CLR_DBGRESET0 = 0x1 << 12,
	CLR_DBGRESET1 = 0x1 << 13,
	CLR_DBGRESET2 = 0x1 << 14,
	CLR_DBGRESET3 = 0x1 << 15,
	CLR_CORERESET0 = 0x1 << 16,
	CLR_CORERESET1 = 0x1 << 17,
	CLR_CORERESET2 = 0x1 << 18,
	CLR_CORERESET3 = 0x1 << 19,
	CLR_CXRESET0 = 0x1 << 20,
	CLR_CXRESET1 = 0x1 << 21,
	CLR_CXRESET2 = 0x1 << 22,
	CLR_CXRESET3 = 0x1 << 23,
	CLR_NONCPURESET = 0x1 << 29
};



/* Reset vector. */

static uint32_t *evp_cpu_reset_ptr = (void *)(TEGRA_EVP_BASE + 0x100);



/* Flow controller registers. */
static uint32_t *flow_ctlr_halt_cop_events_ptr =
	(void *)(FLOW_CTLR_BASE + 0x4);
enum {
	EVENT_MSEC = 0x1 << 24,
	EVENT_JTAG = 0x1 << 28,
	FLOW_MODE_SHIFT = 29,
	FLOW_MODE_STOP = 2 << FLOW_MODE_SHIFT,
};

static uint32_t *flow_ctlr_cluster_control_ptr =
	(void *)(FLOW_CTLR_BASE + 0x2c);
enum {
	FLOW_CLUSTER_ACTIVE_LP = 0x1 << 0
};



/* Power management controller registers. */
enum {
	PARTID_CRAIL = 0,
	PARTID_CELP = 12,
	PARTID_CE0 = 14,
	PARTID_C0NC = 15,
	PARTID_C1NC = 16
};

static uint32_t *pmc_ctlr_clamp_status_ptr = (void *)(PMC_CTLR_BASE + 0x2c);

static uint32_t *pmc_ctlr_pwrgate_toggle_ptr = (void *)(PMC_CTLR_BASE + 0x30);
enum {
	PWRGATE_TOGGLE_START = 0x1 << 8
};

static uint32_t *pmc_ctlr_pwrgate_status_ptr = (void *)(PMC_CTLR_BASE + 0x38);

static uint32_t *pmc_ctlr_scratch4_ptr = (void *)(PMC_CTLR_BASE + 0x60);
enum {
	PMC_SCRATCH4_LP = 0x1 << 31
};

static uint32_t *pmc_ctlr_cpupwrgood_timer_ptr =
	(void *)(PMC_CTLR_BASE + 0xc8);

static uint32_t *pmc_ctlr_scratch41_ptr = (void *)(PMC_CTLR_BASE + 0x140);

static uint32_t *pmc_ctlr_osc_edpd_over_ptr = (void *)(PMC_CTLR_BASE + 0x1a4);
enum {
	PMC_XOFS_SHIFT = 1,
	PMC_XOFS_MASK = 0x3f << PMC_XOFS_SHIFT
};



/* Memory controller registers. */
static uint32_t *mc_video_protect_size_mb_ptr = (void *)(MC_CTLR_BASE + 0x64c);

static uint32_t *mc_video_protect_reg_ctrl_ptr =
	(void *)(MC_CTLR_BASE + 0x650);
enum {
	VIDEO_PROTECT_WRITE_ACCESS_DISABLE = 0x1 << 0,
	VIDEO_PROTECT_ALLOW_TZ_WRITE_ACCESS = 0x1 << 1
};



/* System counter registers. */
static uint32_t *sysctr_cntcr_ptr = (void *)(SYSCTR_CTLR_BASE + 0x0);
enum {
	TSC_CNTCR_ENABLE = 0x1 << 0,
	TSC_CNTCR_HDBG = 0x1 << 1
};

static uint32_t *sysctr_cntfid0_ptr = (void *)(SYSCTR_CTLR_BASE + 0x20);



/* Utility functions. */

static inline void __attribute__((always_inline))
		   __attribute__((noreturn)) halt(void)
{
	for (;;);
}

inline static uint32_t read32(const void *addr)
{
	return *(volatile uint32_t *)addr;
}

inline static void write32(uint32_t val, void *addr)
{
	*(volatile uint32_t *)addr = val;
}

inline static void setbits32(uint32_t bits, void *addr)
{
	write32(read32(addr) | bits, addr);
}

inline static void clrbits32(uint32_t bits, void *addr)
{
	write32(read32(addr) & ~bits, addr);
}

static void __attribute__((noreturn)) reset(void)
{
	write32(SWR_TRIG_SYS_RST, clk_rst_rst_devices_l_ptr);
	halt();
}

static void udelay(unsigned usecs)
{
	uint32_t start = read32(timer_us_ptr);
	while (read32(timer_us_ptr) - start < usecs)
		;
}



/* Accessors. */

static int wakeup_on_lp(void)
{
	return !!(read32(pmc_ctlr_scratch4_ptr) & PMC_SCRATCH4_LP);
}

static uint32_t get_wakeup_vector(void)
{
	return read32(pmc_ctlr_scratch41_ptr);
}

static unsigned get_osc_freq(void)
{
	return (read32(clk_rst_osc_ctrl_ptr) & OSC_FREQ_MASK) >> OSC_FREQ_SHIFT;
}



/* Clock configuration. */

static void config_oscillator(void)
{
	// Read oscillator drive strength from OSC_EDPD_OVER.XOFS and copy
	// to OSC_CTRL.XOFS and set XOE.
	uint32_t xofs = (read32(pmc_ctlr_osc_edpd_over_ptr) &
		    PMC_XOFS_MASK) >> PMC_XOFS_SHIFT;

	uint32_t osc_ctrl = read32(clk_rst_osc_ctrl_ptr);
	osc_ctrl &= ~OSC_XOFS_MASK;
	osc_ctrl |= (xofs << OSC_XOFS_SHIFT);
	osc_ctrl |= OSC_XOE;
	write32(osc_ctrl, clk_rst_osc_ctrl_ptr);
}

static void config_pllu(void)
{
	// Figure out what parameters to use for PLLU.
	uint32_t divm, divn, cpcon, lfcon;
	switch (get_osc_freq()) {
	case OSC_FREQ_12:
	case OSC_FREQ_48:
		divm = 0x0c;
		divn = 0x3c0;
		cpcon = 0x0c;
		lfcon = 0x02;
		break;
	case OSC_FREQ_16P8:
		divm = 0x07;
		divn = 0x190;
		cpcon = 0x05;
		lfcon = 0x02;
		break;
	case OSC_FREQ_19P2:
	case OSC_FREQ_38P4:
		divm = 0x04;
		divn = 0xc8;
		cpcon = 0x03;
		lfcon = 0x02;
		break;
	case OSC_FREQ_26:
		divm = 0x1a;
		divn = 0x3c0;
		cpcon = 0x0c;
		lfcon = 0x02;
		break;
	default:
		// Map anything that's not recognized to 13MHz.
		divm = 0x0d;
		divn = 0x3c0;
		cpcon = 0x0c;
		lfcon = 0x02;
	}

	// Configure PLLU.
	uint32_t base = PLLU_BYPASS | PLLU_OVERRIDE |
			(divn << PLLU_DIVN_SHIFT) | (divm << PLLU_DIVM_SHIFT);
	write32(base, clk_rst_pllu_base_ptr);
	uint32_t misc = (cpcon << PLLU_CPCON_SHIFT) |
			(lfcon << PLLU_LFCON_SHIFT);
	write32(misc, clk_rst_pllu_misc_ptr);

	// Enable PLLU.
	base &= ~PLLU_BYPASS;
	base |= PLLU_ENABLE;
	write32(base, clk_rst_pllu_base_ptr);
	misc |= PLLU_LOCK_ENABLE;
	write32(misc, clk_rst_pllu_misc_ptr);
}

static void config_tsc(void)
{
	// Tell the TSC the oscillator frequency.
	switch (get_osc_freq()) {
	case OSC_FREQ_12:
		write32(12000000, sysctr_cntfid0_ptr);
		break;
	case OSC_FREQ_48:
		write32(48000000, sysctr_cntfid0_ptr);
		break;
	case OSC_FREQ_16P8:
		write32(16800000, sysctr_cntfid0_ptr);
		break;
	case OSC_FREQ_19P2:
		write32(19200000, sysctr_cntfid0_ptr);
		break;
	case OSC_FREQ_38P4:
		write32(38400000, sysctr_cntfid0_ptr);
		break;
	case OSC_FREQ_26:
		write32(26000000, sysctr_cntfid0_ptr);
		break;
	default:
		// Default to 13MHz.
		write32(13000000, sysctr_cntfid0_ptr);
		break;
	}

	// Enable the TSC.
	setbits32(TSC_CNTCR_ENABLE | TSC_CNTCR_HDBG, sysctr_cntcr_ptr);
}



/* Function unit configuration. */

static void config_core_sight(void)
{
	// Enable the CoreSight clock.
	write32(CLK_ENB_CSITE, clk_rst_clk_out_enb_u_set_ptr);

	/*
	 * De-assert CoreSight reset.
	 * NOTE: We're leaving the CoreSight clock on the oscillator for
	 *       now. It will be restored to its original clock source
	 *       when the CPU-side restoration code runs.
	 */
	write32(SWR_CSITE_RST, clk_rst_rst_dev_u_clr_ptr);
}

static void config_mselect(void)
{
	// Set MSELECT clock source to PLLP with 1:4 divider.
	write32((6 << MSELECT_CLK_DIV_SHIFT) | MSELECT_CLK_SRC_PLLP_OUT0,
		clk_rst_clk_src_mselect_ptr);

	// Enable clock to MSELECT.
	write32(CLK_ENB_MSELECT, clk_rst_clk_enb_v_set_ptr);

	udelay(2);

	// Bring MSELECT out of reset.
	write32(SWR_MSELECT_RST, clk_rst_rst_dev_v_clr_ptr);
}



/* Resets. */

static void clear_cpu_resets(void)
{
	// Take the non-cpu of the G and LP clusters out of reset.
	write32(CLR_NONCPURESET, clk_rst_rst_cpulp_cmplx_clr_ptr);
	write32(CLR_NONCPURESET, clk_rst_rst_cpug_cmplx_clr_ptr);

	// Clear software controlled reset of the slow cluster.
	write32(CLR_CPURESET0 | CLR_DBGRESET0 | CLR_CORERESET0 | CLR_CXRESET0,
		clk_rst_rst_cpulp_cmplx_clr_ptr);

	// Clear software controlled reset of the fast cluster.
	write32(CLR_CPURESET0 | CLR_DBGRESET0 | CLR_CORERESET0 | CLR_CXRESET0 |
		CLR_CPURESET1 | CLR_DBGRESET1 | CLR_CORERESET1 | CLR_CXRESET1 |
		CLR_CPURESET2 | CLR_DBGRESET2 | CLR_CORERESET2 | CLR_CXRESET2 |
		CLR_CPURESET3 | CLR_DBGRESET3 | CLR_CORERESET3 | CLR_CXRESET3,
		clk_rst_rst_cpug_cmplx_clr_ptr);
}



/* Power. */

static void power_on_partition(unsigned id)
{
	uint32_t bit = 0x1 << id;
	if (!(read32(pmc_ctlr_pwrgate_status_ptr) & bit)) {
		// Partition is not on. Turn it on.
		write32(id | PWRGATE_TOGGLE_START, pmc_ctlr_pwrgate_toggle_ptr);

		// Wait until the partition is powerd on.
		while (!(read32(pmc_ctlr_pwrgate_status_ptr) & bit))
			;

		// Wait until clamp is off.
		while (read32(pmc_ctlr_clamp_status_ptr) & bit)
			;
	}
}

static void power_on_main_cpu(void)
{
	/*
	 * Reprogram PMC_CPUPWRGOOD_TIMER register:
	 *
	 * XXX This is a fragile assumption. XXX
	 * The kernel prepares PMC_CPUPWRGOOD_TIMER based on a 32768Hz clock.
	 * Note that PMC_CPUPWRGOOD_TIMER is running at pclk.
	 *
	 * We need to reprogram PMC_CPUPWRGOOD_TIMER based on the current pclk
	 * which is at 408Mhz (pclk = sclk = pllp_out0) after reset. Multiply
	 * PMC_CPUPWRGOOD_TIMER by 408M / 32K.
	 *
	 * Save the original PMC_CPUPWRGOOD_TIMER register which we need to
	 * restore after the CPU is powered up.
	 */
	uint32_t orig_timer = read32(pmc_ctlr_cpupwrgood_timer_ptr);

	write32(orig_timer * (408000000 / 32768),
		pmc_ctlr_cpupwrgood_timer_ptr);

	if (wakeup_on_lp()) {
		power_on_partition(PARTID_C1NC);
		power_on_partition(PARTID_CELP);
	} else {
		power_on_partition(PARTID_CRAIL);
		power_on_partition(PARTID_C0NC);
		power_on_partition(PARTID_CE0);
	}

	// Give I/O signals time to stablize.
	write32(20 | EVENT_MSEC | FLOW_MODE_STOP,
		flow_ctlr_halt_cop_events_ptr);

	// Restore the original PMC_CPUPWRGOOD_TIMER.
	write32(orig_timer, pmc_ctlr_cpupwrgood_timer_ptr);
}



/* Entry point. */

void lp0_resume(void)
{
	// If not on the AVP, reset.
	if (read32(up_tag_ptr) != UP_TAG_AVP)
		reset();

	config_oscillator();

	// Tell the flow controller which cluster to wake up. The default is
	// the fast cluster.
	if (wakeup_on_lp())
		setbits32(FLOW_CLUSTER_ACTIVE_LP,
			  flow_ctlr_cluster_control_ptr);

	// Program SUPER_CCLK_DIVIDER.
	write32(SUPER_CDIV_ENB, clk_rst_super_cclk_div_ptr);

	config_core_sight();

	config_pllu();

	// Set the CPU reset vector.
	write32(get_wakeup_vector(), evp_cpu_reset_ptr);

	// Select CPU complex clock source.
	write32(CCLK_PLLP_BURST_POLICY, clk_rst_cclk_burst_policy_ptr);

	config_mselect();

	// Disable PLLX since it isn't used as CPU clock source.
	clrbits32(PLLX_ENABLE, clk_rst_pllx_base_ptr);

	// Set CAR2PMC_CPU_ACK_WIDTH to 408.
	uint32_t ack_width = read32(clk_rst_cpu_softrst_ctrl2_ptr);
	ack_width &= ~CAR2PMC_CPU_ACK_WIDTH_MASK;
	ack_width |= 408 << CAR2PMC_CPU_ACK_WIDTH_SHIFT;
	write32(ack_width, clk_rst_cpu_softrst_ctrl2_ptr);

	// Enable the CPU complex clock.
	write32(CLK_ENB_CPU, clk_rst_clk_enb_l_set_ptr);
	write32(CLK_ENB_CPUG | CLK_ENB_CPULP, clk_rst_clk_enb_v_set_ptr);

	clear_cpu_resets();

	config_tsc();

	// Disable VPR.
	write32(0, mc_video_protect_size_mb_ptr);
	write32(VIDEO_PROTECT_WRITE_ACCESS_DISABLE,
		mc_video_protect_reg_ctrl_ptr);

	power_on_main_cpu();

	// Halt the AVP.
	while (1)
		write32(FLOW_MODE_STOP | EVENT_JTAG,
			flow_ctlr_halt_cop_events_ptr);
}



/* Header. */

extern uint8_t blob_data;
extern uint8_t blob_data_size;
extern uint8_t blob_total_size;

struct lp0_header {
	uint32_t length_insecure;	// Insecure total length.
	uint32_t reserved[3];
	uint8_t rsa_modulus[256];	// RSA key modulus.
	uint8_t aes_signature[16];	// AES signature.
	uint8_t rsa_signature[256];	// RSA-PSS signature.
	uint8_t random_aes_block[16];	// Random data, may be zero.
	uint32_t length_secure;		// Secure total length.
	uint32_t destination;		// Where to load the blob in iRAM.
	uint32_t entry_point;		// Entry point for the blob.
	uint32_t code_length;		// Length of just the data.
} __attribute__((packed));

struct lp0_header header __attribute__((section(".header"))) =
{
	.length_insecure = (uintptr_t)&blob_total_size,
	.length_secure = (uintptr_t)&blob_total_size,
	.destination = (uintptr_t)&blob_data,
	.entry_point = (uintptr_t)&lp0_resume,
	.code_length = (uintptr_t)&blob_data_size
};
