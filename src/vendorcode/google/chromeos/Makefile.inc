##
## This file is part of the coreboot project.
##
## Copyright (C) 2011 The ChromiumOS Authors.  All rights reserved.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; version 2 of the License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
##

romstage-$(CONFIG_ARCH_ROMSTAGE_X86_32) += vbnv_cmos.c
ramstage-$(CONFIG_ARCH_RAMSTAGE_X86_32) += vbnv_cmos.c
romstage-$(CONFIG_ARCH_ROMSTAGE_ARMV7) += vbnv_ec.c
ramstage-$(CONFIG_ARCH_RAMSTAGE_ARMV7) += vbnv_ec.c
romstage-$(CONFIG_ARCH_ROMSTAGE_X86_32) += vboot.c

ramstage-y += gnvs.c
romstage-y += fmap.c
ramstage-y += fmap.c
ramstage-$(CONFIG_CHROMEOS_RAMOOPS) += ramoops.c
smm-y += fmap.c
romstage-y += vpd_decode.c cros_vpd.c
ramstage-y += vpd_decode.c cros_vpd.c

ifeq ($(MOCK_TPM),1)
CFLAGS_common += -DMOCK_TPM=1
else
CFLAGS_common += -DMOCK_TPM=0
endif

ifeq ($(CONFIG_VBOOT_VERIFY_FIRMWARE),y)
romstage-y += vboot_handoff.c
ramstage-y += vboot_handoff.c
romstage-y += vboot_loader.c
rmodules_$(ARCH-romstage-y)-y += vboot_wrapper.c

VB_LIB = $(obj)/external/vboot_reference/vboot_fw.a
# Currently, vboot comes into picture only during the romstage, thus
# is compiled for being used in romstage only. Since, we are splitting
# up all components in one of the three stages of coreboot, vboot seems
# most logical to fall under the romstage. Thus, all references to arch
# and other compiler stuff for vboot is using the romstage arch.
VB_FIRMWARE_ARCH := $(ARCHDIR-$(ARCH-romstage-y))
VB_SOURCE := vboot_reference

# Add the vboot include paths.
CPPFLAGS_common += -I$(VB_SOURCE)/firmware/include

VBOOT_STUB_ELF = $(obj)/vendorcode/google/chromeos/vbootstub.elf
VBOOT_STUB = $(VBOOT_STUB_ELF).rmod
VBOOT_STUB_DOTO = $(VBOOT_STUB_ELF:.elf=.o)

# Dependency for the vboot rmodules. Ordering matters.
VBOOT_STUB_DEPS += $(obj)/vendorcode/google/chromeos/vboot_wrapper.rmodules_$(ARCH-romstage-y).o
VBOOT_STUB_DEPS += $(obj)/lib/memcmp.rmodules_$(ARCH-romstage-y).o
VBOOT_STUB_DEPS += $(obj)/arch/x86/lib/memset.rmodules_$(ARCH-romstage-y).o
VBOOT_STUB_DEPS += $(obj)/arch/x86/lib/memcpy.rmodules_$(ARCH-romstage-y).o
VBOOT_STUB_DEPS += $(VB_LIB)
# Remove the '-include' option since that will break vboot's build and ensure
# vboot_reference can get to coreboot's include files.
VBOOT_CFLAGS += $(patsubst -I%,-I../%,$(filter-out -include $(src)/include/kconfig.h, $(CFLAGS_romstage)))
VBOOT_CFLAGS += -DVBOOT_DEBUG

$(VBOOT_STUB_DOTO): $(VBOOT_STUB_DEPS)
	$(CC_rmodules_$(ARCH-romstage-y)) $(CFLAGS_rmodules_$(ARCH-romstage-y)) -nostdlib -r -o $@ $^

# Link the vbootstub module with a 64KiB-byte heap.
$(eval $(call rmodule_link,$(VBOOT_STUB_ELF), $(VBOOT_STUB_DOTO), 0x10000,$(ARCH-romstage-y)))

# Build vboot library without the default includes from coreboot proper.
$(VB_LIB):
	@printf "    MAKE       $(subst $(obj)/,,$(@))\n"
	$(Q)FIRMWARE_ARCH=$(VB_FIRMWARE_ARCH) \
		CC="$(CC_romstage)" \
		CFLAGS="$(VBOOT_CFLAGS)" \
		make -C $(VB_SOURCE) \
		BUILD=../$(dir $(VB_LIB)) \
		V=$(V) \
		fwlib

endif
