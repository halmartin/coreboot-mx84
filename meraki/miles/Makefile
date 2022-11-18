#
# miles - the Meraki Intermediate Loader for Embedded Systems
#
# This makefile was largely adopted from FILO
#
# Copyright (C) 2008-2009 by coresystems GmbH
# Copyright (C) 2015 Cisco Systems, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

export PROGRAM_NAME := miles
export PROGRAM_VERSION := 0.1.0

export src := $(shell pwd)
export srctree := $(src)
export obj := $(src)/build

UNAME_RELEASE := $(shell uname -r)
BUILD_INFO = ($(shell whoami)@$(shell hostname)) $(shell LANG=C date)

ifndef LIBPAYLOAD_PREFIX
$(error LIBPAYLOAD_PREFIX not specified)
endif

ifndef COREBOOT_DOTCONFIG
$(error COREBOOT_DOTCONFIG not specified)
endif

# Make is silent per default, but 'make V=1' will show all compiler calls.
Q=@
ifneq ($(V),1)
ifneq ($(Q),)
.SILENT:
endif
endif

try-run = $(shell set -e;		\
	TMP=".$$$$.tmp";		\
	if ($(1)) > /dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -rf "$$TMP")

cc-option = $(call try-run,$(CC) $(1) -S -xc /dev/null -o "$$TMP",$(1),$(2))

include ../../.xcompile
include $(COREBOOT_DOTCONFIG)

ARCHDIR-$(CONFIG_ARCH_ARM)     := arm
ARCHDIR-$(CONFIG_ARCH_ARM64)   := arm64
ARCHDIR-$(CONFIG_ARCH_X86)     := x86

ARCH-y := $(ARCHDIR-y)

# If architecture folder name is different from GCC binutils architecture name,
# override here.
ARCH-$(CONFIG_ARCH_ARM)     := arm
ARCH-$(CONFIG_ARCH_ARM64)   := arm64
ARCH-$(CONFIG_ARCH_X86)     := x86_32

CC := $(CC_$(ARCH-y))
AS := $(AS_$(ARCH-y))
LD := $(LD_$(ARCH-y))
NM := $(NM_$(ARCH-y))
OBJCOPY := $(OBJCOPY_$(ARCH-y))
OBJDUMP := $(OBJDUMP_$(ARCH-y))
READELF := $(READELF_$(ARCH-y))
STRIP := $(STRIP_$(ARCH-y))
AR := $(AR_$(ARCH-y))
CFLAGS := $(CFLAGS_$(ARCH-y))

HOSTCC ?= gcc
HOSTCXX ?= g++
HOSTCFLAGS := -I$(srck) -I$(objk) -pipe
HOSTCXXFLAGS := -I$(srck) -I$(objk) -pipe

#LIBPAYLOAD_PREFIX ?= $(obj)/libpayload
LIBPAYLOAD = $(LIBPAYLOAD_PREFIX)/lib/libpayload.a
INCPAYLOAD = $(LIBPAYLOAD_PREFIX)/include
LIBGCC = $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)
GCCINCDIR = $(shell $(CC) -print-search-dirs | head -n 1 | cut -d' ' -f2)include

CPPFLAGS := -nostdinc
CPPFLAGS += -I$(INCPAYLOAD) -I$(INCPAYLOAD)/$(ARCHDIR-y)
CPPFLAGS += -I$(ARCHDIR-y)/include -Iinclude -I$(obj)
CPPFLAGS += -I$(GCCINCDIR)

CFLAGS := -Wall -Wshadow -Os -pipe -std=gnu99 -Wno-unused-variable
CFLAGS += -fomit-frame-pointer -fno-common -ffreestanding -fno-strict-aliasing
CFLAGS += $(call cc-option, -fno-stack-protector,)

LIBS := $(LIBPAYLOAD) $(LIBGCC)

SUBDIRS-y += main/
SUBDIRS-y += $(ARCHDIR-y)/
SUBDIRS-y += libfdt/

$(foreach subdir,$(SUBDIRS-y),$(eval include $(subdir)/Makefile.inc))

TARGET := $(obj)/miles.elf
OBJS := $(patsubst %,$(obj)/%,$(TARGETS-y))

all: prepare $(TARGET)

$(obj)/miles: $(OBJS) $(LIBPAYLOAD)
	printf "  LD      $(subst $(shell pwd)/,,$(@))\n"
	$(LD) -N -T $(ARCHDIR-y)/ldscript $(OBJS) --start-group $(LIBS) --end-group -o $@

$(TARGET): $(obj)/miles $(obj)/miles.map
	printf "  STRIP   $(subst $(shell pwd)/,,$(@))\n"
	$(STRIP) -s $< -o $@

$(OBJS): $(obj)/version.h | libpayload
$(obj)/%.o: $(src)/%.c
	printf "  CC      $(subst $(shell pwd)/,,$(@))\n"
	$(CC) -MMD $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(obj)/%.S.o: $(src)/%.S
	printf "  AS      $(subst $(shell pwd)/,,$(@))\n"
	$(AS) $(ASFLAGS) -o $@ $<

$(obj)/%.map: $(obj)/%
	printf "  SYMS    $(subst $(shell pwd)/,,$(@))\n"
	$(NM) -n $< > $@

$(obj)/version.h: Makefile
	printf "  GEN     $(subst $(shell pwd)/,,$(@))\n"
	echo '#define PROGRAM_NAME "$(PROGRAM_NAME)"' > $@
	echo '#define PROGRAM_VERSION "$(PROGRAM_VERSION)"' >> $@
	echo '#define PROGRAM_VERSION_FULL "$(PROGRAM_VERSION) $(BUILD_INFO)"' >> $@
	echo '#define BUILD_INFO "$(BUILD_INFO)"' >> $@

$(obj)/%/:
	mkdir -p $@

prepare: $(sort $(dir $(OBJS)))

clean:
	rm -rf $(sort $(dir $(OBJS))) $(obj)/util
	rm -rf $(obj)/version.h

distclean: clean
	rm -rf $(obj)

FORCE:

.PHONY: $(PHONY) prepare clean distclean libpayload FORCE
