
ifndef PLATFORM
$(error No platform defined.)
endif

BUILD_DIR = $(abspath build_$(PLATFORM))

COREBOOT_ROOT = $(abspath ..)
LIBPAYLOAD_DIR := $(COREBOOT_ROOT)/payloads/libpayload
LIBPAYLOAD_INSTALL_DIR := $(BUILD_DIR)/libpayload
LIBPAYLOAD_BUILD_DIR := $(BUILD_DIR)/libpayload-build
LIBPAYLOAD := $(LIBPAYLOAD_DESTDIR)/lib/libpayload.a

# Coreboot has problems with an absolute path for build targets
COREBOOT_BUILD_DIR = $(BUILD_DIR)/coreboot
COREBOOT_ROOT_REL_BUILD_DIR = $(subst $(COREBOOT_ROOT)/,,$(COREBOOT_BUILD_DIR))
CONFIGS_DIR := $(abspath configs)

MILES_DIR := miles
MILES_BUILD_DIR := $(BUILD_DIR)/miles

all: coreboot

crossgcc:
	$(MAKE) -C $(COREBOOT_ROOT) $@

crossgcc-%:
	$(MAKE) -C $(COREBOOT_ROOT) $@

$(COREBOOT_BUILD_DIR)/.config: $(CONFIGS_DIR)/config.$(PLATFORM)
	mkdir -p $(COREBOOT_BUILD_DIR)
	sed -e "s|CONFIG_PAYLOAD_FILE=\".*\"|CONFIG_PAYLOAD_FILE=\"$(MILES_BUILD_DIR)/miles.elf\"|" \
		$< > $@
	$(MAKE) -C $(COREBOOT_ROOT) DOTCONFIG=$@ obj=$(COREBOOT_ROOT_REL_BUILD_DIR) oldconfig

$(LIBPAYLOAD_BUILD_DIR)/.config: $(CONFIGS_DIR)/config.libpayload.$(PLATFORM)
	mkdir -p $(LIBPAYLOAD_BUILD_DIR)
	cp $< $@
	$(MAKE) -C $(LIBPAYLOAD_DIR) DOTCONFIG=$@ obj=$(LIBPAYLOAD_BUILD_DIR) oldconfig

libpayload: $(LIBPAYLOAD_BUILD_DIR)/.config
	@printf "Building libpayload...\n"
	$(MAKE) -C $(LIBPAYLOAD_DIR) DOTCONFIG=$< obj=$(LIBPAYLOAD_BUILD_DIR) DESTDIR=$(BUILD_DIR) install

libpayload-menuconfig:
	$(MAKE) -C $(LIBPAYLOAD_DIR) DOTCONFIG=$(CONFIGS_DIR)/config.libpayload.$(PLATFORM) menuconfig

coreboot: $(COREBOOT_BUILD_DIR)/.config miles
	@printf "Building coreboot...\n"
	$(MAKE) -C $(COREBOOT_ROOT) DOTCONFIG=$< obj=$(COREBOOT_ROOT_REL_BUILD_DIR)

coreboot-menuconfig:
	$(MAKE) -C $(COREBOOT_ROOT) DOTCONFIG=$(CONFIGS_DIR)/config.$(PLATFORM) menuconfig

miles: $(COREBOOT_BUILD_DIR)/.config libpayload
	make -C $(MILES_DIR) obj=$(MILES_BUILD_DIR) LIBPAYLOAD_PREFIX=$(LIBPAYLOAD_INSTALL_DIR) COREBOOT_DOTCONFIG=$< PLATFORM=$(PLATFORM)

clean:
	make -C $(COREBOOT_ROOT) obj=$(COREBOOT_ROOT_REL_BUILD_DIR) clean
	make -C $(LIBPAYLOAD_DIR) obj=$(LIBPAYLOAD_BUILD_DIR) clean
	make -C $(MILES_DIR) obj=$(MILES_BUILD_DIR) LIBPAYLOAD_PREFIX=$(LIBPAYLOAD_INSTALL_DIR) PLATFORM=$(PLATFORM) clean
	rm -f $(COREBOOT_BUILD_DIR)/.config $(LIBPAYLOAD_BUILD_DIR)/.config

distclean:
	rm -rf $(BUILD_DIR)

.PHONY: libpayload all clean distclean crossgcc crossgcc-% coreboot miles

