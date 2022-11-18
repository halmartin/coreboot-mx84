/*
 * Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <console/console.h>

#include <cbfs.h>
#include <stdlib.h>
#include <string.h>

#include "cros_vpd.h"
#include "fmap.h"
#include "lib_vpd.h"
#include "vpd_tables.h"

/*
 * Static variables are available in ramstage (all platforms), and romstage for
 * some platforms (ex, ARM, which uses SRAM).
 */
#if defined(__PRE_RAM__) && CONFIG_ARCH_X86
#define STATIC_VAR
#else
#define STATIC_VAR	static
#endif

/* Currently we only support Google VPD 2.0, which has a fixed offset. */
enum {
	GOOGLE_VPD_2_0_OFFSET = 0x600,
};

struct vpd_gets_arg {
	const uint8_t *key;
	const uint8_t *value;
	int32_t key_len, value_len;
	int matched;
};

static int cros_vpd_load(uint8_t **vpd_address, int32_t *vpd_size)
{
	STATIC_VAR int cached = 0;
	STATIC_VAR uint8_t *cached_address = NULL;
	STATIC_VAR int32_t cached_size = 0;
	STATIC_VAR int result = -1;
	struct google_vpd_info info;
	int32_t base;

	const struct fmap_area *area;
	struct cbfs_media media;

	if (cached) {
		*vpd_address = cached_address;
		*vpd_size = cached_size;
		return result;
	}

	cached = 1;
	area = find_fmap_area(fmap_find(), "RO_VPD");
	if (!area) {
		printk(BIOS_ERR, "%s: No RO_VPD FMAP section.\n", __func__);
		return result;
	}
	if (area->size <= GOOGLE_VPD_2_0_OFFSET + sizeof(info)) {
		printk(BIOS_ERR, "%s: Too small (%d) for Google VPD 2.0.\n",
		       __func__, area->size);
		return result;
	}

	base = area->offset + GOOGLE_VPD_2_0_OFFSET;
	cached_size = area->size - GOOGLE_VPD_2_0_OFFSET;
	init_default_cbfs_media(&media);
	media.open(&media);

	/* Try if we can find a google_vpd_info, otherwise read whole VPD. */
	if (media.read(&media, &info, base, sizeof(info)) == sizeof(info) &&
	    memcmp(info.header.magic, VPD_INFO_MAGIC, sizeof(info.header.magic))
	    == 0 && cached_size >= info.size + sizeof(info)) {
		base += sizeof(info);
		cached_size = info.size;
	}

	cached_address = media.map(&media, base, cached_size);
	media.close(&media);
	if (cached_address) {
		*vpd_address = cached_address;
		*vpd_size = cached_size;
		printk(BIOS_DEBUG, "%s: Got VPD: %#x+%#x\n", __func__, base,
		       cached_size);
		result = 0;
	}
	return result;
}

static int vpd_gets_callback(const uint8_t *key, int32_t key_len,
			       const uint8_t *value, int32_t value_len,
			       void *arg)
{
	struct vpd_gets_arg *result = (struct vpd_gets_arg *)arg;
	if (key_len != result->key_len ||
	    memcmp(key, result->key, key_len) != 0)
		/* Returns VPD_OK to continue parsing. */
		return VPD_OK;

	result->matched = 1;
	result->value = value;
	result->value_len = value_len;
	/* Returns VPD_FAIL to stop parsing. */
	return VPD_FAIL;
}

char *cros_vpd_gets(const char *key, char *buffer, int size)
{
	uint8_t *vpd_address = NULL;
	int32_t vpd_size = 0;
	struct vpd_gets_arg arg = {0};
	int consumed = 0;

	if (cros_vpd_load(&vpd_address, &vpd_size) != 0) {
		return NULL;
	}

	arg.key = (const uint8_t *)key;
	arg.key_len = strlen(key);

	while (VPD_OK == decodeVpdString(vpd_size, vpd_address, &consumed,
					 vpd_gets_callback, &arg)) {
		/* Iterate until found or no more entries. */
	}

	if (!arg.matched)
		return NULL;

	if (size < arg.value_len + 1)
		size = arg.value_len + 1;
	memcpy(buffer, arg.value, size - 1);
	buffer[size - 1] = '\0';
	return buffer;
}

