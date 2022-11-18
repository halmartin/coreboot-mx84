/*
 * miles - the Meraki Intermediate Loader for Embedded Systems
 *
 * Copyright (C) 2015 Cisco Systems, Inc.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <libpayload-config.h>
#include <libpayload.h>
#include <libfdt.h>
#include <lib.h>
#include "mplatform.h"

static int
find_itb_config(const void* itb, const char* config_name,
                const char** kernel_name, const char** ramdisk_name,
                const char** fdt_name)
{
    int len;

    int configs_offset = fdt_path_offset(itb, "/configurations");
    if (configs_offset < 0) {
        printf("%s: error finding /configurations: %s\n", __func__,
                fdt_strerror(configs_offset));
        return -1;
    }

    if (!config_name || config_name[0] == '\0') {
        config_name = (const char*)
            fdt_getprop(itb, configs_offset, "default", &len);
        if (!config_name) {
            fprintf(stderr,
                    "%s: error finding default configuration name: %s\n",
                    __func__, fdt_strerror(len));
            return -1;
        }
    }

    int config_offset = fdt_subnode_offset(itb, configs_offset, config_name);
    if (config_offset < 0) {
        printf("%s: error finding config %s: %s\n", __func__,
                config_name, fdt_strerror(len));
        return -1;
    }

    const char* description = (const char*)
        fdt_getprop(itb, config_offset, "description", &len);
    if (len < 0 && len != -FDT_ERR_NOTFOUND) {
        printf("%s: error finding config %s description: %s\n",
                __func__, config_name, fdt_strerror(len));
        return -1;
    }

    printf("Using itb config %s (%s)\n", config_name,
           description ? description : "<NO DESC>");

    *kernel_name = (const char*)
        fdt_getprop(itb, config_offset, "kernel", &len);
    if (len < 0) {
        printf("%s: error finding config %s kernel: %s\n",
                __func__, config_name, fdt_strerror(len));
        return -1;
    }

    if (ramdisk_name) {
        *ramdisk_name = (const char*)fdt_getprop(itb, config_offset, "ramdisk", &len);
        if (len < 0 && len != -FDT_ERR_NOTFOUND) {
            printf("%s: error finding config %s ramdisk: %s\n",
                   __func__, config_name, fdt_strerror(len));
            return -1;
        }
    }

    if (fdt_name) {
        *fdt_name = (const char*)fdt_getprop(itb, config_offset, "fdt", &len);
        if (len < 0 && len != -FDT_ERR_NOTFOUND) {
            printf("%s: error finding config %s fdt: %s\n",
                   __func__, config_name, fdt_strerror(len));
            return -1;
        }
    }

    return 0;
}

static const void*
find_itb_subimage(void *itb, int images_offset, const char *name,
                  int *imagelen,
                  uintptr_t *loadaddr,
                  uintptr_t *entryaddr)
{
    int len;

    int subimage_offset = fdt_subnode_offset(itb, images_offset, name);
    if (subimage_offset < 0) {
	printf("%s: error finding %s: %s\n", __func__,
		name, fdt_strerror(subimage_offset));
	return NULL;
    }

    const char *desc = (const char *)
	fdt_getprop(itb, subimage_offset, "description", &len);

    /* Report the description if present. */

    if (desc) {
	printf("Description: %s\n", desc);
    } else {
	printf("%s: error finding %s/%s: %s\n", __func__,
		name, "description", fdt_strerror(len));
    }

    // Get the image data

    const void *image_addr = fdt_getprop(itb, subimage_offset, "data", &len);
    if (!image_addr) {
	printf("%s: error finding %s/%s: %s\n", __func__,
		name, "data", fdt_strerror(len));
	return NULL;
    }

    *imagelen = len;

    uint8_t digest[SHA1_DIGEST_LENGTH];
    int sha1_checked = 0;

    sha1((uint8_t*)image_addr, len, digest);

    // Check all of the hashes that we know how to check. That's just
    // going to be SHA1 for now.

    for (int hash_offset = fdt_first_subnode(itb, subimage_offset);
	 hash_offset >= 0;
	 hash_offset = fdt_next_subnode(itb, hash_offset)) {

	const char *hash_name = fdt_get_name(itb, hash_offset, NULL);

	if (strncmp(hash_name, "hash", 4) != 0)
	    continue;

	const char *algo = (const char *)fdt_getprop(itb, hash_offset, "algo",
						     &len);
	if (!algo) {
	    printf("%s: error finding %s/%s/algo: %s\n", __func__,
		    name, hash_name, fdt_strerror(len));
	}

	if (strcmp(algo, "sha1") != 0) {
	    printf("%s: Ignoring unknown algorithm %s\n", __func__,
		    algo);
	    continue;
	}
	const char *value = (const char *)fdt_getprop(itb, hash_offset, "value",
						      &len);
	if (!value) {
	    printf("%s: error finding %s/%s/value: %s\n", __func__,
		    name, hash_name, fdt_strerror(len));
	}

	if (len != SHA1_DIGEST_LENGTH) {
	    printf("%s: SHA1 digest length %d invalid\n",
		    __func__, len);
	    return NULL;
	}

	if (memcmp(digest, value, SHA1_DIGEST_LENGTH) != 0) {
	    printf("%s: SHA1 mismatch\n", __func__);
	    return NULL;
	} else {
	    sha1_checked = 1;
	}
    }

    if (!sha1_checked) {
	printf("%s: Warning, no SHA1 property to check\n", __func__);
    }

    if (loadaddr) {
	const char *load_prop = (const char *)
	    fdt_getprop(itb, subimage_offset, "load", &len);
	if (!load_prop) {
	    printf("%s: error finding %s/%s: %s\n", __func__,
                   name, "load", fdt_strerror(len));
	    *loadaddr = 0;
	} else {
	    *loadaddr = (uintptr_t)((load_prop[0] << 24)
                                    | (load_prop[1] << 16)
                                    | (load_prop[2] << 8)
                                    | (load_prop[3]));
	}
    }


    if (entryaddr) {
	const char *entry_prop = (const char *)
	    fdt_getprop(itb, subimage_offset, "entry", &len);
	if (!entry_prop) {
	    printf("%s: error finding %s/%s: %s\n", __func__,
                   name, "load", fdt_strerror(len));
	    *entryaddr = 0;
	} else {
	    *entryaddr = (uintptr_t)((entry_prop[0] << 24)
                                     | (entry_prop[1] << 16)
                                     | (entry_prop[2] << 8)
                                     | (entry_prop[3]));
	}
    }

    return image_addr;
}


int
load_bootkernel(struct miles_buffer* bk, const char* config_name)
{
    if (fdt_check_header(bk->ptr) < 0) {
        printf("Bad header\n");
        return -1;
    }

    int len;
    const char *meraki_build = (const char *)
	fdt_getprop(bk->ptr, 0, "meraki-build", &len);
    if (meraki_build) {
	printf("Meraki-build (bootkernel) is %s\n", meraki_build);
    } else {
        printf("Meraki-build property not found\n");
    }

    int images_offset = fdt_path_offset(bk->ptr, "/images");
    if (images_offset < 0) {
	printf("%s: error finding /images: %s\n", __func__,
               fdt_strerror(images_offset));
	return -1;
    }

    uintptr_t kernel_load, kernel_entry;
    int kernel_size;

    const char* kernel_name = NULL;
    const char* ramdisk_name = NULL;
    const char* fdt_name = NULL;

    if (find_itb_config(bk->ptr, config_name, &kernel_name, &ramdisk_name, &fdt_name) < 0) {
        printf("%s: Couldn't find config.", __func__);
        return -1;
    }

    if (!kernel_name) {
        printf("%s: No kernel specified!", __func__);
        return -1;
    }

    const void* kernel_data = find_itb_subimage(bk->ptr, images_offset, kernel_name,
                                          &kernel_size, &kernel_load,
                                          &kernel_entry);
    if (!kernel_data) {
        printf("%s: Couldn't find kernel image \"%s\"", __func__, kernel_name);
        return -1;
    }

    int ramdisk_size = 0;
    const void* ramdisk_data = NULL;

    if (ramdisk_name) {
       ramdisk_data = find_itb_subimage(bk->ptr, images_offset, ramdisk_name,
                                        &ramdisk_size, NULL, NULL);
       if (!ramdisk_data) {
           printf("%s: Couldn't find initrd image \"%s\"", __func__, ramdisk_name);
           return -1;
       }
    }

    int fdt_size = 0;
    const void* fdt_data = NULL;

    if (fdt_name) {
        fdt_data = find_itb_subimage(bk->ptr, images_offset, fdt_name, &fdt_size, NULL, NULL);

       if (!fdt_data) {
           printf("%s: Couldn't find fdt image \"%s\"", __func__, fdt_name);
           return -1;
       }
    }

    linux_load(kernel_data, kernel_size, ramdisk_data, ramdisk_size, fdt_data, fdt_size, NULL);
    printf("Load failed!\n");

    return -1;
};

int  __attribute__((noreturn))
main(void)
{
    lib_get_sysinfo();
    console_init();
    printf("miles lives!\n");
    relocate();

    struct miles_platform_info info;

    if (platform_get_info(&info) < 0)
        fatal("Unable to get bootkernel locations!\n");

    printf("Trying bootkernel 1...\n");
    load_bootkernel(&info.bootkernels[0], info.itb_config_name);
    printf("Trying bootkernel 2...\n");
    load_bootkernel(&info.bootkernels[1], info.itb_config_name);

    fatal("Unable to load either bootkernel!\n");
}
