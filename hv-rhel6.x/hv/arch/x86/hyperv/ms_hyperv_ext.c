/*
 *
 * Copyright (C) 2018, Microsoft, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 */

#include <linux/types.h>
#include <lis/asm/hyperv.h>
#include <lis/asm/mshyperv.h>

/* See the comment near the struct definition to know why we need this */
struct ms_hyperv_info_external ms_hyperv_ext;


/* Copied from the upstream's ms_hyperv_init_platform() */
void init_ms_hyperv_ext(void)
{
	/*
	 * Extract the features and hints
	 */

	ms_hyperv_ext.features = cpuid_eax(HYPERV_CPUID_FEATURES);
	ms_hyperv_ext.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
	ms_hyperv_ext.hints = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

	pr_info("Hyper-V: detected features 0x%x, hints 0x%x\n",
		ms_hyperv_ext.features, ms_hyperv_ext.hints);
}
