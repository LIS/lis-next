/*
 * X86 specific Hyper-V initialization code.
 *
 * Copyright (C) 2016, Microsoft, Inc.
 *
 * Author : K. Y. Srinivasan <kys@microsoft.com>
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
#include <asm/hypervisor.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clockchips.h>
#include <linux/slab.h>


#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
#ifdef CONFIG_X86_64

static struct ms_hyperv_tsc_page *tsc_pg;

static u64 read_hv_clock_tsc(struct clocksource *arg)
{
	u64 current_tick;

	if (tsc_pg->tsc_sequence != 0) {
		/*
		 * Use the tsc page to compute the value.
		 */

		while (1) {
			u64 tmp;
			u32 sequence = tsc_pg->tsc_sequence;
			u64 cur_tsc;
			u64 scale = tsc_pg->tsc_scale;
			s64 offset = tsc_pg->tsc_offset;

			rdtscll(cur_tsc);
			/* current_tick = ((cur_tsc *scale) >> 64) + offset */
			asm("mulq %3"
				: "=d" (current_tick), "=a" (tmp)
				: "a" (cur_tsc), "r" (scale));

			current_tick += offset;
			if (tsc_pg->tsc_sequence == sequence)
				return current_tick;

			if (tsc_pg->tsc_sequence != 0)
				continue;
			/*
			 * Fallback using MSR method.
			 */
			break;
		}
	}
	rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);
	return current_tick;
}

static struct clocksource hyperv_cs_tsc = {
	.name		= "lis_hyperv_clocksource_tsc_page",
	.rating		= 425,
	.read		= read_hv_clock_tsc,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};
#endif

static u64 read_hv_clock_msr(struct clocksource *arg)
{
	u64 current_tick;
	/*
	 * Read the partition counter to get the current tick count. This count
	 * is set to 0 when the partition is created and is incremented in
	 * 100 nanosecond units.
	 */
	rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);
	return current_tick;
}

static struct clocksource hyperv_cs_msr = {
	.name		= "lis_hyperv_clocksource_msr",
	.rating		= 425,
	.read		= read_hv_clock_msr,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};


void *hv_hypercall_pg;
EXPORT_SYMBOL_GPL(hv_hypercall_pg);
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4))
/*
 *  The clocksource is exposed by kernel in RH7.4 and higher.
 *  Avoid redefining it for RH 7.4 and higher.
 */
struct clocksource *hyperv_cs;
EXPORT_SYMBOL_GPL(hyperv_cs);
#endif

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))
int hv_cpu_init(unsigned int cpu)
{
	/*
	 * In RHEL 7.5+, the kernel initializes the hv_vp_index[]. So
	 * in our LIS drivers, we don't need do anything.
	 */
	return 0;
}

void hyperv_init(void)
{
	/*
	 * In RHEL 7.5+, hyperv_init() runs in the kernel: see
	 * <RHEL 7.5+'s src code>/arch/x86/hyperv/hv_init.c: hyperv_init().
	 * So, in our LIS drivers we don't need do anything.
	 */
}
#else

u32 *hv_vp_index;
EXPORT_SYMBOL_GPL(hv_vp_index);

int hv_cpu_init(unsigned int cpu)
{
	u64 msr_vp_index;

	hv_get_vp_index(msr_vp_index);

	hv_vp_index[smp_processor_id()] = msr_vp_index;

	return 0;
}

/*
 * This function is to be invoked early in the boot sequence after the
 * hypervisor has been detected.
 *
 * 1. Setup the hypercall page.
 * 2. Register Hyper-V specific clocksource.
 */
void hyperv_init(void)
{
	u64 guest_id, required_msrs;
	union hv_x64_msr_hypercall_contents hypercall_msr;

	if (x86_hyper != &x86_hyper_ms_hyperv)
		return;

	/* Absolutely required MSRs */
	required_msrs = HV_X64_MSR_HYPERCALL_AVAILABLE |
		HV_X64_MSR_VP_INDEX_AVAILABLE;

	if ((ms_hyperv_ext.features & required_msrs) != required_msrs)
		return;

	/* Allocate percpu VP index */
	hv_vp_index = kmalloc_array(num_possible_cpus(), sizeof(*hv_vp_index),
				    GFP_KERNEL);
	if (!hv_vp_index)
		return;
	/* We'll initialize hv_vp_index[] later in hv_synic_init. */

	/*
	 * Setup the hypercall page and enable hypercalls.
	 * 1. Register the guest ID
	 * 2. Enable the hypercall and register the hypercall page
	 */
	guest_id = generate_guest_id(0, LINUX_VERSION_CODE, 0);
	wrmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id);

	hv_hypercall_pg  = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_RX);
	if (hv_hypercall_pg == NULL) {
		wrmsrl(HV_X64_MSR_GUEST_OS_ID, 0);
		goto free_vp_index;
	}

	rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
	hypercall_msr.enable = 1;
	hypercall_msr.guest_physical_address = vmalloc_to_pfn(hv_hypercall_pg);
	wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	/*
	 * Register Hyper-V specific clocksource.
	 */
#ifdef CONFIG_X86_64
	if (ms_hyperv_ext.features & HV_X64_MSR_REFERENCE_TSC_AVAILABLE) {
		union hv_x64_msr_hypercall_contents tsc_msr;

		tsc_pg = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL);
		if (!tsc_pg)
			goto register_msr_cs;

		hyperv_cs = &hyperv_cs_tsc;

		rdmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr.as_uint64);

		tsc_msr.enable = 1;
		tsc_msr.guest_physical_address = vmalloc_to_pfn(tsc_pg);

		wrmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr.as_uint64);
		clocksource_register_hz(&hyperv_cs_tsc, NSEC_PER_SEC/100);
		return;
	}
#endif
	/*
	 * For 32 bit guests just use the MSR based mechanism for reading
	 * the partition counter.
	 */

register_msr_cs:
	hyperv_cs = &hyperv_cs_msr;
	if (ms_hyperv_ext.features & HV_X64_MSR_TIME_REF_COUNT_AVAILABLE)
		clocksource_register_hz(&hyperv_cs_msr, NSEC_PER_SEC/100);

	return;

free_vp_index:
	kfree(hv_vp_index);
	hv_vp_index = NULL;
}

/*
 * This routine is called before kexec/kdump, it does the required cleanup.
 */

void hyperv_cleanup(void)
{
	union hv_x64_msr_hypercall_contents hypercall_msr;

	/* Reset our OS id */
	wrmsrl(HV_X64_MSR_GUEST_OS_ID, 0);

	/* Reset the hypercall page */
	hypercall_msr.as_uint64 = 0;
	wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	/* Reset the TSC page */
	hypercall_msr.as_uint64 = 0;
	wrmsrl(HV_X64_MSR_REFERENCE_TSC, hypercall_msr.as_uint64);
}
EXPORT_SYMBOL_GPL(hyperv_cleanup);

void hyperv_report_panic(struct pt_regs *regs, long err)
{
	static bool panic_reported;
	u64 guest_id;

	/*
	 * We prefer to report panic on 'die' chain as we have proper
	 * registers to report, but if we miss it (e.g. on BUG()) we need
	 * to report it on 'panic'.
	 */
	if (panic_reported)
		return;
	panic_reported = true;

	rdmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id);

	wrmsrl(HV_X64_MSR_CRASH_P0, err);
	wrmsrl(HV_X64_MSR_CRASH_P1, guest_id);
	wrmsrl(HV_X64_MSR_CRASH_P2, regs->ip);
	wrmsrl(HV_X64_MSR_CRASH_P3, _HV_DRV_VERSION);
	wrmsrl(HV_X64_MSR_CRASH_P4, regs->sp);

	/*
	 * Let Hyper-V know there is crash data available
	 */
	wrmsrl(HV_X64_MSR_CRASH_CTL, HV_CRASH_CTL_CRASH_NOTIFY);
}
EXPORT_SYMBOL_GPL(hyperv_report_panic);


bool hv_is_hypercall_page_setup(void)
{
	union hv_x64_msr_hypercall_contents hypercall_msr;

	/* Check if the hypercall page is setup */
	hypercall_msr.as_uint64 = 0;
	rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	if (!hypercall_msr.enable)
		return false;

	return true;
}

EXPORT_SYMBOL_GPL(hv_is_hypercall_page_setup);
#endif

void hv_print_host_info(void) {
	int hv_host_info_eax;
	int hv_host_info_ebx;
	int hv_host_info_ecx;
	int hv_host_info_edx;

	/*
	 * Extract host information.
	 */
	if (cpuid_eax(HVCPUID_VENDOR_MAXFUNCTION) >= HVCPUID_VERSION) {
		hv_host_info_eax = cpuid_eax(HVCPUID_VERSION);
		hv_host_info_ebx = cpuid_ebx(HVCPUID_VERSION);
		hv_host_info_ecx = cpuid_ecx(HVCPUID_VERSION);
		hv_host_info_edx = cpuid_edx(HVCPUID_VERSION);

		pr_info("Hyper-V Host Build:%d-%d.%d-%d-%d.%d\n",
			hv_host_info_eax, hv_host_info_ebx >> 16,
			hv_host_info_ebx & 0xFFFF, hv_host_info_ecx,
			hv_host_info_edx >> 24, hv_host_info_edx & 0xFFFFFF);
	}
}
EXPORT_SYMBOL_GPL(hv_print_host_info);
