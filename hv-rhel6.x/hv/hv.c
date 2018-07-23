/*
 * Copyright (c) 2009, Microsoft Corporation.
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
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "include/linux/hyperv.h"
#include <linux/version.h>
#include <linux/interrupt.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#include <linux/clockchips.h>
#endif
#include "include/uapi/linux/hyperv.h"
#include <lis/asm/hyperv.h>
#include <lis/asm/mshyperv.h>
#include "hyperv_vmbus.h"

/* The one and only */
struct hv_context hv_context = {
	.synic_initialized	= false,
};

#define HV_TIMER_FREQUENCY (10 * 1000 * 1000) /* 100ns period */
#define HV_MAX_MAX_DELTA_TICKS 0xffffffff
#define HV_MIN_DELTA_TICKS 1

#define HV_TIMER_FREQUENCY (10 * 1000 * 1000) /* 100ns period */
#define HV_MAX_MAX_DELTA_TICKS 0xffffffff
#define HV_MIN_DELTA_TICKS 1

/*
 * hv_init - Main initialization routine.
 *
 * This routine must be called before any other routines in here are called
 */
int hv_init(void)
{
	/*
	 * This initialization is normally done at
	 * early boot time in the upstream kernel.
	 *
	 * Since we can't change the kernel bootup behavior,
	 * we do this at module load time.
	 */
	hyperv_init();
	hv_print_host_info();

	if (!hv_is_hypercall_page_setup())
		return -ENOTSUPP;

	hv_context.cpu_context = alloc_percpu(struct hv_per_cpu_context);
	if (!hv_context.cpu_context)
		return -ENOMEM;

	return 0;
}

/*
 * hv_post_message - Post a message using the hypervisor message IPC.
 *
 * This involves a hypercall.
 */
int hv_post_message(union hv_connection_id connection_id,
		  enum hv_message_type message_type,
		  void *payload, size_t payload_size)
{
	struct hv_input_post_message *aligned_msg;
	struct hv_per_cpu_context *hv_cpu;
	u64 status;

	if (payload_size > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
		return -EMSGSIZE;

	hv_cpu = get_cpu_ptr(hv_context.cpu_context);
	aligned_msg = hv_cpu->post_msg_page;
	aligned_msg->connectionid = connection_id;
	aligned_msg->reserved = 0;
	aligned_msg->message_type = message_type;
	aligned_msg->payload_size = payload_size;
	memcpy((void *)aligned_msg->payload, payload, payload_size);

	status = hv_do_hypercall(HVCALL_POST_MESSAGE, aligned_msg, NULL);

	/* Preemption must remain disabled until after the hypercall
	 * so some other thread can't get scheduled onto this cpu and
	 * corrupt the per-cpu post_msg_page
	 */
	put_cpu_ptr(hv_cpu);

	return status &0xFFFF;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
static int hv_ce_set_next_event(unsigned long delta,
				struct clock_event_device *evt)
{
	cycle_t current_tick;

	WARN_ON(evt->mode != CLOCK_EVT_MODE_ONESHOT);

	hv_get_current_tick(current_tick);
	current_tick += delta;
	hv_init_timer(HV_X64_MSR_STIMER0_COUNT, current_tick);
	return 0;
}

static void hv_ce_setmode(enum clock_event_mode mode,
			  struct clock_event_device *evt)
{
	union hv_timer_config timer_cfg;

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		/* unsupported */
		break;

	case CLOCK_EVT_MODE_ONESHOT:
		timer_cfg.enable = 1;
		timer_cfg.auto_enable = 1;
		timer_cfg.sintx = VMBUS_MESSAGE_SINT;
		hv_init_timer_config(HV_X64_MSR_STIMER0_CONFIG, timer_cfg.as_uint64);
		break;

	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
		hv_init_timer(HV_X64_MSR_STIMER0_COUNT, 0);
		hv_init_timer_config(HV_X64_MSR_STIMER0_CONFIG, 0);
		break;
	case CLOCK_EVT_MODE_RESUME:
		break;
	}
}

static void hv_init_clockevent_device(struct clock_event_device *dev, int cpu)
{
	dev->name = "Hyper-V clockevent";
	dev->features = CLOCK_EVT_FEAT_ONESHOT;
	dev->cpumask = cpumask_of(cpu);
	dev->rating = 1000;

	/*
	 * Avoid settint dev->owner = THIS_MODULE deliberately as doing so will
	 * result in clockevents_config_and_register() taking additional
	 * references to the hv_vmbus module making it impossible to unload.
	 */
	dev->shift = 31;
	dev->mult = 21474836;
	dev->min_delta_ns = 1000;
	dev->max_delta_ns = 0xffffffff;


	dev->set_mode = hv_ce_setmode;
	dev->set_next_event = hv_ce_set_next_event;
}

#endif

int hv_synic_alloc(void)
{
	int cpu;

	hv_context.hv_numa_map = kzalloc(sizeof(struct cpumask) * nr_node_ids,
					 GFP_KERNEL);
	if (hv_context.hv_numa_map == NULL) {
		pr_err("Unable to allocate NUMA map\n");
		goto err;
	}

	for_each_present_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context.cpu_context, cpu);

		memset(hv_cpu, 0, sizeof(*hv_cpu));
		tasklet_init(&hv_cpu->msg_dpc,
			     vmbus_on_msg_dpc, (unsigned long) hv_cpu);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
		hv_cpu->clk_evt = kzalloc(sizeof(struct clock_event_device),
					  GFP_KERNEL);
		if (hv_cpu->clk_evt == NULL) {
			pr_err("Unable to allocate clock event device\n");
			goto err;
		}
		hv_init_clockevent_device(hv_cpu->clk_evt, cpu);
#endif

		hv_cpu->synic_message_page =
			(void *)get_zeroed_page(GFP_ATOMIC);

		if (hv_cpu->synic_message_page == NULL) {
			pr_err("Unable to allocate SYNIC message page\n");
			goto err;
		}

		hv_cpu->synic_event_page = (void *)get_zeroed_page(GFP_ATOMIC);
		if (hv_cpu->synic_event_page == NULL) {
			pr_err("Unable to allocate SYNIC event page\n");
			goto err;
		}

		hv_cpu->post_msg_page = (void *)get_zeroed_page(GFP_ATOMIC);
		if (hv_cpu->post_msg_page == NULL) {
			pr_err("Unable to allocate post msg page\n");
			goto err;
		}

		INIT_LIST_HEAD(&hv_cpu->chan_list);
	}

	return 0;
err:
	return -ENOMEM;
}


void hv_synic_free(void)
{
	int cpu;

	for_each_present_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context.cpu_context, cpu);

		if (hv_cpu->synic_event_page)
			free_page((unsigned long)hv_cpu->synic_event_page);
		if (hv_cpu->synic_message_page)
			free_page((unsigned long)hv_cpu->synic_message_page);
		if (hv_cpu->post_msg_page)
			free_page((unsigned long)hv_cpu->post_msg_page);
	}

	kfree(hv_context.hv_numa_map);
}

#ifndef HYPERVISOR_CALLBACK_VECTOR
#define HYPERVISOR_CALLBACK_VECTOR (7 + IRQ0_VECTOR)
#endif

/*
 * hv_synic_init - Initialize the Synthethic Interrupt Controller.
 *
 * If it is already initialized by another entity (ie x2v shim), we need to
 * retrieve the initialized message and event pages.  Otherwise, we create and
 * initialize the message and event pages.
 */
void hv_synic_init(void *arg)
{
	union hv_synic_simp simp;
	union hv_synic_siefp siefp;
	union hv_synic_sint shared_sint;
	union hv_synic_scontrol sctrl;
	u64 vp_index;

	int cpu = smp_processor_id();
	struct hv_per_cpu_context *hv_cpu
		= per_cpu_ptr(hv_context.cpu_context, cpu);

	/* Setup the Synic's message page */
	hv_get_simp(simp.as_uint64);
	simp.simp_enabled = 1;
	simp.base_simp_gpa = virt_to_phys(hv_cpu->synic_message_page)
		>> PAGE_SHIFT;

	hv_set_simp(simp.as_uint64);

	/* Setup the Synic's event page */
	hv_get_siefp(siefp.as_uint64);
	siefp.siefp_enabled = 1;
	siefp.base_siefp_gpa = virt_to_phys(hv_cpu->synic_event_page)
		>> PAGE_SHIFT;

	hv_set_siefp(siefp.as_uint64);

	/* Setup the shared SINT. */
	hv_get_synint_state(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT,
			    shared_sint.as_uint64);

	shared_sint.vector = HYPERVISOR_CALLBACK_VECTOR;
	shared_sint.masked = false;

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,10))
	/*
	 * RHEL 6.9 and older's hyperv_vector_handler() doesn't have the
	 * patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a33fd4c27b3ad11c66bdadc5fe6075297ca87a6d,
	 * so we must set shared_sint.auto_eoi to true, otherwise the VM
	 * hangs when booting up.
	 */
	shared_sint.auto_eoi = true;
#else
#error  check the src code of RHEL kernel: arch/x86/kernel/cpu/mshyperv.c:hyperv_vector_handler()!!!
	if (ms_hyperv_ext.hints & HV_X64_DEPRECATING_AEOI_RECOMMENDED)
		shared_sint.auto_eoi = false;
	else
		shared_sint.auto_eoi = true;
#endif

	hv_set_synint_state(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT,
			    shared_sint.as_uint64);

	/* Enable the global synic bit */
	hv_get_synic_state(sctrl.as_uint64);
	sctrl.enable = 1;

	hv_set_synic_state(sctrl.as_uint64);

	hv_context.synic_initialized = true;

	/*
	 * Setup the mapping between Hyper-V's notion
	 * of cpuid and Linux' notion of cpuid.
	 * This array will be indexed using Linux cpuid.
	 */
	hv_get_vp_index(vp_index);
	hv_context.vp_index[cpu] = (u32)vp_index;

#ifdef NOTYET
	/*
	 * Register the per-cpu clockevent source.
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE)
		clockevents_register_device(hv_cpu->clk_evt);
#endif
#endif
	return;
}

/*
 * hv_synic_clockevents_cleanup - Cleanup clockevent devices
 */

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
void hv_synic_clockevents_cleanup(void)
{
	int cpu;

	if (!(ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE))
		return;

	for_each_present_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context.cpu_context, cpu);

		clockevents_unbind_device(hv_cpu->clk_evt, cpu);
	}
}
#endif

/*
 * hv_synic_cleanup - Cleanup routine for hv_synic_init().
 */
void hv_synic_cleanup(void *arg)
{
	union hv_synic_sint shared_sint;
	union hv_synic_simp simp;
	union hv_synic_siefp siefp;
	union hv_synic_scontrol sctrl;

	if (!hv_context.synic_initialized)
		return;

	/* Turn off clockevent device */
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE) {
		struct hv_per_cpu_context *hv_cpu
			= this_cpu_ptr(hv_context.cpu_context);

		clockevents_unbind_device(hv_cpu->clk_evt, cpu);
		hv_ce_shutdown(hv_cpu->clk_evt);
		put_cpu_ptr(hv_cpu);
	}
#else
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE) {
		struct hv_per_cpu_context *hv_cpu
			= this_cpu_ptr(hv_context.cpu_context);

		hv_ce_setmode(CLOCK_EVT_MODE_SHUTDOWN, hv_cpu->clk_evt);
		put_cpu_ptr(hv_cpu);
	}
#endif

	hv_get_synint_state(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT,
			    shared_sint.as_uint64);

	shared_sint.masked = 1;

	/* Need to correctly cleanup in the case of SMP!!! */
	/* Disable the interrupt */

	hv_set_synint_state(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT,
			    shared_sint.as_uint64);
	
	hv_get_simp(simp.as_uint64);
	simp.simp_enabled = 0;
	simp.base_simp_gpa = 0;

	hv_set_simp(simp.as_uint64);

	hv_get_siefp(siefp.as_uint64);
	siefp.siefp_enabled = 0;
	siefp.base_siefp_gpa = 0;

	hv_set_siefp(siefp.as_uint64);

	/* Disable the global synic bit */
	hv_get_synic_state(sctrl.as_uint64);
	sctrl.enable = 0;
	hv_set_synic_state(sctrl.as_uint64);
}
