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
#include <linux/clockchips.h>
#include <lis/asm/hyperv.h>
#include <lis/asm/mshyperv.h>
#include "hyperv_vmbus.h"
#include <asm/msr.h>


/* The one and only */
struct hv_context hv_context = {
	.synic_initialized	= false,
};

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

	memset(hv_context.clk_evt, 0, sizeof(void *) * NR_CPUS);

	hv_print_host_info();

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6))
	if (!hv_is_hyperv_initialized())
#else
	if (!hv_is_hypercall_page_setup())
#endif
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

	return status & 0xFFFF;
}

static int hv_ce_set_next_event(unsigned long delta,
				struct clock_event_device *evt)
{
	u64 current_tick;

	WARN_ON(evt->mode != CLOCK_EVT_MODE_ONESHOT);

	current_tick = hyperv_cs->read(NULL);
	current_tick += delta;
	hv_init_timer(0, current_tick);
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
		hv_init_timer_config(0, timer_cfg.as_uint64);
		break;

	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
		hv_init_timer(0, 0);
		hv_init_timer_config(0, 0);
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

	dev->set_mode = hv_ce_setmode;
	dev->set_next_event = hv_ce_set_next_event;
}


int hv_synic_alloc(void)
{
	int cpu;
	struct hv_per_cpu_context *hv_cpu;

	/*
	 * First, zero all per-cpu memory areas so hv_synic_free() can
	 * detect what memory has been allocated and cleanup properly
	 * after any failures.
	 */
	for_each_present_cpu(cpu) {
		hv_cpu = per_cpu_ptr(hv_context.cpu_context, cpu);
		memset(hv_cpu, 0, sizeof(*hv_cpu));
	}

	hv_context.hv_numa_map = kzalloc(sizeof(struct cpumask) * nr_node_ids,
					 GFP_KERNEL);
	if (hv_context.hv_numa_map == NULL) {
		pr_err("Unable to allocate NUMA map\n");
		goto err;
	}

	for_each_present_cpu(cpu) {
		hv_cpu = per_cpu_ptr(hv_context.cpu_context, cpu);

		tasklet_init(&hv_cpu->msg_dpc,
			     vmbus_on_msg_dpc, (unsigned long) hv_cpu);

		hv_context.clk_evt[cpu] = kzalloc(sizeof(struct clock_event_device),
						  GFP_ATOMIC);
		if (hv_context.clk_evt[cpu] == NULL) {
			pr_err("Unable to allocate clock event device\n");
			goto err;
		}
		hv_init_clockevent_device(hv_context.clk_evt[cpu], cpu);

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

        	if (hv_context.clk_evt[cpu])
                	kfree(hv_context.clk_evt[cpu]);
        
        	free_page((unsigned long)hv_cpu->synic_event_page);
        	free_page((unsigned long)hv_cpu->synic_message_page);
        	free_page((unsigned long)hv_cpu->post_msg_page);
	}

	kfree(hv_context.hv_numa_map);
}

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))  
void hv_clockevents_bind(int cpu)
{
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE)
		clockevents_config_and_register(hv_context.clk_evt[cpu],
						HV_TIMER_FREQUENCY,
						HV_MIN_DELTA_TICKS,
						HV_MAX_MAX_DELTA_TICKS);
}

void hv_clockevents_unbind(int cpu)
{
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE)
		clockevents_unbind_device(hv_context.clk_evt[cpu], cpu);
}

int hv_synic_cpu_used(unsigned int cpu)
{
	struct vmbus_channel *channel, *sc;
	bool channel_found = false;
	unsigned long flags;

	/*
	 * Search for channels which are bound to the CPU we're about to
	 * cleanup. In case we find one and vmbus is still connected we need to
	 * fail, this will effectively prevent CPU offlining. There is no way
	 * we can re-bind channels to different CPUs for now.
	 */
	mutex_lock(&vmbus_connection.channel_mutex);
	list_for_each_entry(channel, &vmbus_connection.chn_list, listentry) {
		if (channel->target_cpu == cpu) {
			channel_found = true;
			break;
		}
		spin_lock_irqsave(&channel->lock, flags);
		list_for_each_entry(sc, &channel->sc_list, sc_list) {
			if (sc->target_cpu == cpu) {
				channel_found = true;
				break;
			}
		}
		spin_unlock_irqrestore(&channel->lock, flags);
		if (channel_found)
			break;
	}
	mutex_unlock(&vmbus_connection.channel_mutex);

	if (channel_found && vmbus_connection.conn_state == CONNECTED)
		return 1;

	return 0;
}
#endif 

/*
 * hv_synic_init - Initialize the Synthethic Interrupt Controller.
 *
 * If it is already initialized by another entity (ie x2v shim), we need to
 * retrieve the initialized message and event pages.  Otherwise, we create and
 * initialize the message and event pages.
 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
void hv_synic_init(unsigned int arg)
#else
void hv_synic_init(void *arg)
#endif
{
	union hv_synic_simp simp;
	union hv_synic_siefp siefp;
	union hv_synic_sint shared_sint;
	union hv_synic_scontrol sctrl;

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
	hv_get_synint_state(VMBUS_MESSAGE_SINT, shared_sint.as_uint64);

	shared_sint.vector = HYPERVISOR_CALLBACK_VECTOR;
	shared_sint.masked = false;

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,4))
	/*
	 * RHEL 7.4 and older's hyperv_vector_handler() doesn't have the
	 * patch: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a33fd4c27b3ad11c66bdadc5fe6075297ca87a6d,
	 * so we must set shared_sint.auto_eoi to true, otherwise the VM
	 * hangs when booting up.
	 */
	shared_sint.auto_eoi = true;
#else
	if (ms_hyperv_ext.hints & HV_X64_DEPRECATING_AEOI_RECOMMENDED)
		shared_sint.auto_eoi = false;
	else
		shared_sint.auto_eoi = true;
#endif

	hv_set_synint_state(VMBUS_MESSAGE_SINT, shared_sint.as_uint64);

	/* Enable the global synic bit */
	hv_get_synic_state(sctrl.as_uint64);
	sctrl.enable = 1;

	hv_set_synic_state(sctrl.as_uint64);

	hv_context.synic_initialized = true;

	hv_cpu_init(cpu);

#ifdef NOTYET
	/*
	 * Register the per-cpu clockevent source.
	 */
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE) 
		clockevents_config_and_register(hv_cpu->clk_evt, 
			HV_TIMER_FREQUENCY, 
			HV_MIN_DELTA_TICKS, 
			HV_MAX_MAX_DELTA_TICKS); 
#endif

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
	hv_clockevents_bind(cpu);
#endif
	return;
}

/*
 * hv_synic_clockevents_cleanup - Cleanup clockevent devices
 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
void hv_synic_clockevents_cleanup(void)
{
	int cpu;

	if (!(ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE))
		return;

	for_each_present_cpu(cpu)
		clockevents_unbind_device(hv_context.clk_evt[cpu], cpu);
}
#endif
/*
 * hv_synic_cleanup - Cleanup routine for hv_synic_init().
 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
void hv_synic_cleanup(unsigned int cpu)
#else
void hv_synic_cleanup(void *arg)
#endif
{
	union hv_synic_sint shared_sint;
	union hv_synic_simp simp;
	union hv_synic_siefp siefp;
	union hv_synic_scontrol sctrl;
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
	unsigned int cpu = smp_processor_id();
#endif

	if (!hv_context.synic_initialized)
		return;

/*	Upstream referecen: 6ffc4b85358f6b7d252420cfa5862312cf5f83d8
	Code locks on 7.3 with no reboot during kdump

	#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE) {
		struct hv_per_cpu_context *hv_cpu
			= this_cpu_ptr(hv_context.cpu_context);

		clockevents_unbind_device(hv_cpu->clk_evt, cpu);
		hv_ce_setmode(CLOCK_EVT_MODE_SHUTDOWN, hv_cpu->clk_evt);
		put_cpu_ptr(hv_cpu);
	}
#else
*/
	/* Turn off clockevent device */
	if (ms_hyperv_ext.features & HV_X64_MSR_SYNTIMER_AVAILABLE)
		hv_ce_setmode(CLOCK_EVT_MODE_SHUTDOWN,
			      hv_context.clk_evt[cpu]);

	hv_get_synint_state(VMBUS_MESSAGE_SINT, shared_sint.as_uint64);

	shared_sint.masked = 1;

	/* Need to correctly cleanup in the case of SMP!!! */
	/* Disable the interrupt */
	hv_set_synint_state(VMBUS_MESSAGE_SINT, shared_sint.as_uint64);

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
