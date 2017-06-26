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
 *   K. Y. Srinivasan <kys@microsoft.com>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/completion.h>
#include "include/linux/hyperv.h"
#include <linux/kernel_stat.h>
#include <linux/cpu.h>
#include <linux/clocksource.h>
#include <linux/version.h>
#include "include/asm/hyperv.h"
#include "include/asm/mshyperv.h"
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include "hyperv_vmbus.h"


#if (RHEL_RELEASE_CODE < 1540)
#include <asm/mshyperv.h>

int x86_hyper_ms_hyperv;
EXPORT_SYMBOL(x86_hyper_ms_hyperv);

void *x86_hyper = &x86_hyper_ms_hyperv;
EXPORT_SYMBOL(x86_hyper);

bool using_null_legacy_pic = false;
EXPORT_SYMBOL(using_null_legacy_pic);


struct ms_hyperv_info ms_hyperv;
EXPORT_SYMBOL(ms_hyperv);

#endif

static struct acpi_device  *hv_acpi_dev;

static struct tasklet_struct msg_dpc;
static struct completion probe_event;
static int irq;

struct hv_device_info {
	u32 chn_id;
	u32 chn_state;
	uuid_le chn_type;
	uuid_le chn_instance;

	u32 monitor_id;
	u32 server_monitor_pending;
	u32 server_monitor_latency;
	u32 server_monitor_conn_id;
	u32 client_monitor_pending;
	u32 client_monitor_latency;
	u32 client_monitor_conn_id;

	struct hv_dev_port_info inbound;
	struct hv_dev_port_info outbound;
};



int hyperv_panic_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct pt_regs *regs;

	regs = task_pt_regs(current);

#ifdef CONFIG_X86_64
	wrmsrl(HV_X64_MSR_CRASH_P0, regs->rip);
	wrmsrl(HV_X64_MSR_CRASH_P1, regs->rax);
	wrmsrl(HV_X64_MSR_CRASH_P2, regs->rbx);
	wrmsrl(HV_X64_MSR_CRASH_P3, regs->rcx);
	wrmsrl(HV_X64_MSR_CRASH_P4, regs->rdx);
#else
	wrmsrl(HV_X64_MSR_CRASH_P0, regs->eip);
	wrmsrl(HV_X64_MSR_CRASH_P1, regs->eax);
	wrmsrl(HV_X64_MSR_CRASH_P2, regs->ebx);
	wrmsrl(HV_X64_MSR_CRASH_P3, regs->ecx);
	wrmsrl(HV_X64_MSR_CRASH_P4, regs->edx);
#endif

	/*
	 * Let Hyper-V know there is crash data available
	 */
	wrmsrl(HV_X64_MSR_CRASH_CTL, HV_CRASH_CTL_CRASH_NOTIFY);
	return NOTIFY_DONE;
}

static struct notifier_block hyperv_panic_block = {
	.notifier_call = hyperv_panic_event,
};

struct resource hyperv_mmio = {
	.name  = "hyperv mmio",
	.flags = IORESOURCE_MEM,
};
EXPORT_SYMBOL_GPL(hyperv_mmio);

static int vmbus_exists(void)
{
	if (hv_acpi_dev == NULL)
		return -ENODEV;

	return 0;
}

static void get_channel_info(struct hv_device *device,
				struct hv_device_info *info)
{
	struct vmbus_channel_debug_info debug_info;

	if (!device->channel)
		return;

	vmbus_get_debug_info(device->channel, &debug_info);

	info->chn_id = debug_info.relid;
	info->chn_state = debug_info.state;
	memcpy(&info->chn_type, &debug_info.interfacetype,
		sizeof(uuid_le));
	memcpy(&info->chn_instance, &debug_info.interface_instance,
		sizeof(uuid_le));

	info->monitor_id = debug_info.monitorid;

	info->server_monitor_pending = debug_info.servermonitor_pending;
	info->server_monitor_latency = debug_info.servermonitor_latency;
	info->server_monitor_conn_id = debug_info.servermonitor_connectionid;

	info->client_monitor_pending = debug_info.clientmonitor_pending;
	info->client_monitor_latency = debug_info.clientmonitor_latency;
	info->client_monitor_conn_id = debug_info.clientmonitor_connectionid;

	info->inbound.int_mask = debug_info.inbound.current_interrupt_mask;
	info->inbound.read_idx = debug_info.inbound.current_read_index;
	info->inbound.write_idx = debug_info.inbound.current_write_index;
	info->inbound.bytes_avail_toread =
		debug_info.inbound.bytes_avail_toread;
	info->inbound.bytes_avail_towrite =
		debug_info.inbound.bytes_avail_towrite;

	info->outbound.int_mask =
		debug_info.outbound.current_interrupt_mask;
	info->outbound.read_idx = debug_info.outbound.current_read_index;
	info->outbound.write_idx = debug_info.outbound.current_write_index;
	info->outbound.bytes_avail_toread =
		debug_info.outbound.bytes_avail_toread;
	info->outbound.bytes_avail_towrite =
		debug_info.outbound.bytes_avail_towrite;
}

#define VMBUS_ALIAS_LEN ((sizeof((struct hv_vmbus_device_id *)0)->guid) * 2)
static void print_alias_name(struct hv_device *hv_dev, char *alias_name)
{
	int i;
	for (i = 0; i < VMBUS_ALIAS_LEN; i += 2)
		sprintf(&alias_name[i], "%02x", hv_dev->dev_type.b[i/2]);
}


/*
 * vmbus_show_device_attr - Show the device attribute in sysfs.
 *
 * This is invoked when user does a
 * "cat /sys/bus/vmbus/devices/<busdevice>/<attr name>"
 */
static ssize_t vmbus_show_device_attr(struct device *dev,
				      struct device_attribute *dev_attr,
				      char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct hv_device_info *device_info;
	char alias_name[VMBUS_ALIAS_LEN + 1];
	int ret = 0;

	device_info = kzalloc(sizeof(struct hv_device_info), GFP_KERNEL);
	if (!device_info)
		return ret;

	get_channel_info(hv_dev, device_info);

	if (!strcmp(dev_attr->attr.name, "class_id")) {
		ret = sprintf(buf, "{%02x%02x%02x%02x-%02x%02x-%02x%02x-"
				"%02x%02x%02x%02x%02x%02x%02x%02x}\n",
				device_info->chn_type.b[3],
				device_info->chn_type.b[2],
				device_info->chn_type.b[1],
				device_info->chn_type.b[0],
				device_info->chn_type.b[5],
				device_info->chn_type.b[4],
				device_info->chn_type.b[7],
				device_info->chn_type.b[6],
				device_info->chn_type.b[8],
				device_info->chn_type.b[9],
				device_info->chn_type.b[10],
				device_info->chn_type.b[11],
				device_info->chn_type.b[12],
				device_info->chn_type.b[13],
				device_info->chn_type.b[14],
				device_info->chn_type.b[15]);
	} else if (!strcmp(dev_attr->attr.name, "device_id")) {
		ret = sprintf(buf, "{%02x%02x%02x%02x-%02x%02x-%02x%02x-"
				"%02x%02x%02x%02x%02x%02x%02x%02x}\n",
				device_info->chn_instance.b[3],
				device_info->chn_instance.b[2],
				device_info->chn_instance.b[1],
				device_info->chn_instance.b[0],
				device_info->chn_instance.b[5],
				device_info->chn_instance.b[4],
				device_info->chn_instance.b[7],
				device_info->chn_instance.b[6],
				device_info->chn_instance.b[8],
				device_info->chn_instance.b[9],
				device_info->chn_instance.b[10],
				device_info->chn_instance.b[11],
				device_info->chn_instance.b[12],
				device_info->chn_instance.b[13],
				device_info->chn_instance.b[14],
				device_info->chn_instance.b[15]);
	} else if (!strcmp(dev_attr->attr.name, "modalias")) {
		print_alias_name(hv_dev, alias_name);
		ret = sprintf(buf, "vmbus:%s\n", alias_name);
	} else if (!strcmp(dev_attr->attr.name, "state")) {
		ret = sprintf(buf, "%d\n", device_info->chn_state);
	} else if (!strcmp(dev_attr->attr.name, "id")) {
		ret = sprintf(buf, "%d\n", device_info->chn_id);
	} else if (!strcmp(dev_attr->attr.name, "out_intr_mask")) {
		ret = sprintf(buf, "%d\n", device_info->outbound.int_mask);
	} else if (!strcmp(dev_attr->attr.name, "out_read_index")) {
		ret = sprintf(buf, "%d\n", device_info->outbound.read_idx);
	} else if (!strcmp(dev_attr->attr.name, "out_write_index")) {
		ret = sprintf(buf, "%d\n", device_info->outbound.write_idx);
	} else if (!strcmp(dev_attr->attr.name, "out_read_bytes_avail")) {
		ret = sprintf(buf, "%d\n",
			       device_info->outbound.bytes_avail_toread);
	} else if (!strcmp(dev_attr->attr.name, "out_write_bytes_avail")) {
		ret = sprintf(buf, "%d\n",
			       device_info->outbound.bytes_avail_towrite);
	} else if (!strcmp(dev_attr->attr.name, "in_intr_mask")) {
		ret = sprintf(buf, "%d\n", device_info->inbound.int_mask);
	} else if (!strcmp(dev_attr->attr.name, "in_read_index")) {
		ret = sprintf(buf, "%d\n", device_info->inbound.read_idx);
	} else if (!strcmp(dev_attr->attr.name, "in_write_index")) {
		ret = sprintf(buf, "%d\n", device_info->inbound.write_idx);
	} else if (!strcmp(dev_attr->attr.name, "in_read_bytes_avail")) {
		ret = sprintf(buf, "%d\n",
			       device_info->inbound.bytes_avail_toread);
	} else if (!strcmp(dev_attr->attr.name, "in_write_bytes_avail")) {
		ret = sprintf(buf, "%d\n",
			       device_info->inbound.bytes_avail_towrite);
	} else if (!strcmp(dev_attr->attr.name, "monitor_id")) {
		ret = sprintf(buf, "%d\n", device_info->monitor_id);
	} else if (!strcmp(dev_attr->attr.name, "server_monitor_pending")) {
		ret = sprintf(buf, "%d\n", device_info->server_monitor_pending);
	} else if (!strcmp(dev_attr->attr.name, "server_monitor_latency")) {
		ret = sprintf(buf, "%d\n", device_info->server_monitor_latency);
	} else if (!strcmp(dev_attr->attr.name, "server_monitor_conn_id")) {
		ret = sprintf(buf, "%d\n",
			       device_info->server_monitor_conn_id);
	} else if (!strcmp(dev_attr->attr.name, "client_monitor_pending")) {
		ret = sprintf(buf, "%d\n", device_info->client_monitor_pending);
	} else if (!strcmp(dev_attr->attr.name, "client_monitor_latency")) {
		ret = sprintf(buf, "%d\n", device_info->client_monitor_latency);
	} else if (!strcmp(dev_attr->attr.name, "client_monitor_conn_id")) {
		ret = sprintf(buf, "%d\n",
			       device_info->client_monitor_conn_id);
	}

	kfree(device_info);
	return ret;
}

static ssize_t vendor_show(struct device *dev,
			   struct device_attribute *dev_attr,
			   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	return sprintf(buf, "0x%x\n", hv_dev->vendor_id);
}
/* static DEVICE_ATTR_RO(vendor); */

static ssize_t device_show(struct device *dev,
			   struct device_attribute *dev_attr,
			   char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	return sprintf(buf, "0x%x\n", hv_dev->device_id);
}
/* static DEVICE_ATTR_RO(device); */

/* Set up per device attributes in /sys/bus/vmbus/devices/<bus device> */
static struct device_attribute vmbus_device_attrs[] = {
	__ATTR(id, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(state, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(class_id, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(device_id, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(monitor_id, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(modalias, S_IRUGO, vmbus_show_device_attr, NULL),

	__ATTR(server_monitor_pending, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(server_monitor_latency, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(server_monitor_conn_id, S_IRUGO, vmbus_show_device_attr, NULL),

	__ATTR(client_monitor_pending, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(client_monitor_latency, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(client_monitor_conn_id, S_IRUGO, vmbus_show_device_attr, NULL),

	__ATTR(out_intr_mask, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(out_read_index, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(out_write_index, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(out_read_bytes_avail, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(out_write_bytes_avail, S_IRUGO, vmbus_show_device_attr, NULL),

	__ATTR(in_intr_mask, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(in_read_index, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(in_write_index, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(in_read_bytes_avail, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(in_write_bytes_avail, S_IRUGO, vmbus_show_device_attr, NULL),
	__ATTR(vendor, S_IRUGO, vendor_show, NULL),
	__ATTR(device, S_IRUGO, device_show, NULL),
	__ATTR_NULL
};


/*
 * vmbus_uevent - add uevent for our device
 *
 * This routine is invoked when a device is added or removed on the vmbus to
 * generate a uevent to udev in the userspace. The udev will then look at its
 * rule and the uevent generated here to load the appropriate driver
 *
 * The alias string will be of the form vmbus:guid where guid is the string
 * representation of the device guid (each byte of the guid will be
 * represented with two hex characters.
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
static int vmbus_uevent(struct device *device, struct kobj_uevent_env *env)
{
	struct hv_device *dev = device_to_hv_device(device);
	int ret;
	char alias_name[VMBUS_ALIAS_LEN + 1];

	print_alias_name(dev, alias_name);
	ret = add_uevent_var(env, "MODALIAS=vmbus:%s", alias_name);
	return ret;
}
#else
int vmbus_uevent(struct device *device, char **envp, int num_envp, char *buffer, int buffer_size)
{
	struct hv_device *dev = device_to_hv_device(device);
	int i = 0;
	int len = 0;
	int ret;
	char alias_name[VMBUS_ALIAS_LEN + 1];

	print_alias_name(dev, alias_name);
	ret = add_uevent_var(envp, num_envp, &i, buffer, buffer_size, &len,
			     "MODALIAS=vmbus:%s", alias_name);

	if (ret)
		return ret;

	envp[i] = NULL;

	return 0;
}
#endif


static const uuid_le null_guid;

static inline bool is_null_guid(const __u8 *guid)
{
	if (memcmp(guid, &null_guid, sizeof(uuid_le)))
		return false;
	return true;
}

/*
 * Return a matching hv_vmbus_device_id pointer.
 * If there is no match, return NULL.
 */
static const struct hv_vmbus_device_id *hv_vmbus_get_id(
					const struct hv_vmbus_device_id *id,
					const __u8 *guid)
{
	for (; !is_null_guid(id->guid); id++)
		if (!memcmp(&id->guid, guid, sizeof(uuid_le)))
			return id;

	return NULL;
}



/*
 * vmbus_match - Attempt to match the specified device to the specified driver
 */
static int vmbus_match(struct device *device, struct device_driver *driver)
{
	struct hv_driver *drv = drv_to_hv_drv(driver);
	struct hv_device *hv_dev = device_to_hv_device(device);

	if (hv_vmbus_get_id(drv->id_table, hv_dev->dev_type.b))
		return 1;

	return 0;
}

/*
 * vmbus_probe - Add the new vmbus's child device
 */
static int vmbus_probe(struct device *child_device)
{
	int ret = 0;
	struct hv_driver *drv =
			drv_to_hv_drv(child_device->driver);
	struct hv_device *dev = device_to_hv_device(child_device);
	const struct hv_vmbus_device_id *dev_id;

	dev_id = hv_vmbus_get_id(drv->id_table, dev->dev_type.b);
	if (drv->probe) {
		ret = drv->probe(dev, dev_id);
		if (ret != 0)
			pr_err("probe failed for device %s (%d)\n",
			       dev_name(child_device), ret);

	} else {
		pr_err("probe not set for driver %s\n",
		       dev_name(child_device));
		ret = -ENODEV;
	}
	return ret;
}

/*
 * vmbus_remove - Remove a vmbus device
 */
static int vmbus_remove(struct device *child_device)
{
	struct hv_driver *drv;
	struct hv_device *dev = device_to_hv_device(child_device);
	u32 relid = dev->channel->offermsg.child_relid;

	if (child_device->driver) {
		drv = drv_to_hv_drv(child_device->driver);
		if (drv->remove)
			drv->remove(dev);
		else {
			hv_process_channel_removal(dev->channel, relid);
			pr_err("remove not set for driver %s\n",
				dev_name(child_device));
		}
	} else {
		/*
		 * We don't have a driver for this device; deal with the
		 * rescind message by removing the channel.
		 */
		hv_process_channel_removal(dev->channel, relid);
	}

	return 0;
}


/*
 * vmbus_shutdown - Shutdown a vmbus device
 */
static void vmbus_shutdown(struct device *child_device)
{
	struct hv_driver *drv;
	struct hv_device *dev = device_to_hv_device(child_device);


	/* The device may not be attached yet */
	if (!child_device->driver)
		return;

	drv = drv_to_hv_drv(child_device->driver);

	if (drv->shutdown)
		drv->shutdown(dev);

	return;
}


/*
 * vmbus_device_release - Final callback release of the vmbus child device
 */
static void vmbus_device_release(struct device *device)
{
	struct hv_device *hv_dev = device_to_hv_device(device);

	kfree(hv_dev);

}

/* The one and only one */
static struct bus_type  hv_bus = {
	.name =			"vmbus",
	.match =		vmbus_match,
	.shutdown =		vmbus_shutdown,
	.remove =		vmbus_remove,
	.probe =		vmbus_probe,
	.uevent =		vmbus_uevent,
	.dev_attrs =    	vmbus_device_attrs,
};

static const char *driver_name = "hyperv";

struct onmessage_work_context {
	struct work_struct work;
	struct hv_message msg;
};

static void vmbus_onmessage_work(void *data)
{
	struct onmessage_work_context *ctx;
	struct work_struct *work = (struct work_struct *)data;

	/* Do not process messages if we're in DISCONNECTED state */
	if (vmbus_connection.conn_state == DISCONNECTED)
		return;

	ctx = container_of(work, struct onmessage_work_context,
			   work);
	vmbus_onmessage(&ctx->msg);
	kfree(ctx);
}

static void hv_process_timer_expiration(struct hv_message *msg, int cpu)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	struct clock_event_device *dev = hv_context.clk_evt[cpu];

	if (dev->event_handler)
		dev->event_handler(dev);

	msg->header.message_type = HVMSG_NONE;

	/*
	 * Make sure the write to MessageType (ie set to
	 * HVMSG_NONE) happens before we read the
	 * MessagePending and EOMing. Otherwise, the EOMing
	 * will not deliver any more messages since there is
	 * no empty slot
	 */
	mb();

	if (msg->header.message_flags.msg_pending) {
		/*
		 * This will cause message queue rescan to
		 * possibly deliver another msg from the
		 * hypervisor
		 */
		wrmsrl(HV_X64_MSR_EOM, 0);
	}
#endif
}

static void vmbus_on_msg_dpc(unsigned long data)
{
	int cpu = smp_processor_id();
	void *page_addr = hv_context.synic_message_page[cpu];
	struct hv_message *msg = (struct hv_message *)page_addr +
				  VMBUS_MESSAGE_SINT;
	struct vmbus_channel_message_header *hdr;
	struct vmbus_channel_message_table_entry *entry;

	struct onmessage_work_context *ctx;

	while (1) {
		if (msg->header.message_type == HVMSG_NONE)
			/* no msg */
			break;

		hdr = (struct vmbus_channel_message_header *)msg->u.payload;

		if (hdr->msgtype >= CHANNELMSG_COUNT) {
			goto msg_handled;
		}

		entry = &channel_message_table[hdr->msgtype];
		if (entry->handler_type == VMHT_BLOCKING) {
			ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC);
			if (ctx == NULL)
				continue;
			INIT_WORK(&ctx->work, vmbus_onmessage_work, (void *)&ctx->work);
			memcpy(&ctx->msg, msg, sizeof(*msg));
			queue_work(vmbus_connection.work_queue, &ctx->work);
		} else
			entry->message_handler(hdr);

msg_handled:
		msg->header.message_type = HVMSG_NONE;

		/*
		 * Make sure the write to MessageType (ie set to
		 * HVMSG_NONE) happens before we read the
		 * MessagePending and EOMing. Otherwise, the EOMing
		 * will not deliver any more messages since there is
		 * no empty slot
		 */
		mb();

		if (msg->header.message_flags.msg_pending) {
			/*
			 * This will cause message queue rescan to
			 * possibly deliver another msg from the
			 * hypervisor
			 */
			wrmsrl(HV_X64_MSR_EOM, 0);
		}
	}
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
static irqreturn_t vmbus_isr(int irq, void *dev_id)
#else
static irqreturn_t vmbus_isr(int irq, void *dev_id, struct pt_regs *regs)
#endif
{
	int cpu = smp_processor_id();
	void *page_addr;
	struct hv_message *msg;
	union hv_synic_event_flags *event;
	bool handled = false;

	page_addr = hv_context.synic_event_page[cpu];
	if (page_addr == NULL)
		return IRQ_NONE;

	event = (union hv_synic_event_flags *)page_addr +
					 VMBUS_MESSAGE_SINT;
	/*
	 * Check for events before checking for messages. This is the order
	 * in which events and messages are checked in Windows guests on
	 * Hyper-V, and the Windows team suggested we do the same.
	 */

	if ((vmbus_proto_version == VERSION_WS2008) ||
		(vmbus_proto_version == VERSION_WIN7)) {

		/* Since we are a child, we only need to check bit 0 */
		if (sync_test_and_clear_bit(0,
			(unsigned long *) &event->flags32[0])) {
			handled = true;
		}
	} else {
		/*
		 * Our host is win8 or above. The signaling mechanism
		 * has changed and we can directly look at the event page.
		 * If bit n is set then we have an interrup on the channel
		 * whose id is n.
		 */
		handled = true;
	}

	if (handled)
		tasklet_schedule(hv_context.event_dpc[cpu]);


	page_addr = hv_context.synic_message_page[cpu];
	msg = (struct hv_message *)page_addr + VMBUS_MESSAGE_SINT;

	/* Check if there are actual msgs to be processed */
	if (msg->header.message_type != HVMSG_NONE) {
		if (msg->header.message_type == HVMSG_TIMER_EXPIRED)
			hv_process_timer_expiration(msg, cpu);
		else
			tasklet_schedule(&msg_dpc);
	}
	if (handled)
		return IRQ_HANDLED;
	else
		return IRQ_NONE;
}

#ifdef NOTYET
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
static void vmbus_flow_handler(unsigned int irq, struct irq_desc *desc)
{
	kstat_incr_irqs_this_cpu(irq, desc);
	desc->action->handler(irq, desc->action->dev_id);
}
#else
static void vmbus_flow_handler(unsigned int irq, struct irq_desc *desc, struct pt_regs *regs)
{
	desc->action->handler(irq, desc->action->dev_id, NULL);
}
#endif
#endif /* NOTYET */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
static cycle_t read_hv_clock(struct clocksource *arg)
#else
static cycle_t read_hv_clock(void)
#endif
{
	cycle_t current_tick;
	/*
	 * Read the partition counter to get the current tick count. This count
	 * is set to 0 when the partition is created and is incremented in
	 * 100 nanosecond units.
	 */
	rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);
	return current_tick;
}

#define HV_CLOCK_SHIFT  22
static struct clocksource hyperv_cs = {
	.name           = "hyperv_clocksource",
	.rating         = 400, /* use this when running on Hyperv*/
	.read           = read_hv_clock,
	.mask           = CLOCKSOURCE_MASK(64),
	.mult           = (100 << HV_CLOCK_SHIFT),
	.shift          = HV_CLOCK_SHIFT,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	.flags          = CLOCK_SOURCE_IS_CONTINUOUS,
#else
	.is_continuous = 1,
#endif
};

/*
 * vmbus_bus_init -Main vmbus driver initialization routine.
 *
 * Here, we
 *	- initialize the vmbus driver context
 *	- invoke the vmbus hv main init routine
 *	- get the irq resource
 *	- retrieve the channel offers
 */
static int vmbus_bus_init(int irq)
{
	int ret;

	/* Hypervisor initialization...setup hypercall page..etc */
	ret = hv_init();
	if (ret != 0) {
		pr_err("Unable to initialize the hypervisor - 0x%x\n", ret);
		return ret;
	}

	tasklet_init(&msg_dpc, vmbus_on_msg_dpc, 0);

	ret = bus_register(&hv_bus);
	if (ret)
		goto err_cleanup;

	ret = request_irq(irq, vmbus_isr, 0, driver_name, hv_acpi_dev);

	if (ret != 0) {
		pr_err("Unable to request IRQ %d\n",
                           irq);
		goto err_unregister;
	}


	/*
	 * Vmbus interrupts can be handled concurrently on
	 * different CPUs. Establish an appropriate interrupt flow
	 * handler that can support this model.
	 */
#ifdef NOTYET
	set_irq_handler(irq, vmbus_flow_handler);
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE >= 1542)
	/*
	 * Register our interrupt handler.
	 */
	hv_register_vmbus_handler(irq, vmbus_isr);
#endif



	ret = hv_synic_alloc();
	if (ret)
		goto err_alloc;
	/*
	 * Initialize the per-cpu interrupt state and
	 * connect to the host.
	 */
	on_each_cpu(hv_synic_init, NULL, 1, 1);
	ret = vmbus_connect();
	if (ret)
		goto err_alloc;


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1540)
	ms_hyperv.features = cpuid_eax(HYPERV_CPUID_FEATURES);
	ms_hyperv.misc_features = cpuid_edx(HYPERV_CPUID_FEATURES);
	ms_hyperv.hints = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);
#endif

	/*
	 * Only register if the crash MSRs are available
	 */
	if (ms_hyperv.misc_features & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE) {
		atomic_notifier_chain_register(&panic_notifier_list,
					       &hyperv_panic_block);
	}

	vmbus_request_offers();
	if (ms_hyperv.features & HV_X64_MSR_TIME_REF_COUNT_AVAILABLE)
		clocksource_register(&hyperv_cs);


	return 0;

err_alloc:
	free_irq(irq, hv_acpi_dev);
	hv_synic_free();

err_unregister:
	bus_unregister(&hv_bus);

err_cleanup:
	hv_cleanup();

	return ret;
}

/**
 * __vmbus_child_driver_register - Register a vmbus's driver
 * @drv: Pointer to driver structure you want to register
 * @owner: owner module of the drv
 * @mod_name: module name string
 *
 * Registers the given driver with Linux through the 'driver_register()' call
 * and sets up the hyper-v vmbus handling for this driver.
 * It will return the state of the 'driver_register()' call.
 *
 */
int __vmbus_driver_register(struct hv_driver *hv_driver, struct module *owner, const char *mod_name)
{
	int ret;

	pr_info("registering driver %s\n", hv_driver->name);

	ret = vmbus_exists();
	if (ret < 0)
		return ret;

	hv_driver->driver.name = hv_driver->name;
	hv_driver->driver.owner = owner;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	hv_driver->driver.mod_name = mod_name;
#endif
	hv_driver->driver.bus = &hv_bus;

	ret = driver_register(&hv_driver->driver);

	return ret;
}
EXPORT_SYMBOL_GPL(__vmbus_driver_register);

/**
 * vmbus_driver_unregister() - Unregister a vmbus's driver
 * @drv: Pointer to driver structure you want to un-register
 *
 * Un-register the given driver that was previous registered with a call to
 * vmbus_driver_register()
 */
void vmbus_driver_unregister(struct hv_driver *hv_driver)
{
	pr_info("unregistering driver %s\n", hv_driver->name);

	if (!vmbus_exists())
		driver_unregister(&hv_driver->driver);
}
EXPORT_SYMBOL_GPL(vmbus_driver_unregister);

/*
 * vmbus_device_create - Creates and registers a new child device
 * on the vmbus.
 */
struct hv_device *vmbus_device_create(const uuid_le *type,
				      const uuid_le *instance,
				      struct vmbus_channel *channel)
{
	struct hv_device *child_device_obj;

	child_device_obj = kzalloc(sizeof(struct hv_device), GFP_KERNEL);
	if (!child_device_obj) {
		pr_err("Unable to allocate device object for child device\n");
		return NULL;
	}

	child_device_obj->channel = channel;
	memcpy(&child_device_obj->dev_type, type, sizeof(uuid_le));
	memcpy(&child_device_obj->dev_instance, instance,
	       sizeof(uuid_le));


	return child_device_obj;
}

/*
 * vmbus_device_register - Register the child device
 */
int vmbus_device_register(struct hv_device *child_device_obj)
{
	int ret = 0;

	dev_set_name(&child_device_obj->device, "vmbus_0_%d",
		     child_device_obj->channel->id);

	child_device_obj->device.bus = &hv_bus;
	child_device_obj->device.release = vmbus_device_release;

	/*
	 * Register with the LDM. This will kick off the driver/device
	 * binding...which will eventually call vmbus_match() and vmbus_probe()
	 */
	ret = device_register(&child_device_obj->device);

	if (ret)
		pr_err("Unable to register child device\n");
	else
		pr_debug("child device %s registered\n",
			dev_name(&child_device_obj->device));

	return ret;
}

/*
 * vmbus_device_unregister - Remove the specified child device
 * from the vmbus.
 */
void vmbus_device_unregister(struct hv_device *device_obj)
{
	pr_debug("child device %s unregistered\n",
		dev_name(&device_obj->device));

	/*
	 * Kick off the process of unregistering the device.
	 * This will call vmbus_remove() and eventually vmbus_device_release()
	 */
	device_unregister(&device_obj->device);
}


/*
 * VMBUS is an acpi enumerated device. Get the the information we
 * need from DSDT.
 */

static acpi_status vmbus_walk_resources(struct acpi_resource *res, void *ctx)
{
	switch (res->type) {
	case ACPI_RESOURCE_TYPE_IRQ:
		irq = res->data.irq.interrupts[0];
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS64:
		hyperv_mmio.start = res->data.address64.minimum;
		hyperv_mmio.end = res->data.address64.maximum;
		break;
	}

	return AE_OK;
}

static int vmbus_acpi_add(struct acpi_device *device)
{
	acpi_status result;
	int ret_val = -ENODEV;

	hv_acpi_dev = device;

	result = acpi_walk_resources(device->handle, METHOD_NAME__CRS,
					vmbus_walk_resources, NULL);

	if (ACPI_FAILURE(result))
		goto acpi_walk_err;
	/*
	 * The parent of the vmbus acpi device (Gen2 firmware) is the VMOD that
	 * has the mmio ranges. Get that.
	 */
	if (device->parent) {
		result = acpi_walk_resources(device->parent->handle,
					METHOD_NAME__CRS,
					vmbus_walk_resources, NULL);

		if (ACPI_FAILURE(result))
			goto acpi_walk_err;
		if (hyperv_mmio.start && hyperv_mmio.end)
			request_resource(&iomem_resource, &hyperv_mmio);
	}
	ret_val = 0;

acpi_walk_err:
	complete(&probe_event);
	return ret_val;
}

static const struct acpi_device_id vmbus_acpi_device_ids[] = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	{"VMBUS", 0},
	{"VMBus", 0},
	{"", 0},
#else
	{"VMBUS"},
	{"VMBus"},
	{""},
#endif
};
MODULE_DEVICE_TABLE(acpi, vmbus_acpi_device_ids);

static struct acpi_driver vmbus_acpi_driver = {
	.name = "vmbus",
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	.ids = vmbus_acpi_device_ids,
#else
	.ids = "VMBus",
#endif
	.ops = {
		.add = vmbus_acpi_add,
	},
};

static int __init hv_acpi_init(void)
{
	int ret, t;

	if (x86_hyper != &x86_hyper_ms_hyperv)
		return -ENODEV;

	init_completion(&probe_event);

	/*
	 * Get irq resources first.
	 */
	ret = acpi_bus_register_driver(&vmbus_acpi_driver);

	if (ret)
		return ret;

	t = wait_for_completion_timeout(&probe_event, 5*HZ);
	if (t == 0) {
		ret = -ETIMEDOUT;
		goto cleanup;
	}

	if (irq <= 0) {
		ret = -ENODEV;
		goto cleanup;
	}

	ret = vmbus_bus_init(irq);
	if (ret)
		goto cleanup;

	return 0;

cleanup:
	acpi_bus_unregister_driver(&vmbus_acpi_driver);
	hv_acpi_dev = NULL;
	return ret;
}

static void __exit vmbus_exit(void)
{
#ifndef CONFIG_X86_32
	int cpu;
#endif

	vmbus_connection.conn_state = DISCONNECTED;
	hv_synic_clockevents_cleanup();
	free_irq(irq, hv_acpi_dev);
	vmbus_free_channels();
	bus_unregister(&hv_bus);
	hv_cleanup();
#ifndef CONFIG_X86_32
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, hv_synic_cleanup, NULL, true, 1);
#else
		smp_call_function(hv_synic_cleanup, NULL, true, 1);
#endif

	acpi_bus_unregister_driver(&vmbus_acpi_driver);
	vmbus_disconnect();
}


MODULE_LICENSE("GPL");
MODULE_VERSION(HV_DRV_VERSION);

subsys_initcall(hv_acpi_init);
module_exit(vmbus_exit);
