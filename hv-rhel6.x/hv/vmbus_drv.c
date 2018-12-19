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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/completion.h>
#include "include/linux/hyperv.h"
#include <linux/kernel_stat.h>
#include <linux/clockchips.h>
#include <linux/cpu.h>
#include <lis/asm/hyperv.h>
#include <linux/screen_info.h>
#include <lis/asm/mshyperv.h>
#include <asm/hypervisor.h>
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include <linux/semaphore.h>
#include <linux/efi.h>
#include "hyperv_vmbus.h"
#include <linux/random.h>

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,5))
bool using_null_legacy_pic = false;
EXPORT_SYMBOL(using_null_legacy_pic);
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
#include <lis/asm/mshyperv.h>

int x86_hyper_ms_hyperv;
EXPORT_SYMBOL(x86_hyper_ms_hyperv);

void *x86_hyper = &x86_hyper_ms_hyperv;
EXPORT_SYMBOL(x86_hyper);

#endif

static struct acpi_device  *hv_acpi_dev;

static struct completion probe_event;
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
static int irq;
#endif

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

	hyperv_report_panic(regs, event);
	return NOTIFY_DONE;
}

static struct notifier_block hyperv_panic_block = {
        .notifier_call = hyperv_panic_event,
};

static const char *fb_mmio_name = "fb_range";
static struct resource *fb_mmio;
static struct resource *hyperv_mmio;
static struct semaphore hyperv_mmio_lock;

static u8 channel_monitor_group(const struct vmbus_channel *channel)
{
	return (u8)channel->offermsg.monitorid / 32;
}

static u32 channel_pending(const struct vmbus_channel *channel,
			   const struct hv_monitor_page *monitor_page)
{
	u8 monitor_group = channel_monitor_group(channel);

	return monitor_page->trigger_group[monitor_group].pending;
}

static int vmbus_exists(void)
{
	if (hv_acpi_dev == NULL)
		return -ENODEV;

	return 0;
}

#define VMBUS_ALIAS_LEN ((sizeof((struct hv_vmbus_device_id *)0)->guid) * 2)
static void print_alias_name(struct hv_device *hv_dev, char *alias_name)
{
	int i;
	for (i = 0; i < VMBUS_ALIAS_LEN; i += 2)
		sprintf(&alias_name[i], "%02x", hv_dev->dev_type.b[i/2]);
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
static u8 channel_monitor_offset(const struct vmbus_channel *channel)
{
	return (u8)channel->offermsg.monitorid % 32;
}

static u32 channel_latency(const struct vmbus_channel *channel,
			   const struct hv_monitor_page *monitor_page)
{
	u8 monitor_group = channel_monitor_group(channel);
	u8 monitor_offset = channel_monitor_offset(channel);

	return monitor_page->latency[monitor_group][monitor_offset];
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
				"%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
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
				"%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
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
static ssize_t channel_vp_mapping_show(struct device *dev,
				       struct device_attribute *dev_attr,
				       char *buf)
{
	struct hv_device *hv_dev = device_to_hv_device(dev);
	struct vmbus_channel *channel = hv_dev->channel, *cur_sc;
	unsigned long flags;
	int buf_size = PAGE_SIZE, n_written, tot_written;
	struct list_head *cur;

	if (!channel)
		return -ENODEV;

	tot_written = snprintf(buf, buf_size, "%u:%u\n",
		channel->offermsg.child_relid, channel->target_cpu);

	spin_lock_irqsave(&channel->lock, flags);

	list_for_each(cur, &channel->sc_list) {
		if (tot_written >= buf_size - 1)
			break;

		cur_sc = list_entry(cur, struct vmbus_channel, sc_list);
		n_written = scnprintf(buf + tot_written,
				     buf_size - tot_written,
				     "%u:%u\n",
				     cur_sc->offermsg.child_relid,
				     cur_sc->target_cpu);
		tot_written += n_written;
	}

	spin_unlock_irqrestore(&channel->lock, flags);

	return tot_written;
}
/* static DEVICE_ATTR_RO(channel_vp_mapping); */

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
	__ATTR(channel_vp_mapping, S_IRUGO, channel_vp_mapping_show, NULL),
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
static int vmbus_uevent(struct device *device, struct kobj_uevent_env *env)
{
	struct hv_device *dev = device_to_hv_device(device);
	int ret;
	char alias_name[VMBUS_ALIAS_LEN + 1];

	print_alias_name(dev, alias_name);
	ret = add_uevent_var(env, "MODALIAS=vmbus:%s", alias_name);
	return ret;
}

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

	if (child_device->driver) {
 		drv = drv_to_hv_drv(child_device->driver);
 		if (drv->remove)
 			drv->remove(dev);
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
}


/*
 * vmbus_device_release - Final callback release of the vmbus child device
 */
static void vmbus_device_release(struct device *device)
{
	struct hv_device *hv_dev = device_to_hv_device(device);
	struct vmbus_channel *channel = hv_dev->channel;

	mutex_lock(&vmbus_connection.channel_mutex);
	hv_process_channel_removal(channel->offermsg.child_relid);
	mutex_unlock(&vmbus_connection.channel_mutex);
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

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
static const char *driver_name = "hyperv";
#endif


struct onmessage_work_context {
	struct work_struct work;
	struct hv_message msg;
};

struct vmbus_chan_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct vmbus_channel *chan, char *buf);
	ssize_t (*store)(struct vmbus_channel *chan,
			 const char *buf, size_t count);
};

/*
 * Called when last reference to channel is gone.
 */
static void vmbus_chan_release(struct kobject *kobj)
{
	struct vmbus_channel *channel
		= container_of(kobj, struct vmbus_channel, kobj);

	kfree_rcu(channel, rcu);
}

#define VMBUS_CHAN_ATTR(_name, _mode, _show, _store) \
	struct vmbus_chan_attribute chan_attr_##_name \
		= __ATTR(_name, _mode, _show, _store)
#define VMBUS_CHAN_ATTR_RW(_name) \
	struct vmbus_chan_attribute chan_attr_##_name = __ATTR_RW(_name)
#define VMBUS_CHAN_ATTR_RO(_name) \
	struct vmbus_chan_attribute chan_attr_##_name = __ATTR_RO(_name)
#define VMBUS_CHAN_ATTR_WO(_name) \
	struct vmbus_chan_attribute chan_attr_##_name = __ATTR_WO(_name)

static ssize_t out_mask_show(const struct vmbus_channel *channel, char *buf)
{
	const struct hv_ring_buffer_info *rbi = &channel->outbound;

	return sprintf(buf, "%u\n", rbi->ring_buffer->interrupt_mask);
}
static VMBUS_CHAN_ATTR_RO(out_mask);

static ssize_t in_mask_show(const struct vmbus_channel *channel, char *buf)
{
	const struct hv_ring_buffer_info *rbi = &channel->inbound;

	return sprintf(buf, "%u\n", rbi->ring_buffer->interrupt_mask);
}
static VMBUS_CHAN_ATTR_RO(in_mask);

static ssize_t read_avail_show(const struct vmbus_channel *channel, char *buf)
{
	const struct hv_ring_buffer_info *rbi = &channel->inbound;

	return sprintf(buf, "%u\n", hv_get_bytes_to_read(rbi));
}
static VMBUS_CHAN_ATTR_RO(read_avail);

static ssize_t write_avail_show(const struct vmbus_channel *channel, char *buf)
{
	const struct hv_ring_buffer_info *rbi = &channel->outbound;

	return sprintf(buf, "%u\n", hv_get_bytes_to_write(rbi));
}
static VMBUS_CHAN_ATTR_RO(write_avail);

static ssize_t show_target_cpu(const struct vmbus_channel *channel, char *buf)
{
	return sprintf(buf, "%u\n", channel->target_cpu);
}
static VMBUS_CHAN_ATTR(cpu, S_IRUGO, show_target_cpu, NULL);

static ssize_t channel_pending_show(const struct vmbus_channel *channel,
					char *buf)
{
	return sprintf(buf, "%d\n",
			   channel_pending(channel,
					   vmbus_connection.monitor_pages[1]));
}
static VMBUS_CHAN_ATTR(pending, S_IRUGO, channel_pending_show, NULL);

static ssize_t channel_latency_show(const struct vmbus_channel *channel,
					char *buf)
{
	return sprintf(buf, "%d\n",
			   channel_latency(channel,
					   vmbus_connection.monitor_pages[1]));
}
static VMBUS_CHAN_ATTR(latency, S_IRUGO, channel_latency_show, NULL);

static ssize_t subchannel_monitor_id_show(const struct vmbus_channel *channel,
					  char *buf)
{
	return sprintf(buf, "%u\n", channel->offermsg.monitorid);
}
static VMBUS_CHAN_ATTR(monitor_id, S_IRUGO, subchannel_monitor_id_show, NULL);

static ssize_t subchannel_id_show(const struct vmbus_channel *channel,
				  char *buf)
{
	return sprintf(buf, "%u\n",
			   channel->offermsg.offer.sub_channel_index);
}
static VMBUS_CHAN_ATTR_RO(subchannel_id);
static ssize_t vmbus_chan_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	const struct vmbus_chan_attribute *attribute
		= container_of(attr, struct vmbus_chan_attribute, attr);
	const struct vmbus_channel *chan
		= container_of(kobj, struct vmbus_channel, kobj);

	if (!attribute->show)
		return -EIO;

	return attribute->show(chan, buf);
}
	static const struct sysfs_ops vmbus_chan_sysfs_ops = {
		.show = vmbus_chan_attr_show,
	};

static struct attribute *vmbus_chan_attrs[] = {
	&chan_attr_out_mask.attr,
	&chan_attr_in_mask.attr,
	&chan_attr_read_avail.attr,
	&chan_attr_write_avail.attr,
	&chan_attr_cpu.attr,
	&chan_attr_pending.attr,
	&chan_attr_latency.attr,
	&chan_attr_monitor_id.attr,
	&chan_attr_subchannel_id.attr,
	NULL
};

static struct kobj_type vmbus_chan_ktype = {
        .sysfs_ops = &vmbus_chan_sysfs_ops,
        .release = vmbus_chan_release,
        .default_attrs = vmbus_chan_attrs,
};

/*
 * vmbus_add_channel_kobj - setup a sub-directory under device/channels
 */
int vmbus_add_channel_kobj(struct hv_device *dev, struct vmbus_channel *channel)
{
        struct kobject *kobj = &channel->kobj;
        u32 relid = channel->offermsg.child_relid;
        int ret;

        kobj->kset = dev->channels_kset;
        ret = kobject_init_and_add(kobj, &vmbus_chan_ktype, NULL,
                                   "%u", relid);
        if (ret)
                return ret;

        kobject_uevent(kobj, KOBJ_ADD);
        printk("wmdsj:cpu:%d,dev_id:%x,ven_id:%x\n",smp_processor_id(),channel->device_id,channel->vendor_id);
        return 0;
}

static void vmbus_onmessage_work(struct work_struct *work)
{
	struct onmessage_work_context *ctx;
	/* Do not process messages if we're in DISCONNECTED state */
	if (vmbus_connection.conn_state == DISCONNECTED)
		return;

	ctx = container_of(work, struct onmessage_work_context,
			   work);
	vmbus_onmessage(&ctx->msg);
	kfree(ctx);
}

static void hv_process_timer_expiration(struct hv_message *msg,
					struct hv_per_cpu_context *hv_cpu)
{
	struct clock_event_device *dev = hv_cpu->clk_evt;

	if (dev->event_handler)
		dev->event_handler(dev);

	vmbus_signal_eom(msg, HVMSG_TIMER_EXPIRED);
}

void vmbus_on_msg_dpc(unsigned long data)
{
	struct hv_per_cpu_context *hv_cpu = (void *)data;
	void *page_addr = hv_cpu->synic_message_page;
	struct hv_message *msg = (struct hv_message *)page_addr +
				  VMBUS_MESSAGE_SINT;
	struct vmbus_channel_message_header *hdr;
	const struct vmbus_channel_message_table_entry *entry;
	struct onmessage_work_context *ctx;
	u32 message_type = msg->header.message_type;

	if (message_type == HVMSG_NONE)
		/* no msg */
		return;

	hdr = (struct vmbus_channel_message_header *)msg->u.payload;

	trace_vmbus_on_msg_dpc(hdr);

	if (hdr->msgtype >= CHANNELMSG_COUNT) {
		WARN_ONCE(1, "unknown msgtype=%d\n", hdr->msgtype);
		goto msg_handled;
	}

	entry = &channel_message_table[hdr->msgtype];
	if (entry->handler_type	== VMHT_BLOCKING) {
		ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC);
		if (ctx == NULL)
			return;

		INIT_WORK(&ctx->work, vmbus_onmessage_work);
		memcpy(&ctx->msg, msg, sizeof(*msg));

		/*
		 * The host can generate a rescind message while we
		 * may still be handling the original offer. We deal with
		 * this condition by ensuring the processing is done on the
		 * same CPU.
		 */
		switch (hdr->msgtype) {
		case CHANNELMSG_RESCIND_CHANNELOFFER:
			/*
			 * Workaround for RHEL 6.X kernels:
			 * Don't schedule rescind work on global queue. 
			 * For KVP/VSS, this may lead to global
			 * workqueue attempting to flush itself and a
			 * deadlock.
			 */
			queue_work_on(vmbus_connection.connect_cpu,
				      vmbus_connection.work_queue,
				      &ctx->work);
			break;

		case CHANNELMSG_OFFERCHANNEL:
			atomic_inc(&vmbus_connection.offer_in_progress);
			queue_work_on(vmbus_connection.connect_cpu,
				      vmbus_connection.work_queue,
				      &ctx->work);
			break;

		default:
			queue_work(vmbus_connection.work_queue, &ctx->work);
		}
	} else
		entry->message_handler(hdr);

msg_handled:
	vmbus_signal_eom(msg, message_type);
}

/*
 * Direct callback for channels using other deferred processing
 */
static void vmbus_channel_isr(struct vmbus_channel *channel)
{
	void (*callback_fn)(void *);

	callback_fn = READ_ONCE(channel->onchannel_callback);
	if (likely(callback_fn != NULL))
		(*callback_fn)(channel->channel_callback_context);
}

/*
 * Schedule all channels with events pending
 */
static void vmbus_chan_sched(struct hv_per_cpu_context *hv_cpu)
{
	unsigned long *recv_int_page;
	u32 maxbits, relid;

	if (vmbus_proto_version < VERSION_WIN8) {
		maxbits = MAX_NUM_CHANNELS_SUPPORTED;
		recv_int_page = vmbus_connection.recv_int_page;
	} else {
		/*
		 * When the host is win8 and beyond, the event page
		 * can be directly checked to get the id of the channel
		 * that has the interrupt pending.
		 */
		void *page_addr = hv_cpu->synic_event_page;
		union hv_synic_event_flags *event
			= (union hv_synic_event_flags *)page_addr +
						 VMBUS_MESSAGE_SINT;

		maxbits = HV_EVENT_FLAGS_COUNT;
		recv_int_page = event->flags;
	}

	if (unlikely(!recv_int_page))
		return;

	for_each_set_bit(relid, recv_int_page, maxbits) {
		struct vmbus_channel *channel;

		if (!sync_test_and_clear_bit(relid, recv_int_page))
			continue;

		/* Special case - vmbus channel protocol msg */
		if (relid == 0)
			continue;

		/* Find channel based on relid */
		list_for_each_entry(channel, &hv_cpu->chan_list, percpu_list) {
			if (channel->offermsg.child_relid != relid)
				continue;

			trace_vmbus_chan_sched(channel);

			if (channel->rescind)
				continue;

			switch (channel->callback_mode) {
			case HV_CALL_ISR:
				vmbus_channel_isr(channel);
				break;

			case HV_CALL_BATCHED:
				hv_begin_read(&channel->inbound);
				/* fallthrough */
			case HV_CALL_DIRECT:
				tasklet_schedule(&channel->callback_event);
			}
		}
	}
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
static irqreturn_t vmbus_isr(int irq, void *dev_id)
#else
static void vmbus_isr(void)
#endif
{
	struct hv_per_cpu_context *hv_cpu
		= this_cpu_ptr(hv_context.cpu_context);
	void *page_addr = hv_cpu->synic_event_page;
	struct hv_message *msg;
	union hv_synic_event_flags *event;
	bool handled = false;

	if (unlikely(page_addr == NULL))
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
		return IRQ_NONE;
#else
		return;
#endif

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
		if (sync_test_and_clear_bit(0, event->flags))
			handled = true;
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
		vmbus_chan_sched(hv_cpu);

	page_addr = hv_cpu->synic_message_page;
	msg = (struct hv_message *)page_addr + VMBUS_MESSAGE_SINT;

	/* Check if there are actual msgs to be processed */
	if (msg->header.message_type != HVMSG_NONE) {
		if (msg->header.message_type == HVMSG_TIMER_EXPIRED)
			hv_process_timer_expiration(msg, hv_cpu);
		else
			tasklet_schedule(&hv_cpu->msg_dpc);
	}
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)) /* we dont have add_interrupt_randomness symbol in kernel yet in 7.2 */
        add_interrupt_randomness(HYPERVISOR_CALLBACK_VECTOR, 0);
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	if (handled)
		return IRQ_HANDLED;
	else
		return IRQ_NONE;
#endif
}


#ifdef CONFIG_HOTPLUG_CPU
static int hyperv_cpu_disable(void)
{
	return -ENOSYS;
}

static void hv_cpu_hotplug_quirk(bool vmbus_loaded)
{
	static void *previous_cpu_disable;

	/*
	 * Offlining a CPU when running on newer hypervisors (WS2012R2, Win8,
	 * ...) is not supported at this moment as channel interrupts are
	 * distributed across all of them.
	 */

	if ((vmbus_proto_version == VERSION_WS2008) ||
	    (vmbus_proto_version == VERSION_WIN7))
		return;

	if (vmbus_loaded) {
		previous_cpu_disable = smp_ops.cpu_disable;
		smp_ops.cpu_disable = hyperv_cpu_disable;
		pr_notice("CPU offlining is not supported by hypervisor\n");
	} else if (previous_cpu_disable)
		smp_ops.cpu_disable = previous_cpu_disable;
}
#else
static void hv_cpu_hotplug_quirk(bool vmbus_loaded)
{
}
#endif


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
static void vmbus_flow_handler(unsigned int irq, struct irq_desc *desc)
{
	kstat_incr_irqs_this_cpu(irq, desc);

	desc->action->handler(irq, desc->action->dev_id);
}
#endif


/*
 * vmbus_bus_init -Main vmbus driver initialization routine.
 *
 * Here, we
 *	- initialize the vmbus driver context
 *	- invoke the vmbus hv main init routine
 *	- get the irq resource
 *	- retrieve the channel offers
 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,7))
static int vmbus_bus_init(void)
#else
static int vmbus_bus_init(int irq)
#endif
{
	int ret;

	/* Hypervisor initialization...setup hypercall page..etc */
	ret = hv_init();
	if (ret != 0) {
		pr_err("Unable to initialize the hypervisor - 0x%x\n", ret);
		return ret;
	}

	ret = bus_register(&hv_bus);
	if (ret)
		return ret;

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
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
	set_irq_handler(irq, vmbus_flow_handler);

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,5))
	/*
	 * Register our interrupt handler.
	 */
	hv_register_vmbus_handler(irq, vmbus_isr);
#endif
#else
	hv_setup_vmbus_irq(vmbus_isr);
#endif
	
	ret = hv_synic_alloc();
	if (ret)
		goto err_alloc;
	/*
	 * Initialize the per-cpu interrupt state and
	 * connect to the host.
	 */
	on_each_cpu(hv_synic_init, NULL, 1);
	ret = vmbus_connect();
	if (ret)
		goto err_connect;

	hv_cpu_hotplug_quirk(true);

	/*
	 * Only register if the crash MSRs are available
	 */
	if (ms_hyperv_ext.misc_features & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE) {
		atomic_notifier_chain_register(&panic_notifier_list,
					       &hyperv_panic_block);
	}

	vmbus_request_offers();

	return 0;

err_connect:
	on_each_cpu(hv_synic_cleanup, NULL, 1);
err_alloc:
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	free_irq(irq, hv_acpi_dev);
#endif
	hv_synic_free();

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
err_unregister:
	bus_unregister(&hv_bus);
#endif

	return ret;
}

/**
 * __vmbus_child_driver_register() - Register a vmbus's driver
 * @hv_driver: Pointer to driver structure you want to register
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
	hv_driver->driver.mod_name = mod_name;
	hv_driver->driver.bus = &hv_bus;

	ret = driver_register(&hv_driver->driver);

	return ret;
}
EXPORT_SYMBOL_GPL(__vmbus_driver_register);

/**
 * vmbus_driver_unregister() - Unregister a vmbus's driver
 * @hv_driver: Pointer to driver structure you want to
 *             un-register
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
	child_device_obj->vendor_id = 0x1414; /* MSFT vendor ID */

	return child_device_obj;
}

/*
 * vmbus_device_register - Register the child device
 */
int vmbus_device_register(struct hv_device *child_device_obj)
{
	struct kobject *kobj = &child_device_obj->device.kobj;
	int ret = 0;

	dev_set_name(&child_device_obj->device, "%pUl",
		     child_device_obj->channel->offermsg.offer.if_instance.b);

	child_device_obj->device.bus = &hv_bus;
	child_device_obj->device.parent = &hv_acpi_dev->dev;
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

	child_device_obj->channels_kset = kset_create_and_add("channels",
							      NULL, kobj);
	if (!child_device_obj->channels_kset) {
		ret = -ENOMEM;
		goto err_dev_unregister;
	}

	ret = vmbus_add_channel_kobj(child_device_obj,
				     child_device_obj->channel);
	if (ret) {
		pr_err("Unable to register primary channeln");
		goto err_kset_unregister;
	}

	return 0;

err_kset_unregister:
	kset_unregister(child_device_obj->channels_kset);

err_dev_unregister:
	device_unregister(&child_device_obj->device);
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
 * VMBUS is an acpi enumerated device. Get the information we
 * need from DSDT.
 */
#define VTPM_BASE_ADDRESS 0xfed40000
static acpi_status vmbus_walk_resources(struct acpi_resource *res, void *ctx)
{
	resource_size_t start = 0;
	resource_size_t end = 0;
	struct resource *new_res;
	struct resource **old_res = &hyperv_mmio;
	struct resource **prev_res = NULL;

	switch (res->type) {
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	case ACPI_RESOURCE_TYPE_IRQ:
		irq = res->data.irq.interrupts[0];
		return AE_OK;
#endif
	/*
	 * "Address" descriptors are for bus windows. Ignore
	 * "memory" descriptors, which are for registers on
	 * devices.
	 */
	case ACPI_RESOURCE_TYPE_ADDRESS32:
		start = res->data.address32.minimum;
		end = res->data.address32.maximum;
		break;

	case ACPI_RESOURCE_TYPE_ADDRESS64:
		start = res->data.address64.minimum;
		end = res->data.address64.maximum;
		break;

	default:
		/* Unused resource type */
		return AE_OK;

	}
	/*
	 * Ignore ranges that are below 1MB, as they're not
	 * necessary or useful here.
	 */
	if (end < 0x100000)
		return AE_OK;

	new_res = kzalloc(sizeof(*new_res), GFP_ATOMIC);
	if (!new_res)
		return AE_NO_MEMORY;

	/* If this range overlaps the virtual TPM, truncate it. */
	if (end > VTPM_BASE_ADDRESS && start < VTPM_BASE_ADDRESS)
		end = VTPM_BASE_ADDRESS;

	new_res->name = "hyperv mmio";
	new_res->flags = IORESOURCE_MEM;
	new_res->start = start;
	new_res->end = end;

	/*
	 * If two ranges are adjacent, merge them.
	 */
	do {
		if (!*old_res) {
			*old_res = new_res;
			break;
		}

		if (((*old_res)->end + 1) == new_res->start) {
			(*old_res)->end = new_res->end;
			kfree(new_res);
			break;
		}

		if ((*old_res)->start == new_res->end + 1) {
			(*old_res)->start = new_res->start;
			kfree(new_res);
			break;
		}

		if ((*old_res)->start > new_res->end) {
			new_res->sibling = *old_res;
			if (prev_res)
				(*prev_res)->sibling = new_res;
			*old_res = new_res;
			break;
		}

		prev_res = old_res;
		old_res = &(*old_res)->sibling;

	} while (1);

	return AE_OK;
}

static int vmbus_acpi_remove(struct acpi_device *device, int type)
{
	struct resource *cur_res;
	struct resource *next_res;

	if (hyperv_mmio) {
		if (fb_mmio) {
			__release_region(hyperv_mmio, fb_mmio->start,
					 resource_size(fb_mmio));
			fb_mmio = NULL;
		}

		for (cur_res = hyperv_mmio; cur_res; cur_res = next_res) {
			next_res = cur_res->sibling;
			kfree(cur_res);
		}
	}

	return 0;
}

static void vmbus_reserve_fb(void)
{
	int size;
	/*
	 * Make a claim for the frame buffer in the resource tree under the
	 * first node, which will be the one below 4GB.  The length seems to
	 * be underreported, particularly in a Generation 1 VM.  So start out
	 * reserving a larger area and make it smaller until it succeeds.
	 */

	if (screen_info.lfb_base) {
		if (efi_enabled)
			size = max_t(__u32, screen_info.lfb_size, 0x800000);
		else
			size = max_t(__u32, screen_info.lfb_size, 0x4000000);

		for (; !fb_mmio && (size >= 0x100000); size >>= 1) {
			fb_mmio = __request_region(hyperv_mmio,
						   screen_info.lfb_base, size,
						   fb_mmio_name, 0);
		}
	}
}

/**
 * vmbus_allocate_mmio() - Pick a memory-mapped I/O range.
 * @new:		If successful, supplied a pointer to the
 *			allocated MMIO space.
 * @device_obj:		Identifies the caller
 * @min:		Minimum guest physical address of the
 *			allocation
 * @max:		Maximum guest physical address
 * @size:		Size of the range to be allocated
 * @align:		Alignment of the range to be allocated
 * @fb_overlap_ok:	Whether this allocation can be allowed
 *			to overlap the video frame buffer.
 *
 * This function walks the resources granted to VMBus by the
 * _CRS object in the ACPI namespace underneath the parent
 * "bridge" whether that's a root PCI bus in the Generation 1
 * case or a Module Device in the Generation 2 case.  It then
 * attempts to allocate from the global MMIO pool in a way that
 * matches the constraints supplied in these parameters and by
 * that _CRS.
 *
 * Return: 0 on success, -errno on failure
 */
int vmbus_allocate_mmio(struct resource **new, struct hv_device *device_obj,
			resource_size_t min, resource_size_t max,
			resource_size_t size, resource_size_t align,
			bool fb_overlap_ok)
{
	struct resource *iter, *shadow;
	resource_size_t range_min, range_max, start;
	const char *dev_n = dev_name(&device_obj->device);
	int retval;

	retval = -ENXIO;
	down(&hyperv_mmio_lock);

	/*
	 * If overlaps with frame buffers are allowed, then first attempt to
	 * make the allocation from within the reserved region.  Because it
	 * is already reserved, no shadow allocation is necessary.
	 */
	if (fb_overlap_ok && fb_mmio && !(min > fb_mmio->end) &&
	    !(max < fb_mmio->start)) {

		range_min = fb_mmio->start;
		range_max = fb_mmio->end;
		start = (range_min + align - 1) & ~(align - 1);
		for (; start + size - 1 <= range_max; start += align) {
			*new = request_mem_region_exclusive(start, size, dev_n);
			if (*new) {
				retval = 0;
				goto exit;
			}
		}
	}

	for (iter = hyperv_mmio; iter; iter = iter->sibling) {
		if ((iter->start >= max) || (iter->end <= min))
			continue;

		range_min = iter->start;
		range_max = iter->end;

		start = (range_min + align - 1) & ~(align - 1);
		for (; start + size - 1 <= range_max; start += align) {
			shadow = __request_region(iter, start, size, NULL,
						  IORESOURCE_BUSY);
			if (!shadow)
				continue;

			*new = request_mem_region_exclusive(start, size, dev_n);
			if (*new) {
				shadow->name = (char *)*new;
				retval = 0;
				goto exit;
			}
			__release_region(iter, start, size);
		}
	}

exit:
	up(&hyperv_mmio_lock);
	return retval;

}
EXPORT_SYMBOL_GPL(vmbus_allocate_mmio);

/**
 * vmbus_free_mmio() - Free a memory-mapped I/O range.
 * @start:		Base address of region to release.
 * @size:		Size of the range to be allocated
 *
 * This function releases anything requested by
 * vmbus_mmio_allocate().
 */
void vmbus_free_mmio(resource_size_t start, resource_size_t size)
{
	struct resource *iter;

	down(&hyperv_mmio_lock);
	for (iter = hyperv_mmio; iter; iter = iter->sibling) {
		if ((iter->start >= start + size) || (iter->end <= start))
			continue;

		__release_region(iter, start, size);
	}
	release_mem_region(start, size);
	up(&hyperv_mmio_lock);
}
EXPORT_SYMBOL_GPL(vmbus_free_mmio);

/**
 * vmbus_cpu_number_to_vp_number() - Map CPU to VP.
 * @cpu_number: CPU number in Linux terms
 *
 * This function returns the mapping between the Linux processor
 * number and the hypervisor's virtual processor number, useful
 * in making hypercalls and such that talk about specific
 * processors.
 *
 * Return: Virtual processor number in Hyper-V terms
 */
int vmbus_cpu_number_to_vp_number(int cpu_number)
{
	return hv_context.vp_index[cpu_number];
}
EXPORT_SYMBOL_GPL(vmbus_cpu_number_to_vp_number);

static int vmbus_acpi_add(struct acpi_device *device)
{
	acpi_status result;
	int ret_val = -ENODEV;
	struct acpi_device *ancestor;

	hv_acpi_dev = device;

	result = acpi_walk_resources(device->handle, METHOD_NAME__CRS,
					vmbus_walk_resources, NULL);

	if (ACPI_FAILURE(result))
		goto acpi_walk_err;
	/*
	 * Some ancestor of the vmbus acpi device (Gen1 or Gen2
	 * firmware) is the VMOD that has the mmio ranges. Get that.
	 */
	for (ancestor = device->parent; ancestor; ancestor = ancestor->parent) {
		result = acpi_walk_resources(ancestor->handle, METHOD_NAME__CRS,
					     vmbus_walk_resources, NULL);

		if (ACPI_FAILURE(result))
			continue;
		if (hyperv_mmio) {
			vmbus_reserve_fb();
			break;
		}
	}
	ret_val = 0;

acpi_walk_err:
	complete(&probe_event);
	if (ret_val)
		vmbus_acpi_remove(device, 0);
	return ret_val;
}

static const struct acpi_device_id vmbus_acpi_device_ids[] = {
	{"VMBUS", 0},
	{"VMBus", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, vmbus_acpi_device_ids);

static struct acpi_driver vmbus_acpi_driver = {
	.name = "vmbus",
	.ids = vmbus_acpi_device_ids,
	.ops = {
		.add = vmbus_acpi_add,
		.remove = vmbus_acpi_remove,
	},
};

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
static void hv_kexec_handler(void)
{
	int cpu;

	hv_synic_clockevents_cleanup();
	vmbus_initiate_unload(false);
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, hv_synic_cleanup, NULL, 1);
	hyperv_cleanup();
};
#endif

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
static void hv_crash_handler(struct pt_regs *regs)
{
	vmbus_initiate_unload();
	/*
	 * In crash handler we can't schedule synic cleanup for all CPUs,
	 * doing the cleanup for current CPU only. This should be sufficient
	 * for kdump.
	 */
	hv_synic_cleanup(NULL);
	hyperv_cleanup();
};
#endif

static int __init hv_acpi_init(void)
{
	int ret, t;

	if (x86_hyper != &x86_hyper_ms_hyperv)
		return -ENODEV;

	sema_init(&hyperv_mmio_lock, 1);

	init_ms_hyperv_ext();

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

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	if (irq <= 0) {
		ret = -ENODEV;
		goto cleanup;
	}

	ret = vmbus_bus_init(irq);
#else
	ret = vmbus_bus_init();
#endif
	if (ret)
		goto cleanup;
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	hv_setup_kexec_handler(hv_kexec_handler);
	hv_setup_crash_handler(hv_crash_handler);
#endif
	return 0;

cleanup:
	acpi_bus_unregister_driver(&vmbus_acpi_driver);
	hv_acpi_dev = NULL;
	return ret;
}

static void __exit vmbus_exit(void)
{
	int cpu;
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	hv_remove_kexec_handler();
	hv_remove_crash_handler();
#endif
	vmbus_connection.conn_state = DISCONNECTED;
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	hv_synic_clockevents_cleanup();
#endif
	vmbus_disconnect();
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	free_irq(irq, hv_acpi_dev);
#endif
	for_each_online_cpu(cpu) {
		struct hv_per_cpu_context *hv_cpu
			= per_cpu_ptr(hv_context.cpu_context, cpu);

		tasklet_kill(&hv_cpu->msg_dpc);
	}
	vmbus_free_channels();
	if (ms_hyperv_ext.misc_features & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE) {
		atomic_notifier_chain_unregister(&panic_notifier_list,
						 &hyperv_panic_block);
	}
	bus_unregister(&hv_bus);
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, hv_synic_cleanup, NULL, 1);
	hv_synic_free();
	acpi_bus_unregister_driver(&vmbus_acpi_driver);
	hv_cpu_hotplug_quirk(false);
}


MODULE_LICENSE("GPL");
MODULE_VERSION(HV_DRV_VERSION);

subsys_initcall(hv_acpi_init);
module_exit(vmbus_exit);
