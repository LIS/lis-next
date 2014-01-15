
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#ifdef __KERNEL__

#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/arp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>

#ifdef CONFIG_MEMORY_HOTPLUG
#undef CONFIG_MEMORY_HOTPLUG
#endif

#define CN_KVP_IDX	0x9

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#ifndef pr_warn
#define pr_warn(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#endif

#ifndef HV_STATUS_INSUFFICIENT_BUFFERS
#define HV_STATUS_INSUFFICIENT_BUFFERS	19
#endif

#ifndef DID_TARGET_FAILURE
#define DID_TARGET_FAILURE	0x10
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1537)
static inline int uuid_le_cmp(const uuid_le u1, const uuid_le u2)
{
	return memcmp(&u1, &u2, sizeof(uuid_le));
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1539)
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif

#define hid_err(x, y)

#define blk_queue_max_segments(a, b)

/*
 * For Hyper-V devices we use the device guid as the id.
 * This was introduced in Linux 3.2 (/include/linux/mod_devicetable.h)
 */
struct hv_vmbus_device_id {
	__u8 guid[16];
	unsigned long driver_data;
};

#ifndef netdev_err
static inline void netdev_err(struct net_device *net, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

#endif

#ifndef netdev_dbg
#if defined(DEBUG)
#define netdev_dbg(dev, fmt, ...)  netdev_err(dev, fmt, ...)
#else
#define netdev_dbg(__dev, format, args...)                      \
({                                                              \
	if (0)                                                  \
		netdev_err(__dev, format, ##args); \
	0;                                                      \
})

#endif
#endif


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE == 1536) && \
LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
static inline void  netif_notify_peers(struct net_device *net)
{
	struct in_device *idev;

	rcu_read_lock();
	if (((idev = __in_dev_get_rcu(net)) != NULL) &&
		idev->ifa_list != NULL) {
		arp_send(ARPOP_REQUEST, ETH_P_ARP,
		idev->ifa_list->ifa_address, net,
		idev->ifa_list->ifa_address, NULL,
		net->dev_addr, NULL);
	}
	rcu_read_unlock();
}

#endif
#endif
#endif
