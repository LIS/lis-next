
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#include <linux/version.h>

//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1


#ifdef __KERNEL__

#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <asm/pgtable_types.h>
#include <net/arp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>


#define CN_KVP_IDX	0x9

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#define HV_DRV_VERSION	"4.0.7"

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE <= 1540)
#ifdef CONFIG_MEMORY_HOTPLUG
#undef CONFIG_MEMORY_HOTPLUG
#endif
#endif

#ifndef pr_warn
#define pr_warn(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#endif

#ifndef HV_STATUS_INSUFFICIENT_BUFFERS
#define HV_STATUS_INSUFFICIENT_BUFFERS	19
#endif

#ifndef RNDIS_STATUS_NETWORK_CHANGE
#define RNDIS_STATUS_NETWORK_CHANGE 0x40010018
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_TX
#define NETIF_F_HW_VLAN_CTAG_TX 0
#endif

#ifndef DID_TARGET_FAILURE
#define DID_TARGET_FAILURE	0x10
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

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1540)
#define hid_err(x, y)
#endif

#define blk_queue_max_segments(a, b)

extern bool using_null_legacy_pic;

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE <= 1536)
static inline void *vzalloc(unsigned long size)
{
	void *ptr;
	ptr = vmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}
#endif
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1538)
#define NETIF_F_RXCSUM 0
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1542)
static inline void
skb_set_hash(struct sk_buff *skb, __u32 hash, int type)
{
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > 1542)
        skb->rxhash = hash;
#endif
}
#endif

bool netvsc_set_hash(u32 *hash, struct sk_buff *skb);


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1793) // 1542)
static inline __u32
skb_get_hash(struct sk_buff *skb)
{
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > 1792) // 1542)
        return skb->hash;
#else
	__u32 hash;
	if (netvsc_set_hash(&hash, skb))
		return hash;
	return 0;
#endif
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1792)
static inline void pm_wakeup_event(struct device *dev, unsigned int msec)
{
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1540)
static inline int kstrtouint(const char *s, unsigned int base, unsigned int *res)
{
	int result;
	char *endbufp = NULL;

	result = (int)simple_strtoul(s, &endbufp, 10);
	return result;
}

#endif

#define PTE_SHIFT ilog2(PTRS_PER_PTE)

#if defined (RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1793)
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1792)
static inline int page_level_shift(int level)
{
        return (PAGE_SHIFT - PTE_SHIFT) + level * PTE_SHIFT;
}
#endif


#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1792)
static inline unsigned long page_level_size(int level)
{
	return 1UL << page_level_shift(level);
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1792)
static inline unsigned long page_level_mask(int level)
{
	return ~(page_level_size(level) - 1);
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1792)
static inline phys_addr_t slow_virt_to_phys(void *__virt_addr)
{
	unsigned long virt_addr = (unsigned long)__virt_addr;
	phys_addr_t phys_addr;
	unsigned long offset;
	int level;
	unsigned long psize;
	unsigned long pmask;
	pte_t *pte;

	pte = lookup_address(virt_addr, &level);
	BUG_ON(!pte);
	psize = page_level_size(level);
	pmask = page_level_mask(level);
	offset = virt_addr & ~pmask;
	phys_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	return (phys_addr | offset);
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1540)
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

/* 
 * The following snippets are from include/linux/u64_stats_sync.h
 *
 *  * In case irq handlers can update u64 counters, readers can use following helpers
 *   * - SMP 32bit arches use seqcount protection, irq safe.
 *    * - UP 32bit must disable irqs.
 *     * - 64bit have no problem atomically reading u64 values, irq safe.
 *      */
static inline unsigned int u64_stats_fetch_begin_irq(const struct u64_stats_sync *syncp)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	return read_seqcount_begin(&syncp->seq);
#else
#if BITS_PER_LONG==32
	local_irq_disable();
#endif
	return 0;
#endif
}

static inline bool u64_stats_fetch_retry_irq(const struct u64_stats_sync *syncp,
					 unsigned int start)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	return read_seqcount_retry(&syncp->seq, start);
#else
#if BITS_PER_LONG==32
	local_irq_enable();
#endif
	return false;
#endif
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE <= 1792)
static inline void u64_stats_init(struct u64_stats_sync *syncp)
{
#if BITS_PER_LONG == 32 && defined(CONFIG_SMP)
	seqcount_init(&syncp->seq);
#endif
}

#define netdev_alloc_pcpu_stats(type)				\
({								\
	typeof(type) __percpu *pcpu_stats = alloc_percpu(type); \
	if (pcpu_stats)	{					\
		int __cpu;					\
		for_each_possible_cpu(__cpu) {			\
			typeof(type) *stat;			\
			stat = per_cpu_ptr(pcpu_stats, __cpu);	\
			u64_stats_init(&stat->syncp);		\
		}						\
	}							\
	pcpu_stats;						\
})
#endif

#endif
#endif
#endif
