
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#include <linux/version.h>

//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define rdtscll(now)    do { (now) = rdtsc_ordered(); } while (0)
#endif

#define HV_DRV_VERSION	"4.2.0"


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
#include <net/tcp_states.h>
#include <net/sock.h>

#define CN_KVP_IDX	0x9

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,4))
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

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))
#define skb_vlan_tag_present(__skb)	((__skb)->vlan_tci & VLAN_TAG_PRESENT)
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,3))
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
#define hid_err(x, y)
#endif

#define blk_queue_max_segments(a, b)

extern bool using_null_legacy_pic;

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,0))
static inline void *vzalloc(unsigned long size)
{
	void *ptr;
	ptr = vmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}
#endif
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,2))
#define NETIF_F_RXCSUM 0
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,6))
static inline void
skb_set_hash(struct sk_buff *skb, __u32 hash, int type)
{
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,6))
        skb->rxhash = hash;
#endif
}
#endif

bool netvsc_set_hash(u32 *hash, struct sk_buff *skb);


#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,1))
static inline __u32
skb_get_hash(struct sk_buff *skb)
{
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,0))
        return skb->hash;
#else
	__u32 hash;
	if (netvsc_set_hash(&hash, skb))
		return hash;
	return 0;
#endif
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static inline void pm_wakeup_event(struct device *dev, unsigned int msec)
{
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
static inline int kstrtouint(const char *s, unsigned int base, unsigned int *res)
{
	int result;
	char *endbufp = NULL;

	result = (int)simple_strtoul(s, &endbufp, 10);
	return result;
}

#endif

#define PTE_SHIFT ilog2(PTRS_PER_PTE)

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,1))
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static inline int page_level_shift(int level)
{
        return (PAGE_SHIFT - PTE_SHIFT) + level * PTE_SHIFT;
}
#endif


#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static inline unsigned long page_level_size(int level)
{
	return 1UL << page_level_shift(level);
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static inline unsigned long page_level_mask(int level)
{
	return ~(page_level_size(level) - 1);
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
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

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
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


#if (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(6,0)) && \
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
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))
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
#endif

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,0))
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

/*
 * Define Infiniband MLX4 dependencies for RDMA driver
 */
struct mlx4_ib_create_cq {
	__u64	buf_addr;
	__u64	db_addr;
};

struct mlx4_ib_create_qp {
	__u64	buf_addr;
	__u64	db_addr;
	__u8	log_sq_bb_count;
	__u8	log_sq_stride;
	__u8	sq_no_prefetch;
	__u8	reserved[5];
};

struct mlx4_ib_alloc_ucontext_resp {
	__u32	dev_caps;
	__u32	qp_tab_size;
	__u16	bf_reg_size;
	__u16	bf_regs_per_page;
	__u32	cqe_size;
};

/*
 * The following READ_ONCE macro is included from
 * tools/include/linux/compiler.h from upstream.
 */
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))

#define __READ_ONCE_SIZE                                                \
({                                                                      \
        switch (size) {                                                 \
        case 1: *(__u8 *)res = *(volatile __u8 *)p; break;              \
        case 2: *(__u16 *)res = *(volatile __u16 *)p; break;            \
        case 4: *(__u32 *)res = *(volatile __u32 *)p; break;            \
        case 8: *(__u64 *)res = *(volatile __u64 *)p; break;            \
        default:                                                        \
                barrier();                                              \
                __builtin_memcpy((void *)res, (const void *)p, size);   \
                barrier();                                              \
        }                                                               \
})

static __always_inline
void __read_once_size(const volatile void *p, void *res, int size)
{
        __READ_ONCE_SIZE;
}

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 * 
 * In contrast to ACCESS_ONCE these two macros will also work on aggregate
 * data types like structs or unions. If the size of the accessed data
 * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)
 * READ_ONCE() and WRITE_ONCE()  will fall back to memcpy and print a
 * compile-time warning.
 * 
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */

#define READ_ONCE(x) \
        ({ union { typeof(x) __val; char __c[1]; } __u; __read_once_size(&(x), __u.__c, sizeof(x)); __u.__val; })
#endif

/*
 * Define VMSock driver dependencies here
 */
static inline int memcpy_from_msg(void *data, struct msghdr *msg, int len)
{
	return memcpy_fromiovec(data, msg->msg_iov, len);
}

static inline int memcpy_to_msg(struct msghdr *msg, void *data, int len)
{
	return memcpy_toiovec(msg->msg_iov, data, len);
}

/*
 * Define ethtool dependencies here.
 */
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
static inline int ethtool_validate_speed(__u32 speed)
{
        return speed <= INT_MAX || speed == SPEED_UNKNOWN;
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
static inline int ethtool_validate_duplex(__u8 duplex)
{
        switch (duplex) {
        case DUPLEX_HALF:
        case DUPLEX_FULL:
        case DUPLEX_UNKNOWN:
                return 1;
        }

        return 0;
}
#endif

/*
 * Define balloon driver dependencies here.
 */

// In-kernel memory onlining is not supported in older kernels.
#define memhp_auto_online 0;

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
static inline long si_mem_available(void)
{
	struct sysinfo val;
	si_meminfo(&val);
	return val.freeram;
}
#endif

/*
 * The function dev_consume_skb_any() was exposed in RHEL 7.2.
 * Provide an inline function for the older versions.
 */
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))
static inline void dev_consume_skb_any(struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}
#endif


#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait socket.
 */
static inline bool sk_fullsock(const struct sock *sk)
{
        return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT);
}
#endif

#define timespec64 timespec
#define ns_to_timespec64 ns_to_timespec
#define do_settimeofday64 do_settimeofday

#endif //#ifdef __KERNEL__
#endif //#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
#endif //#ifndef _HV_COMPAT_H
