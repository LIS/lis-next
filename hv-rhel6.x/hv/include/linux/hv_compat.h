
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#include <linux/version.h>

/*
 * Helpers for determining EXTRAVERSION info on RHEL/CentOS update kernels
 */
#if defined(RHEL_RELEASE_VERSION)
#define KERNEL_EXTRAVERSION(a,b) (((a) << 16) + (b))

#define RHEL_RELEASE_UPDATE_VERSION(a,b,c,d) \
	(((RHEL_RELEASE_VERSION(a,b)) << 32) + (KERNEL_EXTRAVERSION(c,d)))

#if defined(EXTRAVERSION1) && defined (EXTRAVERSION2)
#define RHEL_RELEASE_UPDATE_CODE \
	RHEL_RELEASE_UPDATE_VERSION(RHEL_MAJOR,RHEL_MINOR,EXTRAVERSION1,EXTRAVERSION2)
#else
#define RHEL_RELEASE_UPDATE_CODE \
	RHEL_RELEASE_UPDATE_VERSION(RHEL_MAJOR,RHEL_MINOR,0,0)
#endif
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#define HV_DRV_VERSION	"4.2.6"
#define _HV_DRV_VERSION 0x1AA

#ifdef __KERNEL__

#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
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
#include <scsi/scsi_transport_fc.h>

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,6))
#include <linux/u64_stats_sync.h>
#endif

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

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present(__skb)	((__skb)->vlan_tci & VLAN_TAG_PRESENT)
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

#define NDIS_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION_2   40
#define HASH_KEYLEN NDIS_RSS_HASH_SECRET_KEY_MAX_SIZE_REVISION_2

#define NETVSC_HASH_KEYLEN 40
static u8 netvsc_hash_key[NETVSC_HASH_KEYLEN] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

union sub_key {
	u64 k;
	struct {
		u8 pad[3];
		u8 kb;
		u32 ka;
	};
};

/* Toeplitz hash function
 * data: network byte order
 * return: host byte order
 */
static inline u32 comp_hash(u8 *key, int klen, void *data, int dlen)
{
	union sub_key subk;
	int k_next = 4;
	u8 dt;
	int i, j;
	u32 ret = 0;

	subk.k = 0;
	subk.ka = ntohl(*(u32 *)key);

	for (i = 0; i < dlen; i++) {
		subk.kb = key[k_next];
		k_next = (k_next + 1) % klen;
		dt = ((u8 *)data)[i];
		for (j = 0; j < 8; j++) {
			if (dt & 0x80)
				ret ^= subk.ka;
			dt <<= 1;
			subk.k <<= 1;
		}
	}

	return ret;
}

static inline bool netvsc_set_hash(u32 *hash, struct sk_buff *skb)
{
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	__be32 dbuf[9];
	int data_len = 0;

	skb_reset_mac_header(skb);

	if (eth_hdr(skb)->h_proto != htons(ETH_P_IP) &&
	    eth_hdr(skb)->h_proto != htons(ETH_P_IPV6))
		return false;

	iphdr = ip_hdr(skb);
	ipv6hdr = ipv6_hdr(skb);

	if (iphdr->version == 4) {
		/* check src addr */
		dbuf[0] = iphdr->saddr;
		if (dbuf[0] == 0)
			return false;

		/* dst addr */
		dbuf[1] = iphdr->daddr;
		if (iphdr->protocol == IPPROTO_TCP) {
			tcphdr = tcp_hdr(skb);
			if (tcphdr != NULL) {
				dbuf[2] = *(__be32 *)&tcp_hdr(skb)->source;
				data_len = 12;
			}
		}
	} else if (ipv6hdr->version == 6) {
		memcpy(dbuf, &ipv6hdr->saddr, 32);
		/* src addr
		 * ignore RSS hashing for DHCP discovery messages.
		 */
		if ((dbuf[0] | dbuf[1] | dbuf[2] | dbuf[3]) == 0)
			return false;

		if (ipv6hdr->nexthdr == IPPROTO_TCP) {
			tcphdr = tcp_hdr(skb);
			if (tcphdr != NULL) {
				dbuf[8] = *(__be32 *)&tcp_hdr(skb)->source;
				data_len = 36;
			}
		}
	}

	/* if data_len is 0, we are not able to compute the RSS hash. */
	if (data_len == 0)
		return false;

	*hash = comp_hash(netvsc_hash_key, HASH_KEYLEN, dbuf, data_len);
	return true;
}

static inline __u32
skb_get_hash(struct sk_buff *skb)
{
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
        return skb->hash;
#else
	__u32 hash;
	if (netvsc_set_hash(&hash, skb))
		return hash;
	return 0;
#endif
}

static inline void pm_wakeup_event(struct device *dev, unsigned int msec)
{
}

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

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,8))
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}
#endif

static inline int page_level_shift(int level)
{
        return (PAGE_SHIFT - PTE_SHIFT) + level * PTE_SHIFT;
}

static inline unsigned long page_level_size(int level)
{
	return 1UL << page_level_shift(level);
}

static inline unsigned long page_level_mask(int level)
{
	return ~(page_level_size(level) - 1);
}

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
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,6))
struct u64_stats_sync {
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	seqcount_t	seq;
#endif
};

static inline void u64_stats_update_begin(struct u64_stats_sync *syncp)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	write_seqcount_begin(&syncp->seq);
#endif
}

static inline void u64_stats_update_end(struct u64_stats_sync *syncp)
{
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	write_seqcount_end(&syncp->seq);
#endif
}

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

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,0))
#define this_cpu_ptr(ptr) SHIFT_PERCPU_PTR((ptr), my_cpu_offset)

#define get_cpu_ptr(var) ({	\
	preempt_disable();	\
	this_cpu_ptr(var); })

#define put_cpu_ptr(var) do {	\
	(void)(var);		\
        preempt_enable();	\
} while (0)


#define __percpu
#endif

#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(6,2))
#define for_each_set_bit(bit, addr, size) for_each_bit(bit, addr, size)
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
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,8))  

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
 *  *  * Prevent the compiler from merging or refetching reads or writes. The  
 *   *   * compiler is also forbidden from reordering successive instances of  
 *    *    * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the  
 *     *     * compiler is aware of some particular ordering.  One way to make the  
 *      *      * compiler aware of ordering is to put the two invocations of READ_ONCE,  
 *       *       * WRITE_ONCE or ACCESS_ONCE() in different C statements.  
 *        *        *  
 *         *         * In contrast to ACCESS_ONCE these two macros will also work on aggregate  
 *          *          * data types like structs or unions. If the size of the accessed data  
 *           *           * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)  
 *            *            * READ_ONCE() and WRITE_ONCE()  will fall back to memcpy and print a  
 *             *             * compile-time warning.  
 *              *              *  
 *               *               * Their two major use cases are: (1) Mediating communication between  
 *                *                * process-level code and irq/NMI handlers, all running on the same CPU,  
 *                 *                 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise  
 *                  *                  * mutilate accesses that either do not require ordering or that interact  
 *                   *                   * with an explicit memory barrier or atomic instruction that provides the  
 *                    *                    * required ordering.  
 *                     *                     */  
 
#define READ_ONCE(x) \
	({ union { typeof(x) __val; char __c[1]; } __u; __read_once_size(&(x), __u.__c, sizeof(x)); __u.__val; })
#endif

/*
 * Define ethtool dependencies here.
 */
#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN -1
#endif

static inline int ethtool_validate_speed(__u32 speed)
{
	return speed <= INT_MAX || speed == SPEED_UNKNOWN;
}

#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN 0xff
#endif

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

/*
 * Define balloon driver dependencies here.
 */

// In-kernel memory onlining is not supported in older kernels.
#define memhp_auto_online 0;

static inline long si_mem_available(void)
{
        struct sysinfo val;
        si_meminfo(&val);
        return val.freeram;
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
static inline unsigned long vm_memory_committed(void)
{
	struct sysinfo val;
	si_meminfo(&val);
	return val.totalram - val.freeram;
}
#endif

/*
 * The function dev_consume_skb_any() was exposed in RHEL 7.2.
 * Provide an inline function for the older versions.
 */
static inline void dev_consume_skb_any(struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,1))

/**
 * skb_checksum_none_assert - make sure skb ip_summed is CHECKSUM_NONE
 * @skb: skb to check
 *
 * fresh skbs have their ip_summed set to CHECKSUM_NONE.
 * Instead of forcing ip_summed to CHECKSUM_NONE, we can
 * use this helper, to document places where we make this assertion.
 *
 * Function was introduced in the 6.1 release.  NHM
 */
static inline void skb_checksum_none_assert(struct sk_buff *skb)
{
#ifdef DEBUG
        BUG_ON(skb->ip_summed != CHECKSUM_NONE);
#endif
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
#include <linux/etherdevice.h>
/**
 * ether_addr_equal - Compare two Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two ethernet addresses, returns true if equal
 */
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
        return !compare_ether_addr(addr1, addr2);
}
#endif

#define for_each_clear_bit(bit, addr, size) \
        for ((bit) = find_first_zero_bit((addr), (size));       \
             (bit) < (size);                                    \
             (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
/**
 * ethtool_rxfh_indir_default - get default value for RX flow hash indirection
 * @index: Index in RX flow hash indirection table
 * @n_rx_rings: Number of RX rings to use
 *
 * This function provides the default policy for RX flow hash indirection.
 */
static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
{
        return index % n_rx_rings;
}
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,4))
#define rtnl_dereference(ptr) (ptr)
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,3))
static inline bool is_vlan_dev(const struct net_device *dev)
{
        return dev->priv_flags & IFF_802_1Q_VLAN;
}
#endif

#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT 64
#endif

#define timespec64 timespec
#define ns_to_timespec64 ns_to_timespec
#define do_settimeofday64 do_settimeofday

/**
 * fc_eh_timed_out - FC Transport I/O timeout intercept handler
 * @scmd:	The SCSI command which timed out
 *
 * This routine protects against error handlers getting invoked while a
 * rport is in a blocked state, typically due to a temporarily loss of
 * connectivity. If the error handlers are allowed to proceed, requests
 * to abort i/o, reset the target, etc will likely fail as there is no way
 * to communicate with the device to perform the requested function. These
 * failures may result in the midlayer taking the device offline, requiring
 * manual intervention to restore operation.
 *
 * This routine, called whenever an i/o times out, validates the state of
 * the underlying rport. If the rport is blocked, it returns
 * EH_RESET_TIMER, which will continue to reschedule the timeout.
 * Eventually, either the device will return, or devloss_tmo will fire,
 * and when the timeout then fires, it will be handled normally.
 * If the rport is not blocked, normal error handling continues.
 *
 * Notes:
 *	This routine assumes no locks are held on entry.
 */
static inline enum blk_eh_timer_return
fc_eh_timed_out(struct scsi_cmnd *scmd)
{
	struct fc_rport *rport = starget_to_rport(scsi_target(scmd->device));

	if (rport->port_state == FC_PORTSTATE_BLOCKED)
		return BLK_EH_RESET_TIMER;

	return BLK_EH_NOT_HANDLED;
}

/**
 * refcount_t - variant of atomic_t specialized for reference counts
 * @refs: atomic_t counter field
 *
 * The counter saturates at UINT_MAX and will not move once
 * there. This avoids wrapping the counter and causing 'spurious'
 * use-after-free bugs.
 */
typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

static inline bool refcount_sub_and_test(unsigned int i, refcount_t *r)
{
	unsigned int old, new, val = atomic_read(&r->refs);

	do {
		if (unlikely(val == UINT_MAX))
			return false;

		new = val - i;
		if (new > val) {
			WARN_ONCE(new > val, "refcount_t: underflow; use-after-free.\n");
			return false;
		}

		old = atomic_cmpxchg(&r->refs, val, new);
		if (old == val)
			break;

		val = old;
	} while (1);

	return !new;
}

static inline bool refcount_dec_and_test(refcount_t *r)
{
	return refcount_sub_and_test(1, r);
}

static inline void refcount_set(refcount_t *r, unsigned int n)
{
	atomic_set(&r->refs, n);
}

#define netdev_lockdep_set_classes(dev)				\
{								\
	static struct lock_class_key qdisc_xmit_lock_key;	\
	static struct lock_class_key dev_addr_list_lock_key;	\
	unsigned int i;						\
								\
	lockdep_set_class(&(dev)->addr_list_lock,		\
			  &dev_addr_list_lock_key); 		\
	for (i = 0; i < (dev)->num_tx_queues; i++)		\
		lockdep_set_class(&(dev)->_tx[i]._xmit_lock,	\
				  &qdisc_xmit_lock_key);	\
}

#endif /* end ifdef __KERNEL */
#endif /* end LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35) */
#endif
