
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#include <linux/version.h>

/*
 *  * Helpers for determining EXTRAVERSION info on RHEL/CentOS update kernels
 *   */
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


//#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define rdtscll(now)    do { (now) = rdtsc_ordered(); } while (0)
#endif

#define HV_DRV_VERSION	"4.2.6"
#define _HV_DRV_VERSION 0x1AA

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
#include <scsi/scsi_transport_fc.h>
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

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
#define napi_consume_skb(skb, budget)     dev_consume_skb_any(skb)
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

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))
struct pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};
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
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4))
static inline int memcpy_from_msg(void *data, struct msghdr *msg, int len)
{
	return memcpy_fromiovec(data, msg->msg_iov, len);
}
#endif

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


#if defined(RHEL_RELEASE_UPDATE_CODE) && \
(RHEL_RELEASE_UPDATE_CODE < RHEL_RELEASE_UPDATE_VERSION(7, 2, 327, 36))
/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait socket.
 */
static inline bool sk_fullsock(const struct sock *sk)
{
        return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT);
}
#endif

static inline struct cpumask *irq_data_get_affinity_mask(struct irq_data *d)
{
	return d->affinity;
}


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
static inline enum blk_eh_timer_return fc_eh_timed_out(struct scsi_cmnd *scmd)
{
	struct fc_rport *rport = starget_to_rport(scsi_target(scmd->device));

	if (rport && rport->port_state == FC_PORTSTATE_BLOCKED)
		return BLK_EH_RESET_TIMER;

	return BLK_EH_NOT_HANDLED;
}

/**
 * required for daf0cd445a218314f9461d67d4f2b9c24cdd534b
 */
#define FC_PORT_ROLE_FCP_DUMMY_INITIATOR        0x08

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
	static struct lock_class_key qdisc_tx_busylock_key;	\
	static struct lock_class_key qdisc_xmit_lock_key;	\
	static struct lock_class_key dev_addr_list_lock_key;	\
	unsigned int i;						\
								\
	(dev)->qdisc_tx_busylock = &qdisc_tx_busylock_key;	\
	lockdep_set_class(&(dev)->addr_list_lock,		\
			  &dev_addr_list_lock_key); 		\
	for (i = 0; i < (dev)->num_tx_queues; i++)		\
		lockdep_set_class(&(dev)->_tx[i]._xmit_lock,	\
				  &qdisc_xmit_lock_key);	\
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
static inline int cpumask_next_wrap(int n, const struct cpumask *mask, int start, bool wrap)
{
        int next;

again:
        next = cpumask_next(n, mask);

        if (wrap && n < start && next >= start) {
                return nr_cpumask_bits;

        } else if (next >= nr_cpumask_bits) {
                wrap = true;
                n = -1;
                goto again;
        }

        return next;
}
#endif

#define for_each_cpu_wrap(cpu, mask, start)                                     \
        for ((cpu) = cpumask_next_wrap((start)-1, (mask), (start), false);      \
             (cpu) < nr_cpumask_bits;                                           \
             (cpu) = cpumask_next_wrap((cpu), (mask), (start), true))


#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & \
	 (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))
#endif

#ifndef U64_MAX
#define U64_MAX                ((u64)~0ULL)
#endif

#ifndef for_each_cpu_wrap
/**
 * for_each_cpu_wrap - iterate over every cpu in a mask, starting at a specified location
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask poiter
 * @start: the start location
 *
 * The implementation does not assume any bit in @mask is set (including @start).
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
extern int cpumask_next_wrap(int n, const struct cpumask *mask, int start, bool wrap);

#define for_each_cpu_wrap(cpu, mask, start)					\
	for ((cpu) = cpumask_next_wrap((start)-1, (mask), (start), false);	\
	     (cpu) < nr_cpumask_bits;						\
	     (cpu) = cpumask_next_wrap((cpu), (mask), (start), true))
#endif

#ifndef __ASSEMBLY__

#ifndef __ASM_FORM_RAW
#define __ASM_FORM_RAW(x)     #x

#ifndef __x86_64__
/* 32 bit */
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(a)
#else
/* 64 bit */
# define __ASM_SEL_RAW(a,b) __ASM_FORM_RAW(b)
#endif

#ifdef __ASM_REG
#undef __ASM_REG
#define __ASM_REG(reg)         __ASM_SEL_RAW(e##reg, r##reg)
#endif

#endif

#define _ASM_SP                __ASM_REG(sp)

/*
 * This output constraint should be used for any inline asm which has a "call"
 * instruction.  Otherwise the asm may be inserted before the frame pointer
 * gets set up by the containing function.  If you forget to do this, objtool
 * may print a "call without frame pointer save/setup" warning.
 */
register unsigned long current_stack_pointer asm(_ASM_SP);
#define ASM_CALL_CONSTRAINT "+r" (current_stack_pointer)
#endif

#endif //#ifdef __KERNEL__
#endif //#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
#endif //#ifndef _HV_COMPAT_H
