
#ifndef _HV_COMPAT_H
#define _HV_COMPAT_H

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1

#ifdef __KERNEL__

#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/uuid.h>
#include <linux/netdevice.h>
#include <linux/nls.h>
#include <linux/input.h>
#include <linux/timex.h>
#include <linux/unaligned/le_struct.h>
#include <linux/inetdevice.h>
#include <linux/libata-compat.h> /* sg_* apis */
#include <net/arp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>

#define CN_KVP_IDX	0x9
#define CN_KVP_VAL	0x1

#define CN_VSS_IDX	0xA
#define CN_VSS_VAL	0x1


#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT	VLAN_CFI_MASK
#define VLAN_N_VID		4096


#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#ifndef pr_warn
#define pr_warn(fmt, arg...) printk(KERN_WARNING fmt, ##arg)
#endif

#ifndef pr_err
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif

#define IRQ0_VECTOR FIRST_EXTERNAL_VECTOR

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1287)
static inline void *vzalloc(unsigned long size)
{
        return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
                        PAGE_KERNEL);
}

static inline struct sk_buff *__netdev_alloc_skb_ip_align(struct net_device *dev,
                                unsigned int length, gfp_t gfp)
{
        struct sk_buff *skb = __netdev_alloc_skb(dev, length + NET_IP_ALIGN, gfp);

        if (NET_IP_ALIGN && skb)
                skb_reserve(skb, NET_IP_ALIGN);
        return skb;
}

static inline struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev,
                                unsigned int length)
{
        return __netdev_alloc_skb_ip_align(dev, length, GFP_ATOMIC);
}
#endif

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1286)
static inline bool cancel_delayed_work_sync(void *work)
{
	return cancel_delayed_work((struct work_struct *)work);
}

static inline bool cancel_work_sync(void *work)
{
	return cancel_delayed_work((struct work_struct *)work);
}

#endif
static inline int dev_set_name(struct device *dev, const char *fmt, int num)
{
	int err;

	sprintf(dev->bus_id, fmt, num);
	err = kobject_set_name(&dev->kobj, fmt, num);
	return err;
}

#define __DELAYED_WORK_INITIALIZER(n, f, d) {                           \
	.work.entry  = { &(n.work).entry, &(n.work).entry },                    \
	.work.func = (f),                                               \
	.work.data = (d),                                               \
	.work.timer = TIMER_INITIALIZER(NULL, 0, 0),                    \
	}

#define DECLARE_DELAYED_WORK(n, f, d)                              \
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, d)

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1286)
static inline char *dev_name(struct device *dev)
{
	return dev->bus_id;
}

struct delayed_work {
	struct work_struct work;
};

#define INIT_DELAYED_WORK(_work, _func)                       \
	INIT_WORK(&(_work)->work, _func, &(_work)->work)



void netdev_err(struct net_device *net, const char *fmt, ...);
#endif

#ifndef HV_STATUS_INSUFFICIENT_BUFFERS
#define HV_STATUS_INSUFFICIENT_BUFFERS	19
#endif

#ifndef DID_TARGET_FAILURE
#define DID_TARGET_FAILURE	0x10
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC       02000000        /* set close_on_exec */
#endif

static inline int uuid_le_cmp(const uuid_le u1, const uuid_le u2)
{
	return memcmp(&u1, &u2, sizeof(uuid_le));
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < 1539)
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

#define BUS_VIRTUAL     0x06

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif

static inline void *sg_virt(struct scatterlist *sg)
{
	return sg->page;
}

static inline void  hv_set_buf(struct scatterlist *sg, void *buf,
                                unsigned int length)
{
	sg->page = (struct page *)buf;
	sg->length = length;
}


#define blk_queue_max_segments(a, b)

/*
 * For Hyper-V devices we use the device guid as the id.
 * This was introduced in Linux 3.2 (/include/linux/mod_devicetable.h)
 */
struct hv_vmbus_device_id {
	__u8 guid[16];
	unsigned long driver_data;
};

void rhel_5_x_power_off(void);

#define orderly_poweroff(x) rhel_5_x_power_off()

struct hid_device_id {
	__u16 bus;
	__u16 pad1;
	__u32 vendor;
	__u32 product;
	unsigned long  driver_data;
};

#define HID_ANY_ID      (~0)
#define HID_BUS_ANY     0xffff

#define BTN_TRIGGER_HAPPY	0x2c0
#define KEY_CONTEXT_MENU	0x1b6
#define KEY_VIDEOPHONE		0x1a0
#define KEY_GAMES               0x1a1
#define KEY_MEDIA_REPEAT	0x1b7
#define KEY_WORDPROCESSOR	0x1a5
#define KEY_EDITOR		0x1a6
#define KEY_SPREADSHEET		0x1a7
#define KEY_GRAPHICSEDITOR	0x1a8
#define KEY_PRESENTATION	0x1a9
#define KEY_DATABASE            0x1aa
#define KEY_NEWS		0x1ab
#define KEY_VOICEMAIL		0x1ac
#define KEY_ADDRESSBOOK		0x1ad
#define KEY_LOGOFF		0x1b1
#define KEY_SPELLCHECK		0x1b0
#define KEY_IMAGES		0x1ba
#define KEY_MESSENGER		0x1ae
#define KEY_ZOOMIN		0x1a2
#define KEY_ZOOMOUT		0x1a3
#define KEY_ZOOMRESET		0x1a4
#define ABS_MT_POSITION_X	0x35


struct input_keymap_entry {
#define INPUT_KEYMAP_BY_INDEX   (1 << 0)
	__u8  flags;
	__u8  len;
	__u16 index;
	__u32 keycode;
	__u8  scancode[32];
};

#ifdef CONFIG_MEMORY_HOTPLUG
#undef CONFIG_MEMORY_HOTPLUG
#endif

#undef CONFIG_HIDRAW
#define HIDRAW_BUFFER_SIZE 64

static inline void *input_get_drvdata(struct input_dev *dev)
{
	return dev->dev;

}

static inline void input_set_drvdata(struct input_dev *dev, void *data)
{
	dev->dev = data;
}

static inline int input_scancode_to_scalar(const struct input_keymap_entry *ke,
                             unsigned int *scancode)
{
        switch (ke->len) {
        case 1:
                *scancode = *((u8 *)ke->scancode);
                break;

        case 2:
                *scancode = *((u16 *)ke->scancode);
                break;

        case 4:
                *scancode = *((u32 *)ke->scancode);
                break;

        default:
                return -EINVAL;
        }

        return 0;
}

/*
 * Synchronization events.
 */

#define SYN_REPORT		0
#define SYN_CONFIG		1
#define SYN_MT_REPORT		2
#define SYN_DROPPED		3

#define ABS_MT_TOUCH_MAJOR	0x30    /* Major axis of touching ellipse */
#define ABS_MT_DISTANCE		0x3b    /* Contact hover distance */
#define ABS_MT_TOUCH_MINOR	0x31    /* Minor axis (omit if circular) */
#define ABS_MT_WIDTH_MAJOR	0x32    /* Major axis of approaching ellipse */
#define ABS_MT_WIDTH_MINOR	0x33    /* Minor axis (omit if circular) */
#define ABS_MT_ORIENTATION	0x34    /* Ellipse orientation */
#define ABS_MT_POSITION_Y	0x36    /* Center Y ellipse position */
#define ABS_MT_TOOL_TYPE	0x37    /* Type of touching device */
#define ABS_MT_BLOB_ID		0x38    /* Group a set of packets as a blob */

/* Implementation details, userspace should not care about these */
#define ABS_MT_FIRST		ABS_MT_TOUCH_MAJOR
#define ABS_MT_LAST		ABS_MT_DISTANCE

#define ABS_MAX                 0x3f
#define ABS_CNT                 (ABS_MAX+1)


static inline void set_host_byte(struct scsi_cmnd *cmd, char status)
{
	cmd->result = (cmd->result & 0xff00ffff) | (status << 16);
}

struct timespec ns_to_timespec(const s64 nsec);


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
