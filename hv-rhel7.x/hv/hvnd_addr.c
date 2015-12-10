/*
 * Copyright (c) 2014, Microsoft Corporation.
 *
 * Author:
 *   K. Y. Srinivasan <kys@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * Bug fixes/enhancements: Long Li <longli@microsoft.com>
 */

#include <linux/completion.h>
#include <linux/module.h>
#include <linux/errno.h>
#include "include/linux/hyperv.h"
#include <linux/efi.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/completion.h>
#include <asm/scatterlist.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_addr.h>

#include "vmbus_rdma.h"


#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/nls.h>
#include <linux/workqueue.h>
#include <linux/cdev.h>
#include <linux/hyperv.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

/*
 * Create a char device that can support read/write for passing
 * the payload.
 */

static struct completion ip_event;
static bool opened = false;

char hvnd_ip_addr[4];
char hvnd_mac_addr[6];
bool hvnd_addr_set = false;

int hvnd_get_ip_addr(char **ip_addr, char **mac_addr)
{
	int t;

	/*
	 * Now wait for the user level daemon to get us the
	 * IP addresses bound to the MAC address.
	 */
	if (!hvnd_addr_set) {
		t = wait_for_completion_timeout(&ip_event, 600*HZ);
		if (t == 0)
			return -ETIMEDOUT;
	}

	if (hvnd_addr_set) {
		*ip_addr = hvnd_ip_addr;
		*mac_addr = hvnd_mac_addr;
		return 0;
	}

	return -ENODATA;
}

static ssize_t hvnd_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	char input[120];
	int scaned, i;
	unsigned int mac_addr[6], ip_addr[4];

	if (hvnd_addr_set) {
		hvnd_error("IP/MAC address already set, ignoring input\n");
		return count;
	}

	if (count > sizeof(input)-1)
		return -EINVAL;

	if (copy_from_user(input, buf, count))
		return -EFAULT;

	input[count] = 0;

	/*
	 * Wakeup the context that may be waiting for this.
	 */
	hvnd_debug("get user mode input: %s\n", input);

	scaned = sscanf(input, "rdmaMacAddress=\"%x:%x:%x:%x:%x:%x\" rdmaIPv4Address=\"%u.%u.%u.%u\"",
		&mac_addr[0],
		&mac_addr[1],
		&mac_addr[2],
		&mac_addr[3],
		&mac_addr[4],
		&mac_addr[5],
		&ip_addr[0],
		&ip_addr[1],
		&ip_addr[2],
		&ip_addr[3]);

	if (scaned == 10) {

		for(i=0; i<6; i++)
			hvnd_mac_addr[i] = (char) mac_addr[i];
		for(i=0; i<4; i++)
			hvnd_ip_addr[i] = (char) ip_addr[i];

		hvnd_error("Scanned IP address: %pI4 Mac address: %pM\n", hvnd_ip_addr, hvnd_mac_addr);

		hvnd_addr_set = true;
		complete(&ip_event);
	}

	return count;
}

static int hvnd_open(struct inode *inode, struct file *f)
{
	/*
	 * The user level daemon that will open this device is
	 * really an extension of this driver. We can have only
	 * active open at a time.
	 */
	if (opened)
		return -EBUSY;

	/*
	 * The daemon is alive; setup the state.
	 */
	opened = true;
	return 0;
}

static int hvnd_release(struct inode *inode, struct file *f)
{
	/*
	 * The daemon has exited; reset the state.
	 */
	opened = false;
	return 0;
}


static const struct file_operations hvnd_fops = {
	.write          = hvnd_write,
	.release	= hvnd_release,
	.open		= hvnd_open,
};

static struct miscdevice hvnd_misc = {
	.minor          = MISC_DYNAMIC_MINOR,
	.name           = "hvnd_rdma",
	.fops           = &hvnd_fops,
};

static int hvnd_dev_init(void)
{
	init_completion(&ip_event);
	return misc_register(&hvnd_misc);
}

static void hvnd_dev_deinit(void)
{

	/*
	 * The device is going away - perhaps because the
	 * host has rescinded the channel. Setup state so that
	 * user level daemon can gracefully exit if it is blocked
	 * on the read semaphore.
	 */
	opened = false;
	/*
	 * Signal the semaphore as the device is
	 * going away.
	 */
	misc_deregister(&hvnd_misc);
}

int hvnd_get_outgoing_rdma_addr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
				union nd_sockaddr_inet *og_addr)
{
	int ret;
	/*
	 * Query the host and select the first address.
	 */
	struct pkt_query_addr_list pkt;

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything

	hvnd_init_hdr(&pkt.hdr,
		      (sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1)),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST, 0, 0, 0);

	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = uctx->adaptor_hdl;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr,
				  sizeof(pkt), (u64)&pkt);

	if (ret)
		return ret;

	/*
	 * Copy the address out.
	 */

	memcpy(og_addr, &pkt.ioctl.out[0], sizeof(*og_addr));
	return 0;

}

static struct rdma_addr_client self;

struct resolve_cb_context {
	struct rdma_dev_addr *addr;
	struct completion comp;
};

void hvnd_addr_init(void)
{
	rdma_addr_register_client(&self);
	hvnd_dev_init();
	return;
}

void hvnd_addr_deinit(void)
{
	rdma_addr_unregister_client(&self);
	hvnd_dev_deinit();
	return;
}

static void resolve_cb(int status, struct sockaddr *src_addr,
	     struct rdma_dev_addr *addr, void *context)
{
	memcpy(((struct resolve_cb_context *)context)->addr, addr, sizeof(struct
				rdma_dev_addr));
	complete(&((struct resolve_cb_context *)context)->comp);
}

int hvnd_get_neigh_mac_addr(struct sockaddr *local, struct sockaddr *remote, char *mac_addr)
{
	struct rdma_dev_addr dev_addr;
	struct resolve_cb_context ctx;
	int ret;

	memset(&dev_addr, 0, sizeof(dev_addr));
	ctx.addr = &dev_addr;
	init_completion(&ctx.comp);

	ret = rdma_resolve_ip(&self, local, remote, &dev_addr, 1000, resolve_cb, &ctx);

	if (ret) {
		hvnd_error("rdma_resolve_ip failed ret=%d\n", ret);
		return ret;
	}

	wait_for_completion(&ctx.comp);
	memcpy(mac_addr, dev_addr.dst_dev_addr, ETH_ALEN);
	return ret;
}
