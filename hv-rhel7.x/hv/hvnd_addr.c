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

#include <linux/version.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/hyperv.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <linux/cred.h>
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
#include <linux/hyperv.h>


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
	return;
}

void hvnd_addr_deinit(void)
{
	rdma_addr_unregister_client(&self);
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
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
	dev_addr.net = &init_net;
#endif
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
