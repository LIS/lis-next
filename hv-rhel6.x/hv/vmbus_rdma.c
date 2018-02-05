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
#include <linux/sched.h>
#include <linux/types.h>
#include <asm/scatterlist.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>

#include "vmbus_rdma.h"

/*
 * We only have a single rdma device on the host;
 * have a single receive buffer.
 */


static char hvnd_recv_buffer[PAGE_SIZE * 4];

static atomic_t irp_local_hdl;

char *hvnd_get_op_name(int ioctl)
{
	switch (ioctl) {
	case IOCTL_ND_PROVIDER_INIT:
		return "IOCTL_ND_PROVIDER_INIT\n";
	case IOCTL_ND_PROVIDER_BIND_FILE:
		return "IOCTL_ND_PROVIDER_BIND_FILE\n";
	case IOCTL_ND_ADAPTER_OPEN:
		return "IOCTL_ND_ADAPTER_OPEN\n";

	case IOCTL_ND_ADAPTER_CLOSE:
		return "IOCTL_ND_ADAPTER_CLOSE\n";

	case IOCTL_ND_ADAPTER_QUERY: 
		return "IOCTL_ND_ADAPTER_QUERY\n";

	case IOCTL_ND_PD_CREATE:
		return "IOCTL_ND_PD_CREATE\n";

	case IOCTL_ND_PD_FREE:
		return "IOCTL_ND_PD_FREE\n";

	case IOCTL_ND_CQ_CREATE:
		return "IOCTL_ND_CQ_CREATE\n";

	case IOCTL_ND_CQ_FREE:
		return "IOCTL_ND_CQ_FREE\n";
	case IOCTL_ND_CQ_CANCEL_IO:
		return "IOCTL_ND_CQ_CANCEL_IO\n";
	case IOCTL_ND_CQ_GET_AFFINITY:
		return "IOCTL_ND_CQ_GET_AAFINITY\n";
	case IOCTL_ND_CQ_MODIFY:
		return "IOCTL_ND_CQ_MODIFY\n";

	case IOCTL_ND_CQ_NOTIFY:
		return "IOCTL_ND_CQ_NOTIFY\n";


	case IOCTL_ND_LISTENER_CREATE: 
		return "IOCTL_ND_LISTENER_CREATE\n";

	case IOCTL_ND_LISTENER_FREE: 
		return "IOCTL_ND_LISTENER_FREE\n";

	case IOCTL_ND_QP_FREE: 
		return "IOCTL_ND_QP_FREE\n";

	case IOCTL_ND_CONNECTOR_CANCEL_IO: 
		return "IOCTL_ND_CONNECTOR_CANCEL_IO\n";

	case IOCTL_ND_LISTENER_CANCEL_IO: 
		return "IOCTL_ND_LISTENER_CANCEL_IO\n";

	case IOCTL_ND_LISTENER_BIND: 
		return "IOCTL_ND_LISTENER_BIND\n";

	case IOCTL_ND_LISTENER_LISTEN: 
		return "IOCTL_ND_LISTENER_LISTEN\n";

	case IOCTL_ND_LISTENER_GET_ADDRESS: 
		return "IOCTL_ND_LISTENER_GET_ADDRESS\n";

	case IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST: 
		return "IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST\n";



	case IOCTL_ND_CONNECTOR_CREATE: 
		return "IOCTL_ND_CONNECTOR_CREATE\n";

	case IOCTL_ND_CONNECTOR_FREE: 
		return "IOCTL_ND_CONNECTOR_FREE\n";

	case IOCTL_ND_CONNECTOR_BIND: 
		return "IOCTL_ND_CONNECTOR_BIND\n";

	case IOCTL_ND_CONNECTOR_CONNECT: //KYS: ALERT: ASYNCH Operation 
		return "IOCTL_ND_CONNECTOR_CONNECT\n";

	case IOCTL_ND_CONNECTOR_COMPLETE_CONNECT: 
		return "IOCTL_ND_CONNECTOR_COMPLETE_CONNECT\n";

	case IOCTL_ND_CONNECTOR_ACCEPT: //KYS: ALERT: ASYNCH Operation 
		return "IOCTL_ND_CONNECTOR_ACCEPT\n";

	case IOCTL_ND_CONNECTOR_REJECT: 
		return "IOCTL_ND_CONNECTOR_REJECT\n";

	case IOCTL_ND_CONNECTOR_GET_READ_LIMITS: 
		return "IOCTL_ND_CONNECTOR_GET_READ_LIMITS\n";

	case IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA: 
		return "IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA\n";

	case IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS: 
		return "IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS\n";

	case IOCTL_ND_CONNECTOR_GET_ADDRESS: 
		return "IOCTL_ND_CONNECTOR_GET_ADDRESS\n";

	case IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT: //KYS: ALERT: ASYNCH Operation 
		return "IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT\n";

	case IOCTL_ND_CONNECTOR_DISCONNECT: //KYS: ALERT: ASYNCH Operation 
		return "IOCTL_ND_CONNECTOR_DISCONNECT\n";



	case IOCTL_ND_QP_CREATE: 
		return "IOCTL_ND_QP_CREATE\n";

	case IOCTL_ND_MR_CREATE: 
		return "IOCTL_ND_MR_CREATE\n";

	case IOCTL_ND_MR_FREE: 
		return "IOCTL_ND_MR_FREE\n";
	case IOCTL_ND_MR_REGISTER: 
		return "IOCTL_ND_MR_REGISTER\n";
	case IOCTL_ND_MR_DEREGISTER: 
		return "IOCTL_ND_MR_DEREGISTER\n";
	case IOCTL_ND_MR_CANCEL_IO: 
		return "IOCTL_ND_MR_CANCEL_IO\n";
	case IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST: 
		return "IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST\n";
	case IOCTL_ND_QP_FLUSH:
		return "IOCTL_ND_QP_FLUSH\n";

	default:
		return "Unknown IOCTL\n";
	}
}
int get_irp_handle(struct hvnd_dev *nd_dev, u32 *local, void *irp_ctx)
{
	unsigned int local_handle;
	int ret;

	local_handle = atomic_inc_return(&irp_local_hdl);
	*local = local_handle;

	/*
	 * Now asssociate the local handle with the pointer.
	 */
	ret = insert_handle(nd_dev, &nd_dev->irpidr, irp_ctx, local_handle);
	hvnd_debug("irp_ctx=%p local_handle=%u\n", irp_ctx, local_handle);

	if (ret) {
		hvnd_error("insert_handle failed ret=%d\n", ret);
		return ret;
	}

	return 0;
}

void put_irp_handle(struct hvnd_dev *nd_dev, u32 irp)
{
	remove_handle(nd_dev, &nd_dev->irpidr, irp);

}
	 
static void init_pfn(u64 *pfn, void *addr, u32 length)
{
	int i;
	u32 offset = offset_in_page(addr);
	u32 num_pfn = DIV_ROUND_UP(offset + length, PAGE_SIZE);

	for (i = 0; i < num_pfn; i++) {
		pfn[i] = virt_to_phys((u8*)addr + (PAGE_SIZE * i)) >> PAGE_SHIFT;
	}

}


static void user_va_init_pfn(u64 *pfn, struct ib_umem *umem)
{
	int entry;
	struct scatterlist *sg;
	int i =0;

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,6) || RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(7,0))
	struct ib_umem_chunk *chunk;
	int len, j;
	int shift = ffs(umem->page_size) - 1;

	list_for_each_entry(chunk, &umem->chunk_list, list) {
		for (j = 0; j < chunk->nmap; ++j) {
			len = sg_dma_len(&chunk->page_list[j]) >> shift;
			for_each_sg(&chunk->page_list[j], sg, len, entry) {
				pfn[i++] = page_to_pfn(sg_page(sg));
			}
		}
	}
#else
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		pfn[i++] = page_to_pfn(sg_page(sg));
	}
#endif
}

static u32 get_local_handle(void *p)
{
	u64 val = (unsigned long)p;

	return (u32)val;
}

static int hvnd_send_pg_buffer(struct hvnd_dev *nd_dev,
				struct vmbus_packet_mpb_array *desc,
				u32 desc_size,
				void *buffer,
				u32 bufferlen, u64 cookie)
{
	int ret;
	int t;
	struct hvnd_cookie hvnd_cookie;

	hvnd_cookie.pkt = (void *)cookie;
	init_completion(&hvnd_cookie.host_event);

	ret = vmbus_sendpacket_mpb_desc(nd_dev->hvdev->channel,
					desc,
					desc_size,
					buffer, bufferlen,
			       		(u64)(&hvnd_cookie));

	if (ret) {
		hvnd_error("vmbus_sendpacket_mpb_desc failed ret=%d\n", ret);
		goto err;
	}
		
	t = wait_for_completion_timeout(&hvnd_cookie.host_event, 500*HZ);

	if (t == 0) {
		hvnd_error("wait_for_completion_timeout timed out\n");
		ret = -ETIMEDOUT;
	}

err:
	return ret;
}

static int hvnd_send_packet(struct hvnd_dev *nd_dev, void *buffer,
			    u32 bufferlen, u64 cookie, bool block)
{
	int ret;
	int t;
	struct hvnd_cookie hvnd_cookie;

	hvnd_cookie.pkt = (void *)cookie;
	init_completion(&hvnd_cookie.host_event);

	ret = vmbus_sendpacket(nd_dev->hvdev->channel, buffer, bufferlen,
			       (u64)(&hvnd_cookie), VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret) {
		hvnd_error("vmbus_send pkt failed: %d\n", ret);
		goto err;
	}

	if (!block)
		return ret;
		
	t = wait_for_completion_timeout(&hvnd_cookie.host_event, 500*HZ);

	if (t == 0) {
		hvnd_error("wait_for_completion_timeout timed out\n");
		ret = -ETIMEDOUT;
	}

err:
	return ret;
}

static int  hvnd_send_pgbuf_ioctl_pkt(struct hvnd_dev *nd_dev,
				struct vmbus_packet_mpb_array *desc,
				u32 desc_size,
				struct ndv_packet_hdr_control_1 *hdr,
				u32 pkt_size, u64 cookie)
{
	int ret;
	int ioctl;

	ioctl = hdr->io_cntrl_code;


	ret = hvnd_send_pg_buffer(nd_dev, desc, desc_size,
				hdr, pkt_size, cookie);

	if (ret)
		return ret;

	if (hdr->pkt_hdr.status != 0) {
		hvnd_error("IOCTL: %s failed; status is %x\n",
			hvnd_get_op_name(ioctl),
			hdr->pkt_hdr.status);
		return -EINVAL;
	}

	switch (hdr->io_status) {
	case STATUS_SUCCESS:
	case STATUS_PENDING:
		return 0;

	default:
		hvnd_error("IOCTL: %s failed io status is %x\n", hvnd_get_op_name(ioctl),
			hdr->io_status);
		return  -EINVAL;
	}
}

int  hvnd_send_ioctl_pkt(struct hvnd_dev *nd_dev,
				struct ndv_packet_hdr_control_1 *hdr,
				u32 pkt_size, u64 cookie)
{
	int ret;
	int ioctl;
	bool block;

	block = (hdr->irp_handle.val64 == 0) ? true : false;


	ioctl = hdr->io_cntrl_code;

	ret = hvnd_send_packet(nd_dev, hdr, pkt_size, cookie, block);

	if (ret)
		return ret;

	if (!block)
		return ret;

	if (hdr->pkt_hdr.status != 0) {
		hvnd_error("IOCTL: %s failed; status is %x\n", hvnd_get_op_name(ioctl),
			hdr->pkt_hdr.status);
		return -EINVAL;
	}

	switch (hdr->io_status) {
	case STATUS_SUCCESS:
	case STATUS_PENDING:
		return 0;

	default:
		hvnd_warn("IOCTL: %s failed io status is %x\n", hvnd_get_op_name(ioctl),
			hdr->io_status);
		return -EINVAL;
	}
}

void hvnd_init_hdr(struct ndv_packet_hdr_control_1 *hdr,
			  u32 data_sz, u32 local, u32 remote,
			  u32 ioctl_code,
			  u32 ext_data_sz, u32 ext_data_offset,
			  u64 irp_handle)

{
	int pkt_type;

	pkt_type = NDV_PKT_ID1_CONTROL; 
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);
	hdr->pkt_hdr.packet_type = pkt_type;
	hdr->pkt_hdr.hdr_sz = sizeof(struct ndv_packet_hdr_control_1);
	hdr->pkt_hdr.data_sz = data_sz; 

	hdr->pkt_hdr.status = 0;
 
	hdr->file_handle.local = local;
	hdr->file_handle.remote = remote;
	hdr->irp_handle.val64 = irp_handle;

	hdr->io_cntrl_code = ioctl_code;
	hdr->output_buf_sz = data_sz - ext_data_sz;
	hdr->input_buf_sz = data_sz - ext_data_sz;

	hdr->input_output_buf_offset = 0;

	hdr->extended_data.size = ext_data_sz;
	hdr->extended_data.offset = ext_data_offset; 
}


int hvnd_create_file(struct hvnd_dev *nd_dev, void  *uctx,
		     struct ndv_pkt_hdr_create_1 *create, u32 file_flags)
{
	int ret;
	int pkt_type; 

	
	pkt_type = NDV_PKT_ID1_CREATE; 
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);
	create->pkt_hdr.packet_type = pkt_type;
	create->pkt_hdr.hdr_sz = sizeof(struct ndv_pkt_hdr_create_1);
	create->pkt_hdr.data_sz = 0;

	create->handle.local = get_local_handle(uctx);
	create->access_mask = STANDARD_RIGHTS_ALL;
	create->open_options = OPEN_EXISTING;
	create->file_attributes = FILE_ATTRIBUTE_NORMAL | file_flags;
	create->share_access = FILE_SHARE_ALL;
 
	ret = hvnd_send_packet(nd_dev, create,
			       sizeof(struct ndv_pkt_hdr_create_1),
			       (unsigned long)create, true);
	return ret;
}

int hvnd_cleanup_file(struct hvnd_dev *nd_dev, u32 local, u32 remote)
{
	int ret;
	int pkt_type; 
	struct ndv_pkt_hdr_cleanup_1 cleanup_pkt;

	
	pkt_type = NDV_PKT_ID1_CLEANUP; 
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);

	cleanup_pkt.pkt_hdr.packet_type = pkt_type;
	cleanup_pkt.pkt_hdr.hdr_sz = sizeof(struct ndv_pkt_hdr_create_1);
	cleanup_pkt.pkt_hdr.data_sz = 0;

	cleanup_pkt.handle.local = local;
	cleanup_pkt.handle.remote = remote;
 
	ret = hvnd_send_packet(nd_dev, &cleanup_pkt,
			       sizeof(struct ndv_pkt_hdr_create_1),
			       (unsigned long)&cleanup_pkt, true);
	return ret;
}


static int  hvnd_do_ioctl(struct hvnd_dev *nd_dev, u32 ioctl,
		     struct pkt_nd_provider_ioctl *pkt,
		     union ndv_context_handle *hdr_handle,
		     struct nd_handle  *ioctl_handle,
		     u8 *buf, u32 buf_len, bool c_in, bool c_out, u64 irp_val)
{
	int ret;
	int pkt_type; 

	pkt_type = NDV_PKT_ID1_CONTROL; 
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);

	pkt->hdr.pkt_hdr.packet_type = pkt_type;
	pkt->hdr.pkt_hdr.hdr_sz = sizeof(struct ndv_packet_hdr_control_1);
	pkt->hdr.pkt_hdr.data_sz = (sizeof(struct pkt_nd_provider_ioctl) -
					sizeof(struct ndv_packet_hdr_control_1));

	pkt->hdr.file_handle.local = hdr_handle->local;
	pkt->hdr.file_handle.remote = hdr_handle->remote;
	hvnd_debug("create handle local: %x remote: %x\n", hdr_handle->local, hdr_handle->remote);

	pkt->hdr.irp_handle.val64 = irp_val;

	pkt->hdr.io_cntrl_code = ioctl;
	pkt->hdr.output_buf_sz = sizeof(struct nd_ioctl);
	pkt->hdr.input_buf_sz = sizeof(struct nd_ioctl);
	pkt->hdr.input_output_buf_offset = 0;
	memset(&pkt->ioctl.handle, 0, sizeof(struct nd_handle));
	pkt->ioctl.handle.version = ND_VERSION_1;

	switch (ioctl) {
	case IOCTL_ND_PROVIDER_BIND_FILE:
		pkt->ioctl.handle.handle = ioctl_handle->handle;
		break;
	default:
		break;
	};

	/*
	 * Copy the input buffer, if needed.
	 */

	if (c_in && (buf != NULL))
		memcpy(pkt->ioctl.raw_buffer, buf, buf_len); 
		
	ret = hvnd_send_packet(nd_dev, pkt,
			       sizeof(struct pkt_nd_provider_ioctl),
			       (unsigned long)pkt, true);

	if (ret)
		return ret;

	if (c_out && (buf != NULL))
		memcpy(buf, pkt->ioctl.raw_buffer, buf_len); 

	return ret;
}

static int idr_callback(int id, void *p, void *data)
{
	if (p == data)
		return id;
	return 0;
}

void remove_uctx(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx)
{
	int pid = current_pid();
	unsigned long flags;
	int id;

	if (get_uctx(nd_dev, pid) == uctx)
		remove_handle(nd_dev, &nd_dev->uctxidr, pid);
	else {
		hvnd_warn("uctx %p not found on pid %d, doing a idr search\n", uctx, current_pid());

		spin_lock_irqsave(&nd_dev->id_lock, flags);
		id = idr_for_each(&nd_dev->uctxidr, idr_callback, uctx);
		spin_unlock_irqrestore(&nd_dev->id_lock, flags);

		if (id)
			remove_handle(nd_dev, &nd_dev->uctxidr, id);
		else {
			hvnd_error("uctx %p not found in idr table\n", uctx);
			return;
		}
	}

	kfree(uctx);
}

int hvnd_close_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx)
{
	int ret;

	/*
	 * First close the adaptor.
	 */

	ret = hvnd_free_handle(nd_dev, uctx,
				uctx->adaptor_hdl,
				IOCTL_ND_ADAPTER_CLOSE);

	if (ret)
		hvnd_error("Adaptor close failed; ret is %x\n", ret);

	/*
	 * Now close the two files we created.
	 */

	ret = hvnd_cleanup_file(nd_dev, uctx->file_handle_ovl.local,
				uctx->file_handle_ovl.remote);

	if (ret)
		hvnd_error("file cleanup failed; ret is %x\n", ret);

	ret = hvnd_cleanup_file(nd_dev, uctx->file_handle.local,
				uctx->file_handle.remote);

	if (ret)
		hvnd_error("File cleanup failed; ret is %x\n", ret);

	/*
	 * Remove the uctx from the ID table.
	 */
	remove_uctx(nd_dev, uctx);

	return 0;
}

int hvnd_open_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx)
{
	int ret;
	struct pkt_nd_provider_ioctl *pr_init = &uctx->pr_init_pkt;
	int pkt_type; 
	struct nd_handle ioctl_handle;
	struct pkt_nd_open_adapter *pr_o_adap = &uctx->o_adap_pkt;
 
	ret = hvnd_create_file(nd_dev, uctx, &uctx->create_pkt, 0);
	if (ret) {
		hvnd_error("hvnd_create_file failed ret=%d\n", ret);
		goto error_cr;
	}

	if (uctx->create_pkt.pkt_hdr.status != 0) {
		hvnd_error("create File failed; status is %d\n",
			uctx->create_pkt.pkt_hdr.status);
		ret = -EINVAL;
		goto error_cr;
	}

	uctx->file_handle.local = uctx->create_pkt.handle.local; 
	uctx->file_handle.remote = uctx->create_pkt.handle.remote; 
	hvnd_debug("INITIALIZE PROVIDER\n");
	/*
	 * Now Initialize the Provider.
	 */
	ioctl_handle.handle = 0;
	ret = hvnd_do_ioctl(nd_dev, IOCTL_ND_PROVIDER_INIT, pr_init,
			    &uctx->create_pkt.handle,
		     	    &ioctl_handle, NULL, 0, false, false, 0);

	if (ret) {
		ret = -EINVAL;
		goto error_pr_init;
	}

	if (pr_init->hdr.pkt_hdr.status != 0) {
		hvnd_error("Provider INIT failed; status is %d\n",
			pr_init->hdr.pkt_hdr.status);
		ret = -EINVAL;
		goto error_pr_init;
	}

	if (pr_init->hdr.io_status != 0) {
		hvnd_error("Provider INIT failed; io status is %d\n",
			pr_init->hdr.io_status);
		ret = -EINVAL;
		goto error_pr_init;
	}

	/*
	 * Now create the overlap file.
	 */
 
	hvnd_debug("CREATE OVERLAP FILE\n");
	ret = hvnd_create_file(nd_dev, uctx, &uctx->create_pkt_ovl,
			       FILE_FLAG_OVERLAPPED);
	if (ret) {
		hvnd_error("hvnd_create_file failed ret=%d\n", ret);
		goto error_pr_init;
	}

	if (uctx->create_pkt_ovl.pkt_hdr.status != 0) {
		hvnd_error("create Overlap File failed; status is %d\n",
			uctx->create_pkt_ovl.pkt_hdr.status);
		ret = -EINVAL;
		goto error_pr_init;
	}
	uctx->file_handle_ovl.local = uctx->create_pkt_ovl.handle.local; 
	uctx->file_handle_ovl.remote = uctx->create_pkt_ovl.handle.remote; 

	/*
	 * Now bind the two file handles together.
	 */

	hvnd_debug("BIND FILE IOCTL remote handle: %d local handle: %d\n", 
		uctx->create_pkt_ovl.handle.remote, 
		uctx->create_pkt_ovl.handle.local);

	ioctl_handle.handle = uctx->create_pkt_ovl.handle.val64; 
	ret = hvnd_do_ioctl(nd_dev, IOCTL_ND_PROVIDER_BIND_FILE, pr_init,
			    &uctx->create_pkt.handle,
		     	    &ioctl_handle, NULL, 0, false, false, 0);

	if (ret) {
		ret = -EINVAL;
		goto error_file_bind;
	}
	if (pr_init->hdr.pkt_hdr.status != 0) {
		hvnd_error("Provider File bind failed; status is %d\n",
			pr_init->hdr.pkt_hdr.status);
		ret = -EINVAL;
		goto error_file_bind;
	}
	if (pr_init->hdr.io_status != 0) {
		hvnd_error("Provider INIT failed; io status is %d\n",
			pr_init->hdr.io_status);
		ret = -EINVAL;
		goto error_file_bind;
	}

	/*
	 * Now open the adaptor.
	 */

	hvnd_debug("OPENING THE ADAPTOR\n");

	pkt_type = NDV_PKT_ID1_CONTROL; 
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);
	pr_o_adap->hdr.pkt_hdr.packet_type = pkt_type;
	pr_o_adap->hdr.pkt_hdr.hdr_sz = sizeof(struct ndv_packet_hdr_control_1);
	pr_o_adap->hdr.pkt_hdr.data_sz = (sizeof(struct pkt_nd_open_adapter) -
					sizeof(struct ndv_packet_hdr_control_1));

	pr_o_adap->hdr.pkt_hdr.status = 0;

	hvnd_debug("hdr sz is %d\n", pr_o_adap->hdr.pkt_hdr.hdr_sz);
	hvnd_debug("data sz is %d\n", pr_o_adap->hdr.pkt_hdr.data_sz);

	pr_o_adap->hdr.file_handle.local = uctx->create_pkt.handle.local;
	pr_o_adap->hdr.file_handle.remote = uctx->create_pkt.handle.remote;
	hvnd_debug("create handle local is %x\n", uctx->create_pkt.handle.local);
	hvnd_debug("create handle remote is %x\n", uctx->create_pkt.handle.remote);
	pr_o_adap->hdr.irp_handle.val64 = 0;

	pr_o_adap->hdr.io_cntrl_code = IOCTL_ND_ADAPTER_OPEN;
	pr_o_adap->hdr.output_buf_sz = pr_o_adap->hdr.pkt_hdr.data_sz - sizeof(struct extended_data_oad);
	pr_o_adap->hdr.input_buf_sz = pr_o_adap->hdr.pkt_hdr.data_sz -sizeof(struct extended_data_oad);

	hvnd_debug("output buf sz is %d\n", pr_o_adap->hdr.output_buf_sz);
	hvnd_debug("input buf sz is %d\n", pr_o_adap->hdr.input_buf_sz);
	hvnd_debug("packet size is %d\n", (int)sizeof(struct pkt_nd_open_adapter));

	pr_o_adap->hdr.input_output_buf_offset = 0;


	pr_o_adap->hdr.extended_data.size = sizeof(struct extended_data_oad);
	pr_o_adap->hdr.extended_data.offset = offsetof(struct pkt_nd_open_adapter, ext_data) -
						sizeof(struct ndv_packet_hdr_control_1);

	hvnd_debug("size of the extended data size: %d\n", (int)sizeof(struct extended_data_oad));
	hvnd_debug("offset of extended data: %d\n", pr_o_adap->hdr.extended_data.offset);

	/*
	 * Now fill out the ioctl section.
	 */

	pr_o_adap->ioctl.input.version = ND_VERSION_1; 
	pr_o_adap->ioctl.input.ce_mapping_cnt =
		RTL_NUMBER_OF(pr_o_adap->mappings.ctx_input.mappings); 

	hvnd_debug("ce_mapping cnt is %d\n", pr_o_adap->ioctl.input.ce_mapping_cnt);

	pr_o_adap->ioctl.input.cb_mapping_offset = sizeof(union oad_ioctl);
	hvnd_debug("cb_mapping offset is %d\n", pr_o_adap->ioctl.input.cb_mapping_offset);
	pr_o_adap->ioctl.input.adapter_id = (u64)nd_dev;

	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_UAR].map_type = ND_MAP_IOSPACE;
	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_UAR].map_io_space.cache_type = ND_NON_CACHED;
	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_UAR].map_io_space.cb_length = 4096;

	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_BF].map_type  = ND_MAP_IOSPACE;
	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_BF].map_io_space.cache_type = ND_WRITE_COMBINED;
	pr_o_adap->mappings.ctx_input.mappings[IBV_GET_CONTEXT_BF].map_io_space.cb_length = 4096;

	/*
	 * Fill in the extended data.
	 */
	pr_o_adap->ext_data.cnt = IBV_GET_CONTEXT_MAPPING_MAX;

	ret = hvnd_send_packet(nd_dev, pr_o_adap,
			       sizeof(struct pkt_nd_open_adapter),
			       (unsigned long)pr_o_adap, true);
	if (ret) {
		ret = -EINVAL;
		goto error_file_bind;
	}

	if (pr_o_adap->hdr.pkt_hdr.status != 0) {
		hvnd_error("Open adaptor failed; status is %d\n",
			pr_o_adap->hdr.pkt_hdr.status);
		ret = -EINVAL;
		goto error_file_bind;
	}

	if (pr_o_adap->hdr.io_status != 0) {
		hvnd_error("Open adaptor failed;io status is %d\n",
			pr_o_adap->hdr.io_status);
		ret = -EINVAL;
		goto error_file_bind;
	}

	/*
	 * Copy the necessary response from the host.
	 */

	uctx->adaptor_hdl = pr_o_adap->ioctl.resrc_desc.handle;
	

	hvnd_debug("adaptor handle: %p\n", (void *)uctx->adaptor_hdl);

	uctx->uar_base =
	pr_o_adap->mappings.ctx_output.mapping_results[IBV_GET_CONTEXT_UAR].info;
	hvnd_debug("uar base: %p\n", (void *)uctx->uar_base);

	uctx->bf_base =
	pr_o_adap->mappings.ctx_output.mapping_results[IBV_GET_CONTEXT_BF].info;
	hvnd_debug("bf base: %p\n", (void *)uctx->bf_base);

	uctx->bf_buf_size =
	pr_o_adap->mappings.ctx_output.bf_buf_size;
	hvnd_debug("bf buf size: %d\n", uctx->bf_buf_size);

	uctx->bf_offset =
	pr_o_adap->mappings.ctx_output.bf_offset;
	hvnd_debug("bf offset: %d\n", uctx->bf_offset);

	uctx->cqe_size =
	pr_o_adap->mappings.ctx_output.cqe_size;
	hvnd_debug("cqe size: %d\n", uctx->cqe_size);

	uctx->max_qp_wr =
	pr_o_adap->mappings.ctx_output.max_qp_wr;
	hvnd_debug("max qp wr: %d\n", uctx->max_qp_wr);

	uctx->max_sge =
	pr_o_adap->mappings.ctx_output.max_sge;
	hvnd_debug("max sge: %d\n", uctx->max_sge);

	uctx->max_cqe =
	pr_o_adap->mappings.ctx_output.max_cqe;
	hvnd_debug("max cqe: %d\n", uctx->max_cqe);

	uctx->num_qps =
	pr_o_adap->mappings.ctx_output.qp_tab_size;
	hvnd_debug("num qps: %d\n", uctx->num_qps);

	/*
	 * Now query the adaptor and stash away the adaptor info.
	 */

	ret = hvnd_query_adaptor(nd_dev, uctx);
	if (ret) {
		hvnd_error("Query Adaptor failed; ret is %d\n", ret);
		goto query_err;
	}

	return ret;

query_err:
	hvnd_free_handle(nd_dev, uctx,
			uctx->adaptor_hdl,
			IOCTL_ND_ADAPTER_CLOSE);

	hvnd_error("Open Adaptor Failed!!\n");

error_file_bind:
	hvnd_cleanup_file(nd_dev, uctx->file_handle_ovl.local,
			uctx->file_handle_ovl.remote);

error_pr_init:
	hvnd_cleanup_file(nd_dev, uctx->file_handle.local,
			uctx->file_handle.remote);

error_cr:
	if (get_uctx(nd_dev, current_pid()) != NULL)
		remove_handle(nd_dev, &nd_dev->uctxidr, current_pid());

	return ret;
}

int hvnd_create_cq(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		   struct hvnd_cq *cq)
{
	int ret;
	struct pkt_nd_create_cq *pkt;
	int num_pfn, num_db_pfn, num_sn_pfn;
	int cq_pkt_size;
	unsigned int cq_buf_size, offset;
	u32 ext_data_sz;
	u32 ext_data_offset;

	/*
	 * Now create CQ.
	 * First compute the number of PFNs we need to accomodate:
	 * One each for door bell and arm_sn and pages in cq buffer.
	 */
	cq_buf_size = (cq->entries * uctx->cqe_size);
	offset = offset_in_page(cq->cq_buf);
	num_pfn = DIV_ROUND_UP(offset + cq_buf_size, PAGE_SIZE);

	offset = offset_in_page(cq->db_addr);
	num_db_pfn = DIV_ROUND_UP(offset + 8, PAGE_SIZE);

	offset = offset_in_page(&cq->arm_sn);
	num_sn_pfn = DIV_ROUND_UP(offset + 4, PAGE_SIZE);

	cq_pkt_size = sizeof(struct pkt_nd_create_cq) +
		(num_pfn  * sizeof(u64));

	ext_data_sz = sizeof(struct create_cq_ext_data) + (num_pfn * sizeof(u64));
	ext_data_offset = offsetof(struct pkt_nd_create_cq, ext_data) -
						sizeof(struct ndv_packet_hdr_control_1);

	hvnd_debug("CREATE CQ, num user addr pfns is %d\n", num_pfn);
	hvnd_debug("CREATE CQ, num db pfns is %d\n", num_db_pfn);

	pkt = kzalloc(cq_pkt_size, GFP_KERNEL);

	if (!pkt)
		return -ENOMEM;

	hvnd_init_hdr(&pkt->hdr,
			(cq_pkt_size -
			sizeof(struct ndv_packet_hdr_control_1)),
			uctx->create_pkt.handle.local,
			uctx->create_pkt.handle.remote,
			IOCTL_ND_CQ_CREATE,
			ext_data_sz,
			ext_data_offset,
			0);

	/*
	 * Now fill out the ioctl section.
	 */

	pkt->ioctl.input.version = ND_VERSION_1; 
	pkt->ioctl.input.queue_depth = cq->entries;
	pkt->ioctl.input.ce_mapping_cnt = MLX4_IB_CREATE_CQ_MAPPING_MAX;
	pkt->ioctl.input.cb_mapping_offset = sizeof(union create_cq_ioctl);

	hvnd_debug("ce_mapping cnt is %d\n",  pkt->ioctl.input.ce_mapping_cnt);
	hvnd_debug("cb_mapping offset is %d\n", pkt->ioctl.input.cb_mapping_offset);

	pkt->ioctl.input.adapter_handle = uctx->adaptor_hdl;
	pkt->ioctl.input.affinity.mask = 0;
	pkt->ioctl.input.affinity.group = -1;

	// 0 for usermode CQ arming
	pkt->mappings.cq_in.flags = 0;

	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_BUF].map_memory.map_type = ND_MAP_MEMORY;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_BUF].map_memory.access_type = ND_MODIFY_ACCESS;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_BUF].map_memory.address = (u64)cq->cq_buf;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_BUF].map_memory.cb_length = (cq->entries * uctx->cqe_size);

	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_DB].map_memory.map_type = ND_MAP_MEMORY_COALLESCE;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_DB].map_memory.access_type = ND_WRITE_ACCESS;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_DB].map_memory.address = (u64)cq->db_addr;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_DB].map_memory.cb_length = 8; //size of two ints


	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_ARM_SN].map_memory.map_type = ND_MAP_MEMORY;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_ARM_SN].map_memory.access_type = ND_MODIFY_ACCESS;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_ARM_SN].map_memory.address = (u64)&cq->arm_sn;
	pkt->mappings.cq_in.mappings[MLX4_IB_CREATE_CQ_ARM_SN].map_memory.cb_length = 4; //size of one int 
	/*
	 * Fill in the extended data.
	 */

	pkt->ext_data.cnt = 3;
	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_BUF].size = (sizeof(struct gpa_range) + (num_pfn * sizeof(u64)));
	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_BUF].offset = offsetof(struct create_cq_ext_data, cqbuf_gpa); 

	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_DB].size = sizeof(struct cq_db_gpa);
	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_DB].offset = offsetof(struct create_cq_ext_data, db_gpa); 

	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_ARM_SN].size = sizeof(struct cq_db_gpa);
	pkt->ext_data.fields[MLX4_IB_CREATE_CQ_ARM_SN].offset = offsetof(struct create_cq_ext_data, sn_gpa);

	/*
	 * Fill up the gpa range for cq buffer.
	 */ 

	pkt->ext_data.db_gpa.byte_count = 8;
	pkt->ext_data.db_gpa.byte_offset = offset_in_page(cq->db_addr);
	user_va_init_pfn(&pkt->ext_data.db_gpa.pfn_array[0], cq->db_umem);

	pkt->ext_data.sn_gpa.byte_count = 4;
	pkt->ext_data.sn_gpa.byte_offset = offset_in_page(&cq->arm_sn);
	init_pfn(&pkt->ext_data.sn_gpa.pfn_array[0],
		 &cq->arm_sn,
		 4);

	pkt->ext_data.cqbuf_gpa.byte_count = (cq->entries * uctx->cqe_size);
	pkt->ext_data.cqbuf_gpa.byte_offset = offset_in_page(cq->cq_buf);
	user_va_init_pfn(&pkt->ext_data.cqbuf_gpa.pfn_array[0], cq->umem);

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt->hdr, cq_pkt_size, (u64)pkt);

	if (ret)
		goto cr_cq_err;

	/*
	 * Copy the necessary response from the host.
	 */
	cq->cqn = pkt->mappings.cq_resp.cqn;
	cq->cqe = pkt->mappings.cq_resp.cqe;
	cq->cq_handle = pkt->ioctl.resrc_desc.handle;

	ret = insert_handle(nd_dev, &nd_dev->cqidr, cq, cq->cqn);

	if (ret)
		goto cr_cq_err;
	hvnd_debug("CQ create after success cqn is %d\n", cq->cqn);
	hvnd_debug("CQ create after success cqe is %d\n", cq->cqe);
	hvnd_debug("CQ create after success cq handle is %p\n", (void *)cq->cq_handle);

cr_cq_err:
	kfree(pkt);
	return ret;
}

int hvnd_destroy_cq(struct hvnd_dev *nd_dev, struct hvnd_cq *cq)
{
	struct pkt_nd_free_cq free_cq_pkt;
 
	remove_handle(nd_dev, &nd_dev->cqidr, cq->cqn);

	memset(&free_cq_pkt, 0, sizeof(free_cq_pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&free_cq_pkt.hdr,
		      sizeof(struct pkt_nd_free_cq) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      cq->uctx->create_pkt.handle.local,
		      cq->uctx->create_pkt.handle.remote,
		      IOCTL_ND_CQ_FREE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	free_cq_pkt.ioctl.in.version = ND_VERSION_1;
	free_cq_pkt.ioctl.in.handle = cq->cq_handle; 
 
	return hvnd_send_ioctl_pkt(nd_dev, &free_cq_pkt.hdr, 
			       sizeof(struct pkt_nd_free_cq),
			       (u64)&free_cq_pkt);
}


int hvnd_notify_cq(struct hvnd_dev *nd_dev, struct hvnd_cq *cq,
		   u32 notify_type, u64 irp_handle)
{
	struct pkt_nd_notify_cq notify_cq_pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	irp_fhandle.local = cq->ep_object.local_irp;


	memset(&notify_cq_pkt, 0, sizeof(notify_cq_pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&notify_cq_pkt.hdr,
		      sizeof(struct pkt_nd_notify_cq) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      cq->uctx->create_pkt.handle.local,
		      cq->uctx->create_pkt.handle.remote,
		      IOCTL_ND_CQ_NOTIFY, 0, 0, irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	notify_cq_pkt.ioctl.in.version = ND_VERSION_1;
	notify_cq_pkt.ioctl.in.cq_handle = cq->cq_handle; 
	notify_cq_pkt.ioctl.in.type = notify_type; 
 

	ret = hvnd_send_ioctl_pkt(nd_dev, &notify_cq_pkt.hdr, 
			       sizeof(struct pkt_nd_notify_cq),
			       (u64)&notify_cq_pkt);

	return ret;
}

/*
 * Memory region operations.
 */
int hvnd_cr_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		u64 pd_handle, u64 *mr_handle)
{
	struct pkt_nd_create_mr pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_MR_CREATE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.handle = pd_handle;
	hvnd_debug("PD handle is %p\n", (void *)pd_handle);
	pkt.ioctl.in.reserved = 0;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	/*
	 * Copy the  handle.
	 */
	hvnd_debug("mr handle is %p\n", (void *)pkt.ioctl.out);
	*mr_handle = pkt.ioctl.out;

	return 0;

err:
	hvnd_error("create mr failed: %d\n", ret);
	return ret;

}

int hvnd_free_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		 u64 handle)
{
	return hvnd_free_handle(nd_dev, uctx, handle, IOCTL_ND_MR_FREE);
}

int hvnd_deregister_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle)
{
	struct pkt_nd_deregister_mr pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_MR_DEREGISTER, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.handle = handle;
	pkt.ioctl.in.reserved = 0;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret) 
		goto err;

	return 0;

err:
	hvnd_error("de-register mr failed: %d\n", ret);
	return ret;

}

static inline u32 hvnd_convert_access(int acc)
{
	return (acc & IB_ACCESS_REMOTE_WRITE ? ND_MR_FLAG_ALLOW_REMOTE_WRITE : 0) |
	    (acc & IB_ACCESS_REMOTE_READ ? ND_MR_FLAG_ALLOW_REMOTE_READ : 0) |
	    (acc & IB_ACCESS_LOCAL_WRITE ? ND_MR_FLAG_ALLOW_LOCAL_WRITE : 0);
}


int hvnd_mr_register(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		     struct hvnd_mr *mr)
{
	struct pkt_nd_register_mr pkt;
	int ret;
	struct hv_mpb_array *pb;
	struct vmbus_packet_mpb_array *tpb;
	int sz_leaf;
	int num_pgs;
	int i =0;
	int ext_data_sz;
	u32 acc_flags;
	u32 desc_size;
	int pkt_type;

	/*
	 * The user address is passed in via a two level structure.
	 * An Array of struct hv_page_buffer will be used to describe
	 * the user memory. The pages containing this array will be descibed
	 * in another array of struct hv_page_buffer. We pass this seconed level
	 * array to the host.
	 */

	hvnd_debug("ib_umem_page_count(mr->umem)=%d\n", ib_umem_page_count(mr->umem));

	sz_leaf = ib_umem_page_count(mr->umem) * sizeof(u64) + sizeof(struct hv_mpb_array);

	pb = (struct hv_mpb_array*) __get_free_pages(GFP_KERNEL|__GFP_ZERO, get_order(sz_leaf));

	if (pb == NULL)
		return -ENOMEM;
	/*
	 * Allocate an array of hv_page_buffer to describe the first level.
	 */
	num_pgs = DIV_ROUND_UP(sz_leaf, PAGE_SIZE);
	hvnd_debug("num pages in the top array is %d\n", num_pgs);

	desc_size = (num_pgs * sizeof(u64) +
			sizeof(struct vmbus_packet_mpb_array));
	tpb = (struct vmbus_packet_mpb_array*) __get_free_pages(GFP_KERNEL|__GFP_ZERO, get_order(desc_size));

	if (tpb == NULL) {
		free_pages((unsigned long)pb, get_order(sz_leaf));
		return -ENOMEM;
	}

	hvnd_debug("sz leaf: %d; pgs in top %d\n", sz_leaf, num_pgs);

	/*
	 * Now fill the leaf level array.
	 */
	pb->len = mr->length;
	pb->offset = offset_in_page(mr->start);
	user_va_init_pfn(pb->pfn_array, mr->umem);

	/*
	 * Now fill out the top level array.
	 */
	for (i = 0; i < num_pgs; i++) {
		tpb->range.pfn_array[i] = virt_to_phys((u8*)pb + (PAGE_SIZE * i)) >> PAGE_SHIFT;
		hvnd_debug("virtual address = %p\n", (u8*)pb + (PAGE_SIZE * i));
		hvnd_debug("physical address = %llx\n", virt_to_phys((u8*)pb + (PAGE_SIZE * i)));
		hvnd_debug("tpb->range.pfn_array[%d]=%llx\n", i, tpb->range.pfn_array[i]);
	}

	tpb->range.offset = 8;
	tpb->range.len = ib_umem_page_count(mr->umem) * sizeof(u64);
	

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	ext_data_sz = (ib_umem_page_count(mr->umem) * sizeof(u64));
	acc_flags = ND_MR_FLAG_DO_NOT_SECURE_VM | hvnd_convert_access(mr->acc);
	hvnd_debug("memory register access flags are: %x\n", acc_flags);

	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_MR_REGISTER, 0, 0, 0);

	/*
	 * The memory registration call uses a different mechanism to pass
	 * pfn information.
	 */

	pkt_type = pkt.hdr.pkt_hdr.packet_type;
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTION_EXTERNAL_DATA);
	pkt.hdr.pkt_hdr.packet_type = pkt_type;

	pkt.hdr.extended_data.size = ext_data_sz;
	pkt.hdr.extended_data.offset = 0; 
	/*
	 * Now fill out the ioctl.
	 */

	pkt.ioctl.in.header.version = ND_VERSION_1;
	pkt.ioctl.in.header.flags = acc_flags;
	pkt.ioctl.in.header.cb_length = mr->length;
	pkt.ioctl.in.header.target_addr = mr->virt;
	pkt.ioctl.in.header.mr_handle = mr->mr_handle;
	pkt.ioctl.in.address = mr->virt;

	/*
	 * Now send the packet to the host.
	 */

	ret = hvnd_send_pgbuf_ioctl_pkt(nd_dev,
					tpb, desc_size,
					&pkt.hdr, 
					sizeof(pkt),
					(unsigned long)&pkt);

	if (ret)
		goto err;

	hvnd_info("MR REGISTRATION SUCCESS\n");
	/*
	 * Copy the mr registration data.
	 */
	hvnd_debug("mr registration lkey %x\n", pkt.ioctl.out.lkey);
	hvnd_debug("mr registration rkey %x\n", pkt.ioctl.out.rkey);

	mr->mr_lkey = pkt.ioctl.out.lkey;
	mr->mr_rkey = pkt.ioctl.out.rkey;

	mr->ibmr.lkey = mr->mr_lkey; 
	mr->ibmr.rkey = be32_to_cpu(mr->mr_rkey); 
	hvnd_debug("ibmr registration lkey %x\n", mr->ibmr.lkey);
	hvnd_debug("ibmr registration rkey  %x\n", mr->ibmr.rkey);

	free_pages((unsigned long)pb, get_order(sz_leaf));
	free_pages((unsigned long)tpb, get_order(desc_size));

	return 0;

err:
	free_pages((unsigned long)pb, get_order(sz_leaf));
	free_pages((unsigned long)tpb, get_order(desc_size));

	hvnd_error("mr register failed: %d\n", ret);
	return ret;
}

/*
 * Listener operations.
 */
int hvnd_cr_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		     u64 *listener_handle)
{
	struct pkt_nd_cr_listener pkt;
	int ret;

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_CREATE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.handle = uctx->adaptor_hdl;
	hvnd_debug("Adaptor handle is %p\n", (void *)uctx->adaptor_hdl);
	pkt.ioctl.in.hdr.reserved = 0;
	pkt.ioctl.in.to_semantics = false;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	/*
	 * Copy the listener handle.
	 */
	hvnd_debug("listener handle is %p\n", (void *)pkt.ioctl.out);
	*listener_handle = pkt.ioctl.out;

	return 0;

err:
	hvnd_error("create listener failed: ret=%d uctx=%p adaptor handle=%llu\n", ret, uctx, uctx->adaptor_hdl);
	return ret;

}

int hvnd_free_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle)
{
	struct pkt_nd_free_listener pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_FREE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.handle = listener_handle;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	hvnd_error("free listener failed: %d\n", ret);
	return ret;
}

int hvnd_bind_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, union nd_sockaddr_inet *addr)
{
	struct pkt_nd_bind_listener pkt;
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
	uid_t uid = current_uid();
#else
	kuid_t uid = current_uid();
#endif
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_BIND, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.handle = listener_handle;
	pkt.ioctl.in.hdr.reserved = 0;
 
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
	pkt.ioctl.in.authentication_id = (u32)uid;
#else
	pkt.ioctl.in.authentication_id = (u32)uid.val;
#endif
	pkt.ioctl.in.is_admin = false;

	memcpy(&pkt.ioctl.in.hdr.address, addr, sizeof(*addr));
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	hvnd_error("bind listener failed: %d\n", ret);
	return ret;
}

int hvnd_listen_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, u32 backlog)
{
	struct pkt_nd_listen_listener pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_LISTEN, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.listener_handle = listener_handle;
	pkt.ioctl.in.back_log = backlog;

 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	hvnd_error("listen listener failed: %d\n", ret);
	return ret;
}

int hvnd_get_addr_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, union nd_sockaddr_inet *addr)
{
	struct pkt_nd_get_addr_listener pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_GET_ADDRESS, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.handle = listener_handle;


	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	/*
	 * Copy the adddress.
	 */

	memcpy(addr, &pkt.ioctl.out, sizeof(union nd_sockaddr_inet));

	return 0;

err:
	hvnd_error("listen listener failed: %d\n", ret);
	return ret;
}

int hvnd_get_connection_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, u64 connector_handle,
			u64 irp_handle)
{
	struct pkt_nd_get_connection_listener pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	ret = get_irp_handle(nd_dev, &irp_fhandle.local, (void *)irp_handle);

	if (ret) {
		hvnd_error("get_irp_handle() failed: err: %d\n", ret);
		return ret;
	}
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST, 0, 0,
		      irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.listener_handle = listener_handle;
	pkt.ioctl.in.connector_handle = connector_handle;

 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	hvnd_error("get connection listener failed: %d\n", ret);
	return ret;
}

/*
 * Connector APIs.
 */

int hvnd_cr_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		     u64 *connector_handle)
{
	struct pkt_nd_cr_connector pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(struct pkt_nd_cr_listener) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_CREATE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.handle = uctx->adaptor_hdl;
	pkt.ioctl.in.to_semantics = false;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	/*
	 * Copy the listener handle.
	 */
	hvnd_debug("connector handle is %p\n", (void *)pkt.ioctl.out);
	*connector_handle = pkt.ioctl.out;

	return 0;

err:
	return ret;
}

int hvnd_free_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle)
{
	struct pkt_nd_free_connector pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_FREE, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.handle = handle;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}

int hvnd_bind_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle, union nd_sockaddr_inet *addr)
{
	struct pkt_nd_bind_connector pkt;
	int ret;
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
	uid_t uid = current_uid();
#else
	kuid_t uid = current_uid();
#endif
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_BIND, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.handle = handle;

	memcpy(&pkt.ioctl.in.hdr.address, addr, sizeof(*addr));

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
	pkt.ioctl.in.authentication_id = (u32)uid;
#else
	pkt.ioctl.in.authentication_id = (u32)uid.val;
#endif
	pkt.ioctl.in.is_admin = false;
	
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}

int hvnd_connector_connect(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle, u32 in_rd_limit, u32 out_rd_limit,
			u32 priv_data_length, const u8 *priv_data,
			u64 qp_handle, struct if_physical_addr *phys_addr,
			union nd_sockaddr_inet *dest_addr, struct hvnd_ep_obj *ep)
{
	struct pkt_nd_connector_connect *pkt = &ep->connector_connect_pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	hvnd_debug("local irp is %d\n", ep->local_irp);
	irp_fhandle.local = ep->local_irp;
 
	if (priv_data_length > MAX_PRIVATE_DATA_LEN) {
		hvnd_error("priv_data_length=%d\n", priv_data_length);
		return -EINVAL;
	}

	memset(pkt, 0, sizeof(*pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt->hdr,
		      sizeof(*pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_CONNECT, 0, 0, irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt->ioctl.in.hdr.version = ND_VERSION_1;
	pkt->ioctl.in.hdr.connector_handle = connector_handle;
	pkt->ioctl.in.hdr.read_limits.inbound = in_rd_limit;
	pkt->ioctl.in.hdr.read_limits.outbound = out_rd_limit;
	pkt->ioctl.in.hdr.cb_private_data_length = priv_data_length;
	pkt->ioctl.in.hdr.cb_private_data_offset = offsetof(union connector_connect_ioctl, in.priv_data);
	pkt->ioctl.in.hdr.qp_handle = qp_handle;

	memcpy(&pkt->ioctl.in.hdr.phys_addr, phys_addr,
		sizeof(struct if_physical_addr)); 

	/*
	 * Luke's code does not copy the ip address.
	 */
	memcpy(&pkt->ioctl.in.hdr.destination_address, dest_addr,
		sizeof(union nd_sockaddr_inet)); 

	pkt->ioctl.in.retry_cnt = 7;
	pkt->ioctl.in.rnr_retry_cnt = 7;
	memcpy(pkt->ioctl.in.priv_data, priv_data, priv_data_length);
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt->hdr, sizeof(*pkt), (u64)pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}

int hvnd_connector_complete_connect(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,  enum ibv_qp_state *qp_state)
{
	struct pkt_nd_connector_connect_complete pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_COMPLETE_CONNECT, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.handle = connector_handle;
	pkt.ioctl.in.rnr_nak_to = 0;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	*qp_state = pkt.ioctl.out.state; 
	return 0;

err:
	return ret;
}

int hvnd_connector_accept(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u64 qp_handle,
			u32 in_rd_limit, u32 out_rd_limit,
			u32 priv_data_length, const u8 *priv_data,
			enum ibv_qp_state *qp_state, struct hvnd_ep_obj *ep)
{
	struct pkt_nd_connector_accept pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	irp_fhandle.local = ep->local_irp;
 
	if (priv_data_length > MAX_PRIVATE_DATA_LEN) {
		hvnd_error("priv_data_length=%d\n", priv_data_length);
		return -EINVAL;
	}

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_ACCEPT, 0, 0, irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.reserved = 0;
	pkt.ioctl.in.hdr.read_limits.inbound = in_rd_limit;
	pkt.ioctl.in.hdr.read_limits.outbound = out_rd_limit;
	pkt.ioctl.in.hdr.cb_private_data_length = priv_data_length;

	pkt.ioctl.in.hdr.cb_private_data_offset = offsetof(struct connector_accept_in, private_data); 

	pkt.ioctl.in.hdr.connector_handle = connector_handle;
	pkt.ioctl.in.hdr.qp_handle = qp_handle;

	pkt.ioctl.in.rnr_nak_to = 0;
	pkt.ioctl.in.rnr_retry_cnt = 7;
 

	memcpy(pkt.ioctl.in.private_data, priv_data, priv_data_length);  

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	*qp_state = pkt.ioctl.out.state; 
	return 0;

err:
	return ret;
}

int hvnd_connector_reject(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u32 priv_data_length, u8 *priv_data,
			enum ibv_qp_state *qp_state)
{
	struct pkt_nd_connector_reject pkt;
	int ret;
 
	if (priv_data_length > MAX_PRIVATE_DATA_LEN) {
		hvnd_error("priv_data_length=%d\n", priv_data_length);
		return -EINVAL;
	}

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_REJECT, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.hdr.version = ND_VERSION_1;
	pkt.ioctl.in.hdr.reserved = 0;
	pkt.ioctl.in.hdr.cb_private_data_length = priv_data_length;

	pkt.ioctl.in.hdr.cb_private_data_offset = offsetof(struct connector_reject_in, private_data); 

	pkt.ioctl.in.hdr.connector_handle = connector_handle;

	memcpy(pkt.ioctl.in.private_data, priv_data, priv_data_length);  

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	*qp_state = pkt.ioctl.out.state; 
	return 0;

err:
	return ret;
}

int hvnd_connector_get_rd_limits(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			struct nd_read_limits *rd_limits)
{
	struct pkt_nd_connector_get_rd_limits pkt;
	int ret;
 

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_GET_READ_LIMITS, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.in.version = ND_VERSION_1;
	pkt.ioctl.in.in.reserved = 0;
	pkt.ioctl.in.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	*rd_limits = pkt.ioctl.out.out; 
	return 0;

err:
	return ret;
}

int hvnd_connector_get_priv_data(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u8 *priv_data)
{
	struct pkt_nd_connector_get_priv_data pkt;
	int ret;
 

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	memcpy(priv_data, pkt.ioctl.out, MAX_PRIVATE_DATA_LEN);
	return 0;

err:
	return ret;
}

int hvnd_connector_get_peer_addr(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			union nd_sockaddr_inet *peer_addr)
{
	struct pkt_nd_connector_get_peer_addr pkt;
	int ret;
 

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	memcpy(peer_addr, &pkt.ioctl.out, sizeof(union nd_sockaddr_inet));
	return 0;

err:
	return ret;
}

int hvnd_connector_get_local_addr(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			union nd_sockaddr_inet *addr)
{
	struct pkt_nd_connector_get_addr pkt;
	int ret;
 

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_GET_ADDRESS, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	memcpy(addr, &pkt.ioctl.out, sizeof(union nd_sockaddr_inet));
	return 0;

err:
	return ret;
}


int hvnd_connector_notify_disconnect(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle, struct hvnd_ep_obj *ep)
{
	struct pkt_nd_connector_notify_disconnect pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	irp_fhandle .local = ep->local_irp;

	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT, 0, 0, irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}


//ASYNCH call
int hvnd_connector_disconnect(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle, struct hvnd_ep_obj *ep)
{
	struct pkt_nd_connector_disconnect pkt;
	int ret;
	union ndv_context_handle irp_fhandle;

	irp_fhandle.local = ep->local_irp;
 

	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_CONNECTOR_DISCONNECT, 0, 0, irp_fhandle.val64);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = connector_handle;

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}

/*
 * QP operations.
 */
int hvnd_create_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		   struct hvnd_qp *qp)
{
	int ret;
	struct pkt_nd_create_qp *pkt;
	int num_pfn, num_db_pfn;
	int qp_pkt_size;
	unsigned int  offset;
	u32 ext_data_offset;
	u32 ext_data_size;

	/*
	 * Now create QP.
	 * First compute the number of PFNs we need to accomodate:
	 * One each for door bell and arm_sn and pages in cq buffer.
	 */
	offset = offset_in_page(qp->qp_buf);
	num_pfn = DIV_ROUND_UP(offset + qp->buf_size, PAGE_SIZE);

	offset = offset_in_page(qp->db_addr);
	num_db_pfn = DIV_ROUND_UP(offset + 4, PAGE_SIZE);

	qp_pkt_size = sizeof(struct pkt_nd_create_qp) +
		(num_pfn  * sizeof(u64));

	hvnd_debug("CREATE QP, num pfns is %d\n", num_pfn);
	hvnd_debug("CREATE QP, num DB pfns is %d\n", num_db_pfn);

	pkt = kzalloc(qp_pkt_size, GFP_KERNEL);

	if (!pkt)
		return -ENOMEM;

	hvnd_debug("offset of nd_create_qp is %d\n",
		(int)offsetof(struct pkt_nd_create_qp, ioctl.input));

	ext_data_offset = offsetof(struct pkt_nd_create_qp, ext_data) -
				sizeof(struct ndv_packet_hdr_control_1);

	ext_data_size = sizeof(struct create_qp_ext_data) + (num_pfn  * sizeof(u64)); 

	hvnd_init_hdr(&pkt->hdr,
		      qp_pkt_size -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_QP_CREATE,
		      ext_data_size,
		      ext_data_offset,
		      0);
			
	/*
	 * Now fill out the ioctl section.
	 */

	pkt->ioctl.input.hdr.version = ND_VERSION_1; 

	if (qp->max_inline_data > nd_dev->query_pkt.ioctl.ad_info.inline_request_threshold)
		qp->max_inline_data = nd_dev->query_pkt.ioctl.ad_info.inline_request_threshold;
	pkt->ioctl.input.hdr.cb_max_inline_data = qp->max_inline_data;

	hvnd_debug("pkt->ioctl.input.hdr.cb_max_inline_data=%d\n", pkt->ioctl.input.hdr.cb_max_inline_data);

	pkt->ioctl.input.hdr.ce_mapping_cnt = MLX4_IB_CREATE_QP_MAPPINGS_MAX;
	pkt->ioctl.input.hdr.cb_mapping_offset = sizeof(union create_qp_ioctl);

	pkt->ioctl.input.hdr.initiator_queue_depth = qp->initiator_q_depth;
	pkt->ioctl.input.hdr.max_initiator_request_sge = qp->initiator_request_sge;

	hvnd_debug("recv cq handle is %p\n", (void *)qp->receive_cq_handle);
	hvnd_debug("send cq handle is %p\n", (void *)qp->initiator_cq_handle);
	hvnd_debug("pd handle is %p\n", (void *)qp->pd_handle);
	pkt->ioctl.input.hdr.receive_cq_handle = qp->receive_cq_handle;
	pkt->ioctl.input.hdr.initiator_cq_handle = qp->initiator_cq_handle;
	pkt->ioctl.input.hdr.pd_handle = qp->pd_handle;


	hvnd_debug("ce_mapping cnt is %d\n",  pkt->ioctl.input.hdr.ce_mapping_cnt);
	hvnd_debug("cb_mapping offset is %d\n", pkt->ioctl.input.hdr.cb_mapping_offset);

	pkt->ioctl.input.receive_queue_depth = qp->receive_q_depth;
	pkt->ioctl.input.max_receive_request_sge = qp->receive_request_sge;


	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_BUF].map_memory.map_type = ND_MAP_MEMORY;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_BUF].map_memory.access_type = ND_MODIFY_ACCESS;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_BUF].map_memory.address = (u64)qp->qp_buf;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_BUF].map_memory.cb_length = qp->buf_size;

	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_DB].map_memory.map_type = ND_MAP_MEMORY_COALLESCE;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_DB].map_memory.access_type = ND_WRITE_ACCESS;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_DB].map_memory.address = (u64)qp->db_addr;
	pkt->mappings.qp_in.mappings[MLX4_IB_CREATE_QP_DB].map_memory.cb_length = 4; 

	pkt->mappings.qp_in.log_sq_bb_count = qp->log_sq_bb_count;
	pkt->mappings.qp_in.log_sq_stride = qp->log_sq_stride;
	pkt->mappings.qp_in.sq_no_prefetch = qp->sq_no_prefetch;


	/*
	 * Fill in the extended data.
	 */

	pkt->ext_data.cnt = 2;
	pkt->ext_data.fields[MLX4_IB_CREATE_QP_BUF].size = sizeof(struct gpa_range) + (num_pfn * sizeof(u64));
	pkt->ext_data.fields[MLX4_IB_CREATE_QP_BUF].offset = offsetof(struct create_qp_ext_data, qpbuf_gpa); 

	pkt->ext_data.fields[MLX4_IB_CREATE_QP_DB].size = sizeof(struct qp_db_gpa); 
	pkt->ext_data.fields[MLX4_IB_CREATE_QP_DB].offset = offsetof(struct create_qp_ext_data, db_gpa); 

	/*
	 * Fill up the gpa range for qp  buffer.
	 */ 

	pkt->ext_data.db_gpa.byte_count = 4; //KYS 8 or 16?
	pkt->ext_data.db_gpa.byte_offset = offset_in_page(qp->db_addr);
	user_va_init_pfn(&pkt->ext_data.db_gpa.pfn_array[0], qp->db_umem);

	pkt->ext_data.qpbuf_gpa.byte_count = qp->buf_size;
	pkt->ext_data.qpbuf_gpa.byte_offset = offset_in_page(qp->qp_buf);
	user_va_init_pfn(&pkt->ext_data.qpbuf_gpa.pfn_array[0], qp->umem);

	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt->hdr, qp_pkt_size, (u64)pkt);

	if (ret)
		goto cr_qp_err;

	/*
	 * Copy the necessary response from the host.
	 */
	qp->qp_handle = pkt->ioctl.resrc_desc.handle;

	qp->qpn = pkt->mappings.qp_resp.qpn;
	qp->max_send_wr = pkt->mappings.qp_resp.max_send_wr;
	qp->max_recv_wr = pkt->mappings.qp_resp.max_recv_wr;
	qp->max_send_sge = pkt->mappings.qp_resp.max_send_sge;
	qp->max_recv_sge = pkt->mappings.qp_resp.max_recv_sge;


	hvnd_debug("qp->max_send_wr=%d max_recv_wr=%d max_send_sge=%d max_recv_sge=%d max_inline_data=%d\n", qp->max_send_wr, qp->max_recv_wr, qp->max_send_sge, qp->max_recv_sge, qp->max_inline_data);

	ret = insert_handle(nd_dev, &nd_dev->qpidr, qp, qp->qpn);

	if (ret)
		goto cr_qp_err;

	hvnd_debug("QP create after success qpn:%d qp:%p handle:%llu\n", qp->qpn, qp, qp->qp_handle);

cr_qp_err:
	kfree(pkt);
	return ret;
}

int hvnd_free_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		 struct hvnd_qp *qp)
{
	remove_handle(nd_dev, &nd_dev->qpidr, qp->qpn);
	return hvnd_free_handle(nd_dev, uctx, qp->qp_handle, IOCTL_ND_QP_FREE);
}

int hvnd_flush_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		  struct hvnd_qp *qp)
{
	struct pkt_nd_flush_qp pkt;
	int ret;
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      IOCTL_ND_QP_FLUSH, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = qp->qp_handle;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	return ret;
}


int hvnd_bind_nic(struct hvnd_dev *nd_dev, bool un_bind, char *ip_addr, char *mac_addr)
{
	int ret;
	int pkt_type = NDV_PKT_ID1_BIND;

	/*
	 * Send the bind information over to the host.
	 * For now, we will have a single ip and MAC address that we
	 * will deal with. Down the road we will need to expand support
	 * for multiple IP and MAC addresses and also deal with changing
	 * IP addresses.
	 */

	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);
	hvnd_debug("bind packet type is %d ID:%d\n", pkt_type, NDV_PACKET_TYPE_ID(pkt_type));
	nd_dev->bind_pkt.pkt_hdr.packet_type = pkt_type;
	
	nd_dev->bind_pkt.pkt_hdr.hdr_sz = sizeof(struct ndv_pkt_hdr_bind_1);
	hvnd_debug("bind packet size is %d\n", (int)sizeof(struct ndv_pkt_hdr_bind_1));
	nd_dev->bind_pkt.pkt_hdr.data_sz = 0;
	nd_dev->bind_pkt.unbind = un_bind;
	nd_dev->bind_pkt.ip_address.address_family = AF_INET;
	nd_dev->bind_pkt.ip_address.ipv4.sin_family = AF_INET;
	nd_dev->bind_pkt.ip_address.ipv4.sin_port = 0;
	nd_dev->bind_pkt.ip_address.ipv4.sin_addr.s_addr = *(unsigned int*)ip_addr;

	nd_dev->bind_pkt.phys_addr.length = ETH_ALEN;
	memcpy(nd_dev->bind_pkt.phys_addr.addr, mac_addr, ETH_ALEN);

	/*
	 * This is the adapter handle; needs to be unique for each
	 * MAC, ip address tuple.
	 */
	nd_dev->bind_pkt.guest_id = (u64)nd_dev;

	ret = hvnd_send_packet(nd_dev, &nd_dev->bind_pkt,
				sizeof(struct ndv_pkt_hdr_bind_1),
				(u64)NULL,
				true);
	return ret;
}

int hvnd_init_resources(struct hvnd_dev *nd_dev)
{
	unsigned long mmio_sz;
	struct resource *resrc;
	int ret = -ENOMEM;

	resrc = &iomem_resource;

	mmio_sz = (nd_dev->hvdev->channel->offermsg.offer.mmio_megabytes * 1024 * 1024);
	nd_dev->mmio_sz = mmio_sz;
	nd_dev->mmio_resource.name = KBUILD_MODNAME;
	nd_dev->mmio_resource.flags = IORESOURCE_MEM | IORESOURCE_BUSY;

	ret = allocate_resource(resrc, &nd_dev->mmio_resource,
				mmio_sz, 0, -1, mmio_sz, NULL, NULL);

	if (ret) {
		hvnd_error("Unable to allocate mmio resources\n");
		return ret;
	}
	hvnd_debug("MMIO start is %p\n", (void *)nd_dev->mmio_resource.start);

	/*
	 * Send the mmio information over to the host.
	 */
	nd_dev->resources.pkt_hdr.packet_type = NDV_PKT_ID1_INIT_RESOURCES;
	nd_dev->resources.pkt_hdr.hdr_sz = sizeof(union ndv_packet_hdr);
	nd_dev->resources.pkt_hdr.data_sz = 0;

	nd_dev->resources.io_space_sz_mb = mmio_sz;
	nd_dev->resources.io_space_start = nd_dev->mmio_resource.start;

	ret = hvnd_send_packet(nd_dev, &nd_dev->resources,
				sizeof(struct ndv_pkt_hdr_init_resources_1),
				(u64)NULL,
				true);
	return ret;
}

int hvnd_query_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx)
{
	struct pkt_nd_query_adaptor *pkt;
	int ret;
	int pkt_type;

	hvnd_debug("Performing Adapter query nd_dev=%p\n", nd_dev);

	// check if there is a need to do query
	if (nd_dev->query_pkt_set)
		return 0;

	// need a lock, multiple process can call this at the same time

	down(&nd_dev->query_pkt_sem);
	if (nd_dev->query_pkt_set) {
		up(&nd_dev->query_pkt_sem);
		return 0;
	}

	/*
	 * Now query the adaptor.
	 */

	pkt = &nd_dev->query_pkt;

	pkt_type = NDV_PKT_ID1_CONTROL;
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);

	pkt->hdr.pkt_hdr.packet_type = pkt_type;
	pkt->hdr.pkt_hdr.hdr_sz = sizeof(struct ndv_packet_hdr_control_1);
	pkt->hdr.pkt_hdr.data_sz = sizeof(struct pkt_nd_query_adaptor) -
				   sizeof(struct ndv_packet_hdr_control_1);


	pkt->hdr.file_handle.local = uctx->file_handle.local;
	pkt->hdr.file_handle.remote = uctx->file_handle.remote;

	pkt->hdr.irp_handle.val64 = 0;

	pkt->hdr.io_cntrl_code = IOCTL_ND_ADAPTER_QUERY;
	pkt->hdr.output_buf_sz = sizeof(struct nd_adap_query_ioctl);
	pkt->hdr.input_buf_sz = sizeof(struct nd_adap_query_ioctl);
	pkt->hdr.input_output_buf_offset = 0;
	memset(&pkt->ioctl.ad_q, 0, sizeof(struct nd_adap_query_ioctl));

	pkt->ioctl.ad_q.version = ND_VERSION_1;
	pkt->ioctl.ad_q.info_version = ND_VERSION_2;
	pkt->ioctl.ad_q.adapter_handle = uctx->adaptor_hdl; 

	ret = hvnd_send_packet(nd_dev, pkt,
				sizeof(struct pkt_nd_query_adaptor),
				(unsigned long)pkt, true);

	hvnd_debug("pkt->ioctl.ad_info.inline_request_threshold=%d\n", pkt->ioctl.ad_info.inline_request_threshold);

	// how about host returning PENDING
	up(&nd_dev->query_pkt_sem);

	if (ret)
		return ret;

	hvnd_debug("Query Adaptor Succeeded\n");
	nd_dev->query_pkt_set = true;

	return 0;
}


int  hvnd_create_pd(struct hvnd_ucontext *uctx, struct hvnd_dev *nd_dev,
		    struct hvnd_ib_pd *hvnd_pd)
{
	struct pkt_nd_pd_create *pkt = &uctx->pd_cr_pkt;
	int ret;
	int pkt_type;

	hvnd_debug("Create Protection Domain\n");

	pkt_type = NDV_PKT_ID1_CONTROL;
	NDV_ADD_PACKET_OPTION(pkt_type, NDV_PACKET_OPTIONS_REQUIRES_PASSIVE);

	pkt->hdr.pkt_hdr.packet_type = pkt_type;
	pkt->hdr.pkt_hdr.hdr_sz = sizeof(struct ndv_packet_hdr_control_1);
	pkt->hdr.pkt_hdr.data_sz = sizeof(struct pkt_nd_pd_create) -
				   sizeof(struct ndv_packet_hdr_control_1);

	hvnd_debug("pdcreate packet size: %d\n", (int)sizeof(struct pkt_nd_pd_create));
	hvnd_debug("pdcreate hdr size: %d\n", (int)sizeof(struct ndv_packet_hdr_control_1));
	hvnd_debug("pdcreate data size: %d\n", pkt->hdr.pkt_hdr.data_sz);

	pkt->hdr.file_handle.local = uctx->create_pkt.handle.local; 
	pkt->hdr.file_handle.remote = uctx->create_pkt.handle.remote; 

	hvnd_debug("create pd uctx is %p\n", uctx);
	hvnd_debug("create pd local file is %d\n", uctx->create_pkt.handle.local);
	hvnd_debug("create pd local file is %d\n", uctx->create_pkt.handle.remote);

	pkt->hdr.irp_handle.val64 = 0;
	pkt->hdr.io_cntrl_code = IOCTL_ND_PD_CREATE;

	pkt->hdr.output_buf_sz = sizeof(struct nd_create_pd_ioctl);
	pkt->hdr.input_buf_sz =  sizeof(struct nd_create_pd_ioctl);
	pkt->hdr.input_output_buf_offset = 0;

	hvnd_debug("output/input buf size: %d\n", pkt->hdr.output_buf_sz);
	/*
	 * Fill the ioctl section.
	 */

	pkt->ioctl.in.version = ND_VERSION_1;
	pkt->ioctl.in.reserved = 0;
	pkt->ioctl.in.handle = uctx->adaptor_hdl;


	ret = hvnd_send_packet(nd_dev, pkt,
				sizeof(struct pkt_nd_pd_create),
				(unsigned long)pkt, true);

	if (ret)
		return ret;

	if (pkt->hdr.pkt_hdr.status != 0) {
		hvnd_error("Create PD failed; status is %d\n",
			pkt->hdr.pkt_hdr.status);
		return -EINVAL;
	}
	if (pkt->hdr.io_status != 0) {
		hvnd_error("Create PD failed;io status is %d\n",
			pkt->hdr.io_status);
		return -EINVAL;
	}

	hvnd_debug("Create PD Succeeded\n");

	hvnd_debug("pd_handle is %p\n", (void *)pkt->ioctl.resp.pd_handle);
	hvnd_debug("pdn is %d\n", (int)pkt->ioctl.resp.pdn);

	hvnd_pd->pdn = pkt->ioctl.resp.pdn;
	hvnd_pd->handle = pkt->ioctl.out_handle;
	
	return 0;
}

int hvnd_cancel_io(struct hvnd_ep_obj *ep_object)
{
	struct pkt_nd_cancel_io pkt;
	int ret;
	u32 ioctl;

	switch (ep_object->type) {
	case ND_LISTENER:
		hvnd_debug("LISTENER I/O Cancelled\n");
		ioctl = IOCTL_ND_LISTENER_CANCEL_IO;
		break;
	case ND_CONNECTOR:
		hvnd_debug("CONNECTOR I/O Cancelled\n");
		ioctl = IOCTL_ND_CONNECTOR_CANCEL_IO;
		break;
	case ND_MR:
		hvnd_debug("MR I/O Cancelled\n");
		ioctl = IOCTL_ND_MR_CANCEL_IO;
		break;
	case ND_CQ:
		hvnd_debug("CQ I/O Cancelled\n");
		ioctl = IOCTL_ND_CQ_CANCEL_IO;
		break;
	default:
		hvnd_error("UNKNOWN object type\n");
		return -EINVAL;
	}
 
	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      ep_object->uctx->create_pkt.handle.local,
		      ep_object->uctx->create_pkt.handle.remote,
		      ioctl, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = ep_object->ep_handle;
	hvnd_debug("cancel io handle is %p\n", (void *)ep_object->ep_handle);
 
	ret = hvnd_send_ioctl_pkt(ep_object->nd_dev, &pkt.hdr,
				sizeof(pkt),
				(u64)&pkt);

	if (ret)
		goto err;

	/*
	 * Now that we have cancelled all I/Os,
	 */

	return 0;

err:
	hvnd_error("cancel I/O operation failed\n");
	return ret;
}


int hvnd_free_handle(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle, u32 ioctl)
{
	struct pkt_nd_free_handle pkt;
	int ret;
 
	hvnd_debug("Freeing handle ioctl is %s; handle is %p\n",
		hvnd_get_op_name(ioctl), (void *)handle);

	hvnd_debug("uctx is %p\n", uctx);
	hvnd_debug("nd_dev is %p\n", nd_dev);

	memset(&pkt, 0, sizeof(pkt)); //KYS try to avoid having to zero everything
	hvnd_init_hdr(&pkt.hdr,
		      sizeof(pkt) -
		      sizeof(struct ndv_packet_hdr_control_1),
		      uctx->create_pkt.handle.local,
		      uctx->create_pkt.handle.remote,
		      ioctl, 0, 0, 0);

	/*
	 * Now fill in the ioctl section.
	 */
	pkt.ioctl.in.version = ND_VERSION_1;
	pkt.ioctl.in.reserved = 0;
	pkt.ioctl.in.handle = handle;
 
	ret = hvnd_send_ioctl_pkt(nd_dev, &pkt.hdr, sizeof(pkt), (u64)&pkt);

	if (ret)
		goto err;

	return 0;

err:
	hvnd_error("%s: ret=%d\n", __func__, ret);
	return ret;
}

int hvnd_negotiate_version(struct hvnd_dev *nd_dev)
{
	union ndv_packet_init *pkt = &nd_dev->init_pkt;
	int ret;

	nd_dev->negotiated_version = NDV_PROTOCOL_VAERSION_INVALID;

	pkt->packet_type = NDV_PACKET_TYPE_INIT;
	pkt->protocol_version = NDV_PROTOCOL_VERSION_CURRENT;
	pkt->flags = 0; //KYS are the flags 0?

	ret = hvnd_send_packet(nd_dev, pkt, 
			       sizeof(union ndv_packet_init), (u64)NULL, true);

	return ret;
} 

void hvnd_callback(void *context)
{
	struct hv_device *dev = context;
	struct hvnd_dev *nd_dev = hv_get_drvdata(dev);
	int copy_sz = 0;
	struct ndv_packet_hdr_control_1 *ctrl_hdr;
	union ndv_packet_init *pkt_init;
	u32 recvlen;
	u32 local_irp;
	u64 requestid;
	u32 *pkt_type;
	u32 pkt_id;
	struct hvnd_ep_obj *ep_object;
	struct incoming_pkt *incoming_pkt; /* Used only for asynch calls */
	char *incoming_pkt_start;
	struct vmpacket_descriptor *desc;
	int status;
	struct hvnd_cookie *hvnd_cookie;
	unsigned long flags;

	vmbus_recvpacket_raw(dev->channel, hvnd_recv_buffer,
			 (PAGE_SIZE * 4), &recvlen, &requestid);

	if (recvlen <= 0)
		return;

	desc = (struct vmpacket_descriptor *)hvnd_recv_buffer;
	incoming_pkt_start = hvnd_recv_buffer + (desc->offset8 << 3);
	recvlen -= desc->offset8 << 3;

	pkt_type = (u32 *)incoming_pkt_start;
	pkt_id = *pkt_type;
	if (pkt_id != NDV_PACKET_TYPE_INIT)
		pkt_id = NDV_PACKET_TYPE_ID(pkt_id);

	switch (pkt_id) {
	case NDV_PACKET_TYPE_INIT:
		/*
		 * Host is responding to our init packet.
		 */
		pkt_init = (union ndv_packet_init *)incoming_pkt_start;
		nd_dev->negotiated_version = pkt_init->protocol_version;
		copy_sz = 0;
		break;

	case NDV_PKT_ID1_INIT_RESOURCES:
		copy_sz = 0;
		break;

	case NDV_PKT_ID1_BIND:
		nd_dev->bind_pkt.pkt_hdr.status = ((union ndv_packet_hdr *) incoming_pkt_start)->status;
		copy_sz = 0;
		break;

	case NDV_PKT_ID1_COMPLETE:
		ctrl_hdr = (struct ndv_packet_hdr_control_1 *)incoming_pkt_start;
		status = ctrl_hdr->io_status;

		local_irp = ctrl_hdr->irp_handle.local;
		ep_object = (struct hvnd_ep_obj *)map_irp_to_ctx(nd_dev, local_irp);

		if (!ep_object) {
			hvnd_error("irp could not be mapped; irp is %d ioctl is %s", 
				local_irp, hvnd_get_op_name(ctrl_hdr->io_cntrl_code));
			goto complete;
		}

		if (ctrl_hdr->io_cntrl_code != IOCTL_ND_CQ_NOTIFY)
			hvnd_debug("completion packet; iostatus is %x, ioctl is %s", ctrl_hdr->io_status, hvnd_get_op_name(ctrl_hdr->io_cntrl_code)); 

		switch(ctrl_hdr->io_cntrl_code) {

		case IOCTL_ND_CQ_NOTIFY: 
			hvnd_process_cq_event_complete(ep_object, status);

			ep_del_work_pending(ep_object);
			goto complete;

		case IOCTL_ND_CONNECTOR_ACCEPT:

			hvnd_process_connector_accept(ep_object, status);

			ep_del_work_pending(ep_object);
			goto complete;

		case IOCTL_ND_CONNECTOR_DISCONNECT:
			hvnd_debug("disconnected: ep opj is %p; status: %d\n", ep_object, status);
			hvnd_process_disconnect(ep_object, status);

			ep_del_work_pending(ep_object);
			goto complete;

		default:
			break;
		}

		/*
		 * This is the completion notification;
		 * the IRP cookie is the state through which
		 * we will invoke the callback.
		 */
		incoming_pkt = (struct incoming_pkt *) kmalloc(recvlen + sizeof(struct incoming_pkt), GFP_ATOMIC);
		if (incoming_pkt == NULL) {
			hvnd_error("Could not alloc memory in callback\n");
			ep_del_work_pending(ep_object);
			goto complete;
		}
		memcpy(incoming_pkt->pkt, incoming_pkt_start, recvlen);

		spin_lock_irqsave(&ep_object->incoming_pkt_list_lock, flags);
		list_add_tail(&incoming_pkt->list_entry, &ep_object->incoming_pkt_list);
		spin_unlock_irqrestore(&ep_object->incoming_pkt_list_lock, flags);

		schedule_work(&ep_object->wrk.work);

		goto complete;

	case NDV_PKT_ID1_CREATE:
		copy_sz = sizeof(struct ndv_pkt_hdr_create_1);	
		break;

	case NDV_PKT_ID1_CLEANUP:
		copy_sz = sizeof(struct ndv_pkt_hdr_cleanup_1);
		break;

	case NDV_PKT_ID1_CONTROL:
		ctrl_hdr = (struct ndv_packet_hdr_control_1 *)incoming_pkt_start;
		status = ctrl_hdr->io_status;

		if (ctrl_hdr->io_cntrl_code != IOCTL_ND_CQ_NOTIFY)
			hvnd_debug("packet; iostatus is %x ioctl is %s", 
				ctrl_hdr->io_status, hvnd_get_op_name(ctrl_hdr->io_cntrl_code)); 

		switch (ctrl_hdr->io_cntrl_code) {

		case IOCTL_ND_PROVIDER_INIT:
			copy_sz = sizeof(struct pkt_nd_provider_ioctl);
			break;

		case IOCTL_ND_PROVIDER_BIND_FILE:
			copy_sz = sizeof(struct pkt_nd_provider_ioctl);
			break;

		case IOCTL_ND_ADAPTER_OPEN:
			copy_sz = sizeof(struct pkt_nd_open_adapter);
			break;

		case IOCTL_ND_ADAPTER_CLOSE:
			copy_sz = sizeof(struct pkt_nd_free_handle);
			break;

		case IOCTL_ND_ADAPTER_QUERY: 
			copy_sz = sizeof(struct pkt_nd_query_adaptor);
			break;

		case IOCTL_ND_PD_CREATE:
			copy_sz = sizeof(struct pkt_nd_pd_create);
			break;

		case IOCTL_ND_PD_FREE:
			copy_sz = sizeof(struct pkt_nd_free_handle);
			break;

		case IOCTL_ND_CQ_CREATE:
			copy_sz = sizeof(struct pkt_nd_create_cq);
			break;

		case IOCTL_ND_CQ_FREE:
			copy_sz = sizeof(struct pkt_nd_free_cq);
			break;

		case IOCTL_ND_CQ_NOTIFY: //FIXME check ep stop state
			local_irp = ctrl_hdr->irp_handle.local;
			ep_object = (struct hvnd_ep_obj *)map_irp_to_ctx(nd_dev, local_irp);
			if (!ep_object) {
				hvnd_error("irp could not be mapped\n");
				goto complete;
				return;
			}	
			copy_sz = sizeof(struct pkt_nd_notify_cq);
			hvnd_process_cq_event_pending(ep_object, status);
			goto complete;
			return;

		case IOCTL_ND_LISTENER_CREATE: 
			copy_sz = sizeof(struct pkt_nd_cr_listener);
			break;

		case IOCTL_ND_LISTENER_FREE: 
			copy_sz = sizeof(struct pkt_nd_free_listener);
			break;

		case IOCTL_ND_QP_FREE: 
			copy_sz = sizeof(struct pkt_nd_free_handle);
			break;

		case IOCTL_ND_CONNECTOR_CANCEL_IO: 
		case IOCTL_ND_MR_CANCEL_IO:
		case IOCTL_ND_CQ_CANCEL_IO:
		case IOCTL_ND_LISTENER_CANCEL_IO: 
			copy_sz = sizeof(struct pkt_nd_cancel_io);
			break;

		case IOCTL_ND_LISTENER_BIND: 
			copy_sz = sizeof(struct pkt_nd_bind_listener);
			break;

		case IOCTL_ND_LISTENER_LISTEN: 
			copy_sz = sizeof(struct pkt_nd_listen_listener);
			break;

		case IOCTL_ND_LISTENER_GET_ADDRESS: 
			copy_sz = sizeof(struct pkt_nd_get_addr_listener);
			break;

		case IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST: 
			copy_sz = sizeof(struct pkt_nd_get_connection_listener);
			goto complete; // non-block

		case IOCTL_ND_CONNECTOR_CREATE: 
			copy_sz = sizeof(struct pkt_nd_cr_connector);
			break;

		case IOCTL_ND_CONNECTOR_FREE: 
			copy_sz = sizeof(struct pkt_nd_free_connector);
			break;

		case IOCTL_ND_CONNECTOR_BIND: 
			copy_sz = sizeof(struct pkt_nd_free_connector);
			break;

		case IOCTL_ND_CONNECTOR_CONNECT: //KYS: ALERT: ASYNCH Operation 
			copy_sz = sizeof(struct pkt_nd_connector_connect);
			goto complete; //non-block

		case IOCTL_ND_CONNECTOR_COMPLETE_CONNECT: 
			copy_sz = sizeof(struct pkt_nd_connector_connect_complete);
			break;

		case IOCTL_ND_CONNECTOR_ACCEPT: //KYS: ALERT: ASYNCH Operation 
			copy_sz = sizeof(struct pkt_nd_connector_accept);
			goto complete; //non-block

		case IOCTL_ND_CONNECTOR_REJECT: 
			copy_sz = sizeof(struct pkt_nd_connector_reject);
			break;

		case IOCTL_ND_CONNECTOR_GET_READ_LIMITS: 
			copy_sz = sizeof(struct pkt_nd_connector_get_rd_limits);
			break;

		case IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA: 
			copy_sz = sizeof(struct pkt_nd_connector_get_priv_data);
			break;

		case IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS: 
			copy_sz = sizeof(struct pkt_nd_connector_get_peer_addr);
			break;

		case IOCTL_ND_CONNECTOR_GET_ADDRESS: 
			copy_sz = sizeof(struct pkt_nd_connector_get_addr);
			break;

		case IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT: //KYS: ALERT: ASYNCH Operation 
			copy_sz = sizeof(struct pkt_nd_connector_notify_disconnect);
			goto complete; //non-block

		case IOCTL_ND_CONNECTOR_DISCONNECT: //KYS: ALERT: ASYNCH Operation 
			hvnd_debug("IOCTL_ND_CONNECTOR_DISCONNECT\n");
			copy_sz = sizeof(struct pkt_nd_connector_notify_disconnect);
			goto complete; // non-block

		case IOCTL_ND_QP_CREATE: 
			copy_sz = sizeof(struct pkt_nd_create_qp);
			break;

		case IOCTL_ND_MR_CREATE: 
			copy_sz = sizeof(struct pkt_nd_create_mr);
			break;

		case IOCTL_ND_MR_FREE: 
			copy_sz = sizeof(struct pkt_nd_free_handle);
			break;

		case IOCTL_ND_MR_REGISTER: 
			copy_sz = sizeof(struct pkt_nd_register_mr);
			break;

		case IOCTL_ND_MR_DEREGISTER:
			copy_sz = sizeof(struct pkt_nd_deregister_mr);
			break;

		case IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST:
			copy_sz = sizeof(struct pkt_query_addr_list);
			break;

		case IOCTL_ND_QP_FLUSH:
			copy_sz = sizeof(struct pkt_nd_flush_qp);
			break;

		default:
			hvnd_warn("Got unknown ioctl: %d\n",
				ctrl_hdr->io_cntrl_code); 
			copy_sz = 0;
			break;
		}

		break;
	default:
		hvnd_warn("Got an unknown packet type %d\n", *pkt_type);
		break;
	}

	hvnd_cookie = (struct hvnd_cookie *)requestid;
	memcpy(hvnd_cookie->pkt, incoming_pkt_start, copy_sz);
	complete(&hvnd_cookie->host_event);

complete:
	/* send out ioctl completion patcket */
	if(desc->flags & VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED) {
		int retry = 5;
		while (true) {
			int ret;
			ret = vmbus_sendpacket(dev->channel, NULL, 0, requestid, VM_PKT_COMP, 0);
			if(ret == 0) {
				break;
			} else if (ret == -EAGAIN) {
				if(--retry == 0) {
					hvnd_error("give up retrying send completion packet\n");
					break;
				}
				hvnd_warn("retrying send completion packet\n");
				udelay(100);
			} else {
				hvnd_error("unable to send completion packet ret=%d\n", ret);
				break;
			}
		}
	}

}
