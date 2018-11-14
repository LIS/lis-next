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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/io.h>
#include "include/linux/hyperv.h"
#include <linux/completion.h>
#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "vmbus_rdma.h"

static struct hvnd_dev *g_nd_dev = NULL; // the one and only one

int hvnd_log_level = HVND_ERROR;
module_param(hvnd_log_level, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(hvnd_log_level,
	"Logging level, "
	"0 - Error (default), "
	"1 - Warning, "
	"2 - Info, "
	"3 - Debug.");

static int disable_cq_notify = 1;
//static int disable_cq_notify = 0;
module_param(disable_cq_notify, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(disable_cq_notify,
	"Disable CQ notification, "
	"0 - Enable, "
	"1 - Disable (default).");

enum {
	MLX4_USER_DEV_CAP_64B_CQE = 1L << 0
};

#define HVND_NODE_DESC "vmbus-RDMA"

#undef MLX4_IB_UVERBS_ABI_VERSION
#define MLX4_IB_UVERBS_ABI_VERSION             4 

struct mlx4_wqe_data_seg {
	__be32                  byte_count;
	__be32                  lkey;
	__be64                  addr;
};

/* return value:
	true: ep is running
	false: ep is stopped
*/
bool ep_add_work_pending(struct hvnd_ep_obj *ep_object)
{
	bool ret = true;
	atomic_inc(&ep_object->nr_requests_pending);
	if (ep_object->stopping) {
		if(atomic_dec_and_test(&ep_object->nr_requests_pending))
			wake_up(&ep_object->wait_pending);
		ret = false;
	}
	return ret;
}

void ep_del_work_pending(struct hvnd_ep_obj *ep_object)
{
	if(atomic_dec_and_test(&ep_object->nr_requests_pending))
		wake_up(&ep_object->wait_pending);

	if(atomic_read(&ep_object->nr_requests_pending)<0) {
		hvnd_error("ep_object->nr_requests_pending=%d type=%d cm_state=%d\n", atomic_read(&ep_object->nr_requests_pending), ep_object->type, ep_object->cm_state);
		dump_stack();
	}
}

void ep_stop(struct hvnd_ep_obj *ep_object)
{
	if (!ep_object->stopping) {
		ep_object->stopping = true;
		hvnd_cancel_io(ep_object);
	}

	if(atomic_read(&ep_object->nr_requests_pending)<0) {
		hvnd_error("IO canceled, ep_object->nr_requests_pending=%d type=%d cm_state=%d\n", atomic_read(&ep_object->nr_requests_pending), ep_object->type, ep_object->cm_state);
		dump_stack();
	}

	wait_event(ep_object->wait_pending, !atomic_read(&ep_object->nr_requests_pending));
}

static int vmbus_dma_map_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction direction, struct dma_attrs *attrs)
{
	struct scatterlist *sg;
	u64 addr;
	int i;
	int ret = nents;

	BUG_ON(!valid_dma_direction(direction));

	for_each_sg(sgl, sg, nents, i) {
		addr = (u64) page_address(sg_page(sg));
		/* TODO: handle highmem pages */
		if (!addr) {
			ret = 0;
			break;
		}
		sg->dma_address = addr + sg->offset;
		sg->dma_length = sg->length;
	}
	return ret;
}

static void vmbus_dma_unmap_sg(struct device *dev,
			 struct scatterlist *sg, int nents,
			 enum dma_data_direction direction, struct dma_attrs *attrs)
{
	BUG_ON(!valid_dma_direction(direction));
}


struct dma_map_ops vmbus_dma_ops = {
	.map_sg = vmbus_dma_map_sg,
	.unmap_sg = vmbus_dma_unmap_sg,
};

static int hvnd_get_incoming_connections(struct hvnd_ep_obj *listener,
					 struct hvnd_dev *nd_dev,
					 struct hvnd_ucontext *uctx);

static struct hvnd_ep_obj *hvnd_setup_ep(struct iw_cm_id *cm_id, int ep_type,
					struct hvnd_dev *nd_dev,
					struct hvnd_ucontext *uctx);

static void hvnd_deinit_ep(struct hvnd_ep_obj *ep)
{
	put_irp_handle(ep->nd_dev, ep->local_irp);
}

static void hvnd_destroy_ep(struct hvnd_ep_obj *ep)
{
	hvnd_debug("canceling work for ep %p\n", ep);
	cancel_work_sync(&ep->wrk.work);
	hvnd_deinit_ep(ep);
	kfree(ep);
}


#define	UC(b)	(((int)b)&0xff)
char *debug_inet_ntoa(struct in_addr in, char *b)
{
	register char *p;

	p = (char *)&in;
	(void)snprintf(b, 20,
	    "%d.%d.%d.%d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);
}

void hvnd_process_events(struct work_struct *work);

static int hvnd_init_ep(struct hvnd_ep_obj *ep_object,
			 struct iw_cm_id *cm_id, int ep_type,
			 struct hvnd_dev *nd_dev,
			 struct hvnd_ucontext *uctx)
{
	int ret;

	ep_object->type = ep_type;
	ep_object->cm_id = cm_id;
	ep_object->nd_dev = nd_dev;
	ep_object->uctx = uctx;

	ep_object->parent = NULL;

	ep_object->wrk.callback_arg = ep_object;
	INIT_WORK(&ep_object->wrk.work, hvnd_process_events);
	INIT_LIST_HEAD(&ep_object->incoming_pkt_list);
	spin_lock_init(&ep_object->incoming_pkt_list_lock);

/*
	spin_lock_init(&ep_object->ep_lk);
	ep_object->to_be_destroyed = false;
	ep_object->io_outstanding = false;
	ep_object->stopped = false;
*/
	ep_object->stopping = false;
	atomic_set(&ep_object->nr_requests_pending, 0);
	init_waitqueue_head(&ep_object->wait_pending);

	ret = get_irp_handle(nd_dev, &ep_object->local_irp, (void *)ep_object);

	if (ret) {
		hvnd_error("get_irp_handle() failed: err: %d\n", ret);
		return ret;
	}
	return 0;

}

static int set_rq_size(struct hvnd_dev *dev, struct ib_qp_cap *cap,
			struct hvnd_qp *qp)
{

	/* HW requires >= 1 RQ entry with >= 1 gather entry */
	if (!cap->max_recv_wr || !cap->max_recv_sge)
		return -EINVAL;

	qp->rq_wqe_cnt   = roundup_pow_of_two(max(1U, cap->max_recv_wr));
	qp->rq_max_gs    = roundup_pow_of_two(max(1U, cap->max_recv_sge));
	qp->rq_wqe_shift = ilog2(qp->rq_max_gs * sizeof (struct mlx4_wqe_data_seg));


	return 0;
}

static int set_user_sq_size(struct hvnd_dev *dev,
			    struct hvnd_qp *qp,
			    struct mlx4_ib_create_qp *ucmd)
{
	qp->sq_wqe_cnt   = 1 << ucmd->log_sq_bb_count;
	qp->sq_wqe_shift = ucmd->log_sq_stride;

	qp->buf_size = (qp->rq_wqe_cnt << qp->rq_wqe_shift) +
			(qp->sq_wqe_cnt << qp->sq_wqe_shift);

	return 0;
}

static int hvnd_db_map_user(struct hvnd_ucontext *uctx, unsigned long virt,
				struct ib_umem **db_umem) 
{
	struct mlx4_ib_user_db_page *page;
	int err = 0;

	mutex_lock(&uctx->db_page_mutex);

	list_for_each_entry(page, &uctx->db_page_list, list)
		if (page->user_virt == (virt & PAGE_MASK))
			goto found;

	page = kmalloc(sizeof *page, GFP_KERNEL);
	if (!page) {
		err = -ENOMEM;
		goto out;
	}

	page->user_virt = (virt & PAGE_MASK);
	page->refcnt    = 0;
	page->umem      = ib_umem_get(&uctx->ibucontext, virt & PAGE_MASK,
				      PAGE_SIZE, 0, 0);
	if (IS_ERR(page->umem)) {
		hvnd_error("ib_umem_get failure\n");
		err = PTR_ERR(page->umem);
		kfree(page);
		goto out;
	}

	list_add(&page->list, &uctx->db_page_list);

found:
	++page->refcnt;
out:
	mutex_unlock(&uctx->db_page_mutex);
	if (!err)
		*db_umem = page->umem;

	return err;
}

static void hvnd_db_unmap_user(struct hvnd_ucontext *uctx, u64 db_addr)
{
	struct mlx4_ib_user_db_page *page;

	mutex_lock(&uctx->db_page_mutex);
	list_for_each_entry(page, &uctx->db_page_list, list)
		if (page->user_virt == (db_addr & PAGE_MASK))
			goto found;

found:
	if (!--page->refcnt) {
		list_del(&page->list);
		ib_umem_release(page->umem);
		kfree(page);
	}

	mutex_unlock(&uctx->db_page_mutex);
}


static void debug_check(const char *func, int line)
{
	hvnd_debug("func is: %s; line is %d\n", func, line);

	if (in_interrupt()) {
		hvnd_error("In interrupt func is: %s; line is %d\n", func, line);
		return;
	}
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4)) 
static struct ib_ah *hvnd_ah_create(struct ib_pd *pd,
				    struct ib_ah_attr *ah_attr)
#elif (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(7,4))
static struct ib_ah *hvnd_ah_create(struct ib_pd *pd,
				    struct ib_ah_attr *ah_attr,
				    struct ib_udata *udata)
#else
static struct ib_ah *hvnd_ah_create(struct ib_pd *pd,
				    struct rdma_ah_attr *ah_attr,
				    struct ib_udata *udata)
#endif
{
	debug_check(__func__, __LINE__);
	return ERR_PTR(-ENOSYS);
}

static int hvnd_ah_destroy(struct ib_ah *ah)
{
	debug_check(__func__, __LINE__);
	return -ENOSYS;
}

static int hvnd_multicast_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	debug_check(__func__, __LINE__);
	return -ENOSYS;
}

static int hvnd_multicast_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	debug_check(__func__, __LINE__);
	return -ENOSYS;
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
static int hvnd_process_mad(struct ib_device *ibdev,
			    int mad_flags,
			    u8 port_num,
			    const struct ib_wc *in_wc,
			    const struct ib_grh *in_grh,
			    const struct ib_mad_hdr *in_mad,
			    size_t in_mad_size,
			    struct ib_mad_hdr *out_mad,
			    size_t *out_mad_size,
			    u16 *out_mad_pkey_index)
#else
static int hvnd_process_mad(struct ib_device *ibdev, int mad_flags,
			    u8 port_num, struct ib_wc *in_wc,
			    struct ib_grh *in_grh, struct ib_mad *in_mad,
			    struct ib_mad *out_mad)
#endif
{
	debug_check(__func__, __LINE__);
	return -ENOSYS;
}

void hvnd_acquire_uctx_ref(struct hvnd_ucontext *uctx)
{
	atomic_inc(&uctx->refcnt);
}

void hvnd_drop_uctx_ref(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx)
{
	if (atomic_dec_and_test(&uctx->refcnt)) {
		hvnd_debug("uctx ref cnt dropped it is %d\n", atomic_read(&uctx->refcnt));
		hvnd_debug("About to close adaptor\n");
		hvnd_close_adaptor(nd_dev, uctx);
	}
	else
		hvnd_debug("uctx ref cnt dropped it is %d\n", atomic_read(&uctx->refcnt));
}


static int hvnd_dealloc_ucontext(struct ib_ucontext *context)
{
	struct hvnd_dev *nd_dev;
	struct hvnd_ucontext *uctx;

	uctx = to_nd_context(context);
	nd_dev = to_nd_dev(context->device);

	hvnd_debug("calling %s\n", __func__);

	hvnd_drop_uctx_ref(nd_dev, uctx);

	return 0;
}

static struct ib_ucontext *hvnd_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata)
{
	struct hvnd_dev *nd_dev = to_nd_dev(ibdev);
	struct hvnd_ucontext *uctx;
	struct mlx4_ib_alloc_ucontext_resp resp;
	int ret;

	if (!nd_dev->ib_active) {
		hvnd_error("ib device is not active, try again\n");
		return ERR_PTR(-EAGAIN);
	}

	uctx = get_uctx(nd_dev, current_pid());
	if (uctx) {
		// it is already opened, just increase its reference count
		hvnd_acquire_uctx_ref(uctx);
	} else {

		/*
		 * The Windows host expects the following to be done:
		 * 1. Successfully send struct ndv_pkt_hdr_create_1
		 * 2. INIT PROVIDER
		 * 3. Open Adapter
		 * Before we can complete this call.
		 */

		uctx = kzalloc(sizeof(struct hvnd_ucontext), GFP_KERNEL);
		if (!uctx) {
			return ERR_PTR(-ENOMEM);
		}

		atomic_set(&uctx->refcnt, 1);
		INIT_LIST_HEAD(&uctx->db_page_list);
		mutex_init(&uctx->db_page_mutex);

		/*
		 * Stash away the context with the calling PID.
		 */
		ret = insert_handle(nd_dev, &nd_dev->uctxidr, uctx, current_pid());
		if (ret) {
			hvnd_error("Uctx ID insertion failed; ret is %d\n", ret);
			goto err1;
		}

		hvnd_debug("Opening adaptor pid is %d\n", current_pid());

		ret = hvnd_open_adaptor(nd_dev, uctx);
		if (ret) {
			hvnd_error("hvnd_open_adaptor failed ret=%d\n", ret);
			goto err1;
		}

	}

	/*
	 * Copy the response out.
	 */

	resp.dev_caps         =	MLX4_USER_DEV_CAP_64B_CQE; 
	resp.qp_tab_size      = uctx->o_adap_pkt.mappings.ctx_output.qp_tab_size;
	resp.bf_reg_size      = uctx->o_adap_pkt.mappings.ctx_output.bf_reg_size;
	resp.bf_regs_per_page =	uctx->o_adap_pkt.mappings.ctx_output.bf_regs_per_page;
	resp.cqe_size         =	uctx->o_adap_pkt.mappings.ctx_output.cqe_size;

	ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (ret) {
		hvnd_error("ib_copy_to_udata failed ret=%d\n", ret);
		goto err1;
	}

	return &uctx->ibucontext;

err1:
	kfree(uctx);
	return ERR_PTR(ret);
}

static int hvnd_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	struct hvnd_ucontext *uctx = to_nd_context(context);

	if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
		hvnd_error("vma not a page size, actual size=%lu\n", vma->vm_end - vma->vm_start);
		return -EINVAL;
	}

	if (vma->vm_pgoff == 0) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

		if (io_remap_pfn_range(vma, vma->vm_start,
					(uctx->uar_base >> PAGE_SHIFT),
					PAGE_SIZE, vma->vm_page_prot)) {
			hvnd_error("io_remap_pfn_range failure\n");
			return -EAGAIN;
		}
	} else if (vma->vm_pgoff == 1 && uctx->bf_buf_size != 0) {
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

		if (io_remap_pfn_range(vma, vma->vm_start,
					(uctx->uar_base >> PAGE_SHIFT) + 1, 
					PAGE_SIZE, vma->vm_page_prot)) {
			hvnd_error("io_remap_pfn_range failure\n");
			return -EAGAIN;
		}
	} else {
		hvnd_error("check code\n");
		return -EINVAL;
	}

	return 0;
}

static int hvnd_deallocate_pd(struct ib_pd *pd)
{

	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	struct hvnd_ib_pd *hvnd_pd;
	struct ib_ucontext *ibuctx = pd->uobject->context;

	hvnd_pd = to_nd_pd(pd);
	nd_dev = to_nd_dev(pd->device);
	uctx = to_nd_context(ibuctx); 

	hvnd_free_handle(nd_dev, uctx, hvnd_pd->handle,
			 IOCTL_ND_PD_FREE);

	hvnd_drop_uctx_ref(nd_dev, uctx);
	return 0;
}

static struct ib_pd *hvnd_allocate_pd(struct ib_device *ibdev,
				      struct ib_ucontext *context,
				      struct ib_udata *udata)
{
	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	int ret;
	struct hvnd_ib_pd *hvnd_pd;

	if (!context) {
		hvnd_error("kernel mode context not supported\n");
		return ERR_PTR(-EINVAL);
	}


	hvnd_pd = kzalloc(sizeof(struct hvnd_ib_pd), GFP_KERNEL);

	if (!hvnd_pd) {
		return ERR_PTR(-ENOMEM);
	}

	uctx = to_nd_context(context);
	nd_dev = to_nd_dev(ibdev);

	ret = hvnd_create_pd(uctx, nd_dev, hvnd_pd);
	if (ret) {
		hvnd_error("hvnd_create_pd failure ret=%d\n", ret);
		goto error_cr_pd;
	}

	if (context) {
		if (ib_copy_to_udata(udata, &hvnd_pd->pdn, sizeof (__u32))) {
			hvnd_error("ib_copy_to_udata failure\n");
			ret = -EFAULT;
			goto error_fault;
		}
	}

	hvnd_acquire_uctx_ref(uctx);
	return &hvnd_pd->ibpd;

error_fault:
	hvnd_free_handle(nd_dev, uctx, hvnd_pd->handle,
			 IOCTL_ND_PD_FREE);
	
error_cr_pd:
	kfree(hvnd_pd);
	return ERR_PTR(ret);
}

static int hvnd_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			   u16 *pkey)
{
	debug_check(__func__, __LINE__);
	*pkey = 0;
	return 0;
}

static int hvnd_query_gid(struct ib_device *ibdev, u8 port, int index,
			  union ib_gid *gid)
{
	int ret;
	struct hvnd_dev *nd_dev = to_nd_dev(ibdev);

	debug_check(__func__, __LINE__);

	if (!nd_dev->bind_complete) {
		ret = wait_for_completion_timeout(&nd_dev->addr_set, 60*HZ);
		if (!ret && !nd_dev->bind_complete)
			return -ETIMEDOUT;
	}

	memset(&(gid->raw[0]), 0, sizeof(gid->raw));
	memcpy(&(gid->raw[0]), nd_dev->mac_addr, 6);
	return 0;
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
static int hvnd_query_device(struct ib_device *ibdev,
			     struct ib_device_attr *props,
			     struct ib_udata *udata)
#else
static int hvnd_query_device(struct ib_device *ibdev,
			     struct ib_device_attr *props)
#endif
{
	struct hvnd_dev *nd_dev = to_nd_dev(ibdev);
	struct adapter_info_v2 *adap_info;

	if (!nd_dev->query_pkt_set) {
		hvnd_error("query packet not received yet\n");
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
		return 0;
#else
		return -ENODATA;
#endif
	}

	adap_info = &nd_dev->query_pkt.ioctl.ad_info;

	memset(props, 0, sizeof *props);

	/*
	 * Copy the relevant properties out.
	 */
	props->fw_ver = 0;
	props->device_cap_flags    = 0;
	//props->device_cap_flags |= IB_DEVICE_BAD_PKEY_CNTR;
	//props->device_cap_flags |= IB_DEVICE_BAD_QKEY_CNTR;
	//props->device_cap_flags |= IB_DEVICE_XRC;

	props->vendor_id           =  0x15b3;
	props->vendor_part_id      = adap_info->device_id;

	props->max_mr_size         = ~0ull;
	props->page_size_cap       = PAGE_SIZE;
	props->max_qp              = 16384;
	props->max_qp_wr           = min(adap_info->max_recv_q_depth,
					 adap_info->max_initiator_q_depth);

	props->max_sge             = min(adap_info->max_initiator_sge, 
					 adap_info->max_recv_sge);
	props->max_cq              = 0x1FFFF;
	props->max_cqe             = adap_info->max_completion_q_depth;
	props->max_mr              = 16384;
	props->max_pd              = 16384;

	props->max_qp_rd_atom      = adap_info->max_inbound_read_limit;
	props->max_qp_init_rd_atom = adap_info->max_outbound_read_limit;
	props->max_res_rd_atom     = props->max_qp_rd_atom * props->max_qp;
	props->max_srq             = 16384;
	props->max_srq_wr          = adap_info->max_recv_q_depth;
	props->max_srq_sge         = adap_info->max_recv_sge;

	return 0;
}

static int hvnd_query_port(struct ib_device *ibdev, u8 port,
			   struct ib_port_attr *props)
{
	memset(props, 0, sizeof(struct ib_port_attr));

	props->max_mtu = IB_MTU_4096;
	props->active_mtu = IB_MTU_4096;

	/*
	 * KYS: TBD need to base this on netdev.
	 */
	props->state = IB_PORT_ACTIVE;

	props->port_cap_flags = IB_PORT_CM_SUP;

	props->gid_tbl_len = 1;
	props->pkey_tbl_len = 1;
	props->active_width = 1;
	props->active_speed = IB_SPEED_DDR; //KYS: check
	props->max_msg_sz = -1;

	return 0;
}

static enum rdma_link_layer
hvnd_get_link_layer(struct ib_device *device, u8 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

static ssize_t hvnd_show_rev(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	return 0;
}

static ssize_t hvnd_show_fw_ver(struct device *dev, struct device_attribute *attr,
			   char *buf)
{
	return 0;
}

static ssize_t hvnd_show_hca(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	return 0;
}

static ssize_t hvnd_show_board(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	return 0; 
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
static int hvnd_get_port_immutable(struct ib_device *ibdev, u8 port_num, struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = hvnd_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;

	return 0;
}
#endif

static struct ib_qp *hvnd_ib_create_qp(struct ib_pd *pd, struct ib_qp_init_attr *attrs,
			     struct ib_udata *udata)
{
	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	struct mlx4_ib_create_qp ucmd;
	struct hvnd_qp *qp;
	int ret = 0;
	struct hvnd_ib_pd *hvnd_pd = to_nd_pd(pd);
	struct hvnd_cq *send_cq = to_nd_cq(attrs->send_cq); 
	struct hvnd_cq *recv_cq = to_nd_cq(attrs->recv_cq); 

	uctx = get_uctx_from_pd(pd);
	nd_dev = to_nd_dev(pd->device);

	if (attrs->qp_type != IB_QPT_RC)
	{
		hvnd_error("attrs->qp_type=%d not IB_QPT_RC\n", attrs->qp_type);
		return ERR_PTR(-EINVAL);
	}

	qp = kzalloc(sizeof *qp, GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		goto err_done;
	}

	qp->uctx = uctx;

	if (ib_copy_from_udata(&ucmd, udata, sizeof ucmd)) {
		hvnd_error("ib_copy_from_udata failed\n");
		ret = -EFAULT;
		goto err_ucpy;
	}

	qp->qp_buf = (void *)ucmd.buf_addr;
	qp->db_addr = (void *)ucmd.db_addr;
	qp->log_sq_bb_count = ucmd.log_sq_bb_count;
	qp->log_sq_stride = ucmd.log_sq_stride;
	qp->sq_no_prefetch = ucmd.sq_no_prefetch;
	qp->port = attrs->port_num;

	init_waitqueue_head(&qp->wait);
	atomic_set(&qp->refcnt, 1);


	qp->recv_cq = recv_cq;
	qp->send_cq = send_cq;
	qp->nd_dev = nd_dev;

	qp->receive_cq_handle = recv_cq->cq_handle; 
	qp->initiator_cq_handle = send_cq->cq_handle; 
	qp->pd_handle = hvnd_pd->handle; 
	qp->cq_notify = false;

	qp->ibqp.qp_num = attrs->qp_type == IB_QPT_SMI ? 0 : 1;

	qp->max_inline_data = attrs->cap.max_inline_data;

	qp->initiator_q_depth = attrs->cap.max_send_wr;
	qp->initiator_request_sge = attrs->cap.max_send_sge;


	qp->receive_q_depth = attrs->cap.max_recv_wr;
	qp->receive_request_sge = attrs->cap.max_recv_sge;

	set_rq_size(nd_dev, &attrs->cap, qp);

	set_user_sq_size(nd_dev, qp, &ucmd);

	qp->umem = ib_umem_get(&uctx->ibucontext, ucmd.buf_addr,
				qp->buf_size, 0, 0);
		if (IS_ERR(qp->umem)) {
		ret = PTR_ERR(qp->umem);
		hvnd_error("ib_umem_get failed ret=%d\n", ret);
		goto err_ucpy;
	}

	ret =  hvnd_db_map_user(uctx, ucmd.db_addr, &qp->db_umem);

	if (ret) {
		hvnd_error("hvnd_db_map_user failed ret=%d\n", ret);
		goto err_db_map;
	}

	ret = hvnd_create_qp(nd_dev, uctx, qp);

	if (ret) {
		hvnd_error("hvnd_create_qp failed ret=%d\n", ret);
		goto err_qp;
	}

	hvnd_acquire_uctx_ref(uctx);

	qp->ibqp.qp_num = qp->qpn;
	qp->ibqp.qp_type = IB_QPT_RC; 


	return &qp->ibqp;

err_qp:
	hvnd_db_unmap_user(uctx, ucmd.db_addr);

err_db_map:
	ib_umem_release(qp->umem);

err_ucpy:
	kfree(qp);
err_done:
	return ERR_PTR(ret);
}

static int hvnd_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			     int attr_mask, struct ib_udata *udata)
{
	struct hvnd_qp *qp = to_nd_qp(ibqp);
	struct hvnd_dev *nd_dev = to_nd_dev(ibqp->device);
	enum ib_qp_state cur_state, new_state;
	int ret = 0;

	if (attr != NULL) {

	        cur_state = attr_mask & IB_QP_CUR_STATE ? attr->cur_qp_state : qp->qp_state;
	   	new_state = attr_mask & IB_QP_STATE ? attr->qp_state : cur_state;

		hvnd_debug("qp->qp_state is %d new state is %d\n", qp->qp_state, new_state);
		hvnd_debug("current qp state is %d\n", cur_state);
		if (attr_mask & IB_QP_STATE) {
			/* Ensure the state is valid */
			if (attr->qp_state < 0 || attr->qp_state > IB_QPS_ERR) 
			{
				hvnd_error("incorrect qp state attr->qp_state=%d\n", attr->qp_state);
				return EINVAL;
			}

			if (qp->qp_state != new_state) {
				qp->qp_state = new_state;
				/*
			 	* The only state transition supported is the transition to
			 	* error state.
			 	*/
				switch (new_state) {
				case IB_QPS_ERR:
				case IB_QPS_SQD:
					ret = hvnd_flush_qp(nd_dev, qp->uctx, qp);

					if (ret)
						hvnd_error("hvnd_flush_qp failed ret=%d\n", ret);

					// immediately notify the upper layer on disconnection
					if (!ret && qp->connector)
						hvnd_process_notify_disconnect(qp->connector, STATUS_SUCCESS);

					return ret;

				default:
					break;
				}
			}
		}
	}
	return 0;
}


static int hvnd_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_qp_init_attr *init_attr)
{
	struct hvnd_qp *qp = to_nd_qp(ibqp);

	memset(attr, 0, sizeof *attr);
	memset(init_attr, 0, sizeof *init_attr);

	attr->qp_state = qp->qp_state;

	init_attr->cap.max_send_wr = qp->max_send_wr;
	init_attr->cap.max_recv_wr = qp->max_recv_wr;

	init_attr->cap.max_send_sge = qp->max_send_sge;
	init_attr->cap.max_recv_sge = qp->max_recv_sge;
	init_attr->cap.max_inline_data = qp->max_inline_data;

	init_attr->sq_sig_type = IB_SIGNAL_ALL_WR;

	return 0;
}

static void hvnd_refuse_connection(struct hvnd_ep_obj *connector, int status);
static int hvnd_destroy_qp(struct ib_qp *ib_qp)
{
	int ret;
	struct hvnd_qp *qp = to_nd_qp(ib_qp);
	struct hvnd_dev *nd_dev = to_nd_dev(ib_qp->device);
	u64 jiffies;

	if (!qp->connector) {
		hvnd_warn("error: connector is NULL; skip destroying connector\n");
		goto free_qp;
	}

	/* should we flush the qp first on ctrl-C? , no need to disconnect on abrupt shutdown?*/
	if(qp->qp_state != IB_QPS_ERR && qp->qp_state != IB_QPS_SQD) {
		hvnd_warn("qp_state=%d, doing abrupt disconnect\n", qp->qp_state);
		hvnd_flush_qp(nd_dev, qp->uctx, qp);

		ep_stop(qp->connector);

		// now no pending activity is possible on the connector

		switch (qp->connector->cm_state) {

		case hvnd_cm_idle:
		case hvnd_cm_connect_reply_refused:
		case hvnd_cm_connect_request_sent:
		case hvnd_cm_close_sent:
			hvnd_warn("cm_state = %d not doing anything\n", qp->connector->cm_state);
			break;

		case hvnd_cm_connect_received:
			hvnd_warn("cm_state = %d refusing pending connection request\n", qp->connector->cm_state);
			hvnd_refuse_connection(qp->connector, -ECONNREFUSED);
			break;

		case hvnd_cm_connect_reply_sent:
		case hvnd_cm_established_sent:
		case hvnd_cm_accept_sent:
			hvnd_warn("cm_state = %d notifying disconnect on existing connection\n", qp->connector->cm_state);
			hvnd_process_notify_disconnect(qp->connector, STATUS_CANCELLED);
			break;

		default:
			hvnd_error("unknown cm_state = %d\n", qp->connector->cm_state);

		}
		goto free_connector;
	} else {
		hvnd_debug("qp_state=%d, doing normal disconnect\n", qp->qp_state);
	}

	if (!ep_add_work_pending(qp->connector))
		goto free_connector;

	init_completion(&qp->connector->disconnect_event);

	/*
	 * First issue a disconnect on the connector.
	 */

	hvnd_debug("calling hvnd_connector_disconnect\n");
	ret = hvnd_connector_disconnect(nd_dev, qp->uctx,
					qp->connector->ep_handle,
					qp->connector);
	if (ret) {
		ep_del_work_pending(qp->connector);
		hvnd_error("disconnect: retval is %d\n", ret);
		ep_stop(qp->connector);
		goto free_connector;
	}
	/*
	 * Now wait for the disconnect.
	 */
	jiffies = get_jiffies_64();
	if (!wait_for_completion_timeout(&qp->connector->disconnect_event, 30*HZ)) {
		hvnd_warn("connector disconnect timed out\n");
	}
	hvnd_debug("Completed disconnect connector=%p jiffies=%llu\n", qp->connector, get_jiffies_64() - jiffies);

	/*
	 * Now free up the connector and drop the reference on uctx.
	 */

	ep_stop(qp->connector);

free_connector:
	hvnd_debug("destroying connector handle: %p\n", (void *) qp->connector->ep_handle);
	hvnd_free_handle(nd_dev, qp->uctx,
			 qp->connector->ep_handle,
			 IOCTL_ND_CONNECTOR_FREE);

	hvnd_drop_uctx_ref(nd_dev, qp->uctx);
	hvnd_destroy_ep(qp->connector);
	qp->connector = NULL;
free_qp:
	atomic_dec(&qp->refcnt);
	hvnd_debug("Waiting for the ref cnt to go to 0\n");

	wait_event(qp->wait, !atomic_read(&qp->refcnt));

	hvnd_debug("About to destroy qp\n");
	hvnd_db_unmap_user(qp->uctx, (u64)qp->db_addr);
	ib_umem_release(qp->umem);

	hvnd_debug("About to free qp\n");
	ret = hvnd_free_qp(nd_dev, qp->uctx, qp);

	if (ret == 0) {
		hvnd_drop_uctx_ref(nd_dev, qp->uctx);
		kfree(qp);
	} else {
		hvnd_error("free qp failed: ret is %d\n", ret);
	}

	return ret;
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
static struct ib_cq *hvnd_ib_create_cq(struct ib_device *ibdev,
				       const struct ib_cq_init_attr *attr,
				       struct ib_ucontext *ib_context,
				       struct ib_udata *udata)
#else
static struct ib_cq *hvnd_ib_create_cq(struct ib_device *ibdev, int entries,
				    int vector, struct ib_ucontext *ib_context,
				    struct ib_udata *udata)
#endif
{
	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	struct mlx4_ib_create_cq ucmd;
	struct hvnd_cq *cq;
	int ret = 0;
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
	int entries = attr->cqe;
#endif

	uctx = to_nd_context(ib_context);
	nd_dev = to_nd_dev(ibdev);

	if (entries < 1 || entries > uctx->max_cqe) {
		hvnd_error("incorrct entries=%d\n", entries);
		ret = -EINVAL;
		goto err_done;
	}

	cq = kzalloc(sizeof *cq, GFP_KERNEL);
	if (!cq) {
		ret = -ENOMEM;
		goto err_done;
	}

	entries      = roundup_pow_of_two(entries + 1);
	cq->ibcq.cqe = entries - 1;
	cq->entries = entries;
	cq->uctx = uctx;

	if (ib_copy_from_udata(&ucmd, udata, sizeof ucmd)) {
		hvnd_error("ib_copy_from_udata failed\n");
		ret = -EFAULT;
		goto err_ucpy;
	}

	cq->cq_buf = (void *)ucmd.buf_addr;
	cq->db_addr = (void *)ucmd.db_addr;
	cq->arm_sn = 0; 

	/*
	 * Initialize the IRP state. Need to have a separate irp state
	 * for CQ; for now share it with Listener/connector.
	 */
	ret = hvnd_init_ep(&cq->ep_object, NULL, ND_CQ, nd_dev, uctx);

	if (ret) {
		hvnd_error("hvnd_init_ep failed ret=%d\n", ret);
		goto  err_ucpy;
	}

	cq->ep_object.cq = cq;
	cq->monitor = true;

	cq->umem = ib_umem_get(ib_context, ucmd.buf_addr,
				(entries * uctx->cqe_size),
				IB_ACCESS_LOCAL_WRITE, 1);
		if (IS_ERR(cq->umem)) {
		ret = IS_ERR(cq->umem);
		hvnd_error("ib_umem_get failed ret=%d\n", ret);
		goto err_ucpy;
	}

	ret =  hvnd_db_map_user(uctx, ucmd.db_addr, &cq->db_umem);

	if (ret) {
		hvnd_error("hvnd_db_map_user failed ret=%d\n", ret);
		goto err_db_map;
	}

	ret = hvnd_create_cq(nd_dev, uctx, cq);

	if (ret) {
		hvnd_error("hvnd_create_cq failed ret=%d\n", ret);
		goto err_cq;
	}

	cq->ep_object.ep_handle = cq->cq_handle;

	if (ib_copy_to_udata(udata, &cq->cqn, sizeof (__u32))) {
		hvnd_error("ib_copy_to_udata failed\n");
		ret = -EFAULT;
		goto err_ucpy_out;
	}

	if (!disable_cq_notify) {

		if (!ep_add_work_pending(&cq->ep_object))
			goto err_ucpy_out;

		ret = hvnd_notify_cq(nd_dev, cq, ND_CQ_NOTIFY_ANY,
			     (u64)&cq->ep_object);

		if (ret) {
			ep_del_work_pending(&cq->ep_object);
			hvnd_error("hvnd_notify_cq failed ret=%d\n", ret);
			goto err_ucpy_out;
		}
	}

	hvnd_acquire_uctx_ref(uctx);

	return &cq->ibcq;

err_ucpy_out:
	hvnd_destroy_cq(nd_dev, cq);

err_cq:
	hvnd_db_unmap_user(uctx, ucmd.db_addr);

err_db_map:
	ib_umem_release(cq->umem);

err_ucpy:
	kfree(cq);
err_done:
	return ERR_PTR(ret);
}

static struct ib_qp *hvnd_get_qp(struct ib_device *dev, int qpn)
{
	struct hvnd_dev *nd_dev;
	struct hvnd_qp *qp = NULL;

	nd_dev = to_nd_dev(dev);
	qp = get_qpp(nd_dev, qpn);
	return (qp?&qp->ibqp:NULL);
}

static int hvnd_ib_destroy_cq(struct ib_cq *ib_cq)
{
	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	struct hvnd_cq *cq;

	cq = to_nd_cq(ib_cq);
	uctx = cq->uctx;
	nd_dev = to_nd_dev(uctx->ibucontext.device);

	cq->monitor = false;

//	hvnd_cancel_io(&cq->ep_object);
	ep_stop(&cq->ep_object);

	hvnd_deinit_ep(&cq->ep_object);

	hvnd_db_unmap_user(uctx, (u64)cq->db_addr);
	ib_umem_release(cq->umem);

	hvnd_destroy_cq(nd_dev, cq);

	hvnd_drop_uctx_ref(nd_dev, uctx);
	kfree(cq);

	return 0;
}

static int hvnd_resize_cq(struct ib_cq *cq, int cqe, struct ib_udata *udata)
{
	/*
	 * NDDirect does not support resizing CQ.
	 */
	hvnd_info("check code\n");
	return -ENOSYS;
}

static int hvnd_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	hvnd_info("check code\n");
	return 0;
}

static struct ib_mr *hvnd_get_dma_mr(struct ib_pd *pd, int acc)
{
	hvnd_info("check code\n");
	return NULL;
}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
static struct ib_mr *hvnd_register_phys_mem(struct ib_pd *pd,
					    struct ib_phys_buf *buffer_list,
					    int num_phys_buf, int acc,
					    u64 *iova_start)
{
	hvnd_info("check code\n");
	return NULL;
}

int hvnd_reregister_phys_mem(struct ib_mr *mr, int mr_rereg_mask,
			     struct ib_pd *pd, struct ib_phys_buf *buffer_list,
			     int num_phys_buf, int acc, u64 *iova_start)
{
	hvnd_info("check code\n");
	return 0;
}

static int hvnd_bind_mw(struct ib_qp *qp, struct ib_mw *mw,
			struct ib_mw_bind *mw_bind)
{
	hvnd_info("check code\n");
	return -ENOSYS;
}

static struct ib_mr *hvnd_alloc_fast_reg_mr(struct ib_pd *pd, int pbl_depth)
{
	debug_check(__func__, __LINE__);
	return NULL;
}

static struct ib_fast_reg_page_list *
hvnd_alloc_fastreg_pbl(struct ib_device *device,
			int page_list_len)
{
	debug_check(__func__, __LINE__);
	return NULL;
}

void hvnd_free_fastreg_pbl(struct ib_fast_reg_page_list *ibpl)
{
	debug_check(__func__, __LINE__);
}

static int hvnd_get_mib(struct ib_device *ibdev,
			union rdma_protocol_stats *stats)
{
	return 0;
}
#endif

static void debug_dump_umem(struct ib_umem *umem)
{
#ifdef HVND_MEM_DEBUG
	struct ib_umem_chunk *chunk;
	struct scatterlist *sg;
	int len, j, entry;
	int shift = ffs(umem->page_size) - 1;

	hvnd_debug("umem=%p\n", umem);
	hvnd_debug("context=%p length=%lu offset=%d page_size=%d writable=%d hugetlb=%d\n",
		umem->context,
		umem->length,
		umem->offset,
		umem->page_size,
		umem->writable,
		umem->hugetlb);

	list_for_each_entry(chunk, &umem->chunk_list, list) {
		hvnd_debug("chunk->nmap=%d\n", chunk->nmap);
		for (j = 0; j < chunk->nmap; ++j) {
			sg = &chunk->page_list[j];
			hvnd_debug("sg_dma_len=%d sg_dma_address=%llx\n", sg_dma_len(sg), sg_dma_address(sg));
			hvnd_debug("page_link=%lx offset=%u length=%u\n", sg->page_link, sg->offset, sg->length);
			len = sg_dma_len(&chunk->page_list[j]) >> shift;
			for_each_sg(&chunk->page_list[j], sg, len, entry) {
				hvnd_debug("PFN=%lu\n", page_to_pfn(sg_page(sg)));
			}
		}
	}
#endif
}


static struct ib_mr *hvnd_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt, int acc, struct ib_udata *udata)
{
	int err = 0;
	struct hvnd_ib_pd *hvndpd = to_nd_pd(pd);
	struct hvnd_mr *mr;

	mr = kmalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		return ERR_PTR(-ENOMEM);
	}
	mr->pd = hvndpd;

	mr->umem = ib_umem_get(pd->uobject->context, start, length, acc, 0);
	if (IS_ERR(mr->umem)) {
		err = PTR_ERR(mr->umem);
		hvnd_error("ib_umem_get failed ret=%d\n", err);
		kfree(mr);
		return ERR_PTR(err);
	}

	debug_dump_umem(mr->umem);

	mr->start = start;
	mr->length = length;
	mr->virt = virt;
	mr->acc = acc;

	hvnd_debug("start=%llx length=%llx virt=%llx acc=%d\n", start, length, virt, acc);

	/*
	 * First create a memory region.
	 */
	err = hvnd_cr_mr(to_nd_dev(pd->device),
			to_nd_context(pd->uobject->context), hvndpd->handle,
			&mr->mr_handle);
	if (err) {
		hvnd_error("cr_mr failed; ret is %d\n", err);
		goto err;
	}

	err =  hvnd_mr_register(to_nd_dev(pd->device),
				to_nd_context(pd->uobject->context), mr);

	if (err)
		goto err0;

	hvnd_acquire_uctx_ref(to_nd_context(pd->uobject->context));

	return &mr->ibmr;

err0:
	hvnd_free_mr(to_nd_dev(pd->device),
		to_nd_context(pd->uobject->context), mr->mr_handle);
err:
	ib_umem_release(mr->umem);
	kfree(mr);
	return ERR_PTR(err);
}



static int hvnd_dereg_mr(struct ib_mr *ib_mr)
{
	int ret;
	struct hvnd_mr *mr = to_nd_mr(ib_mr);
	struct hvnd_ucontext *uctx = to_nd_context(ib_mr->pd->uobject->context);
	struct hvnd_dev *nd_dev = to_nd_dev(ib_mr->device);

	
	hvnd_debug("dereg_mr entering\n");

	ret = hvnd_deregister_mr(nd_dev, uctx, mr->mr_handle);

	if (ret) {
		hvnd_error("hvnd_deregister_mr() failed: %x\n", ret);
		return ret;
	}
	/*
	 * Now free up the memory region.
	 */

	ret = hvnd_free_mr(nd_dev, uctx, mr->mr_handle);
	if (ret) {
		hvnd_error("hvnd_free_mr() failed: %x\n", ret);
		return ret;
	}

	ib_umem_release(mr->umem);

	hvnd_drop_uctx_ref(nd_dev, uctx);
	kfree(mr);
	
	hvnd_debug("dereg_mr done\n");
	return 0;
}

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,5)
static struct ib_mw *hvnd_alloc_mw(struct ib_pd *pd)
#elif RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3)
static struct ib_mw *hvnd_alloc_mw(struct ib_pd *pd, enum ib_mw_type type)
#else
static struct ib_mw *hvnd_alloc_mw(struct ib_pd *pd, enum ib_mw_type type, struct ib_udata *udata)
#endif
{
	hvnd_info("check code\n");
	return NULL;
}

static int hvnd_dealloc_mw(struct ib_mw *mw)
{
	debug_check(__func__, __LINE__);
	return 0;
}

static int hvnd_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct hvnd_ucontext *uctx;
	struct hvnd_dev *nd_dev;
	struct hvnd_cq *cq;

	cq = to_nd_cq(ibcq);
	uctx = cq->uctx;
	nd_dev = to_nd_dev(uctx->ibucontext.device);


	debug_check(__func__, __LINE__);

	return 0;
}

static int hvnd_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
			  struct ib_send_wr **bad_wr)
{
	debug_check(__func__, __LINE__);
	return 0;
}

int hvnd_post_receive(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	debug_check(__func__, __LINE__);
	return 0;
}

static int hvnd_resolve_addr(struct sockaddr_in *laddr, struct sockaddr_in *raddr,
			     struct if_physical_addr *phys_addrstruct)
{
	int ret;

	phys_addrstruct->length = ETH_ALEN;
	ret = hvnd_get_neigh_mac_addr((struct sockaddr *)laddr, 
					(struct sockaddr *)raddr,
					phys_addrstruct->addr);

	hvnd_debug("Dest MAC is %pM\n", phys_addrstruct->addr);
	return ret;
}
	
static int hvnd_connect(struct iw_cm_id *cm_id,
			struct iw_cm_conn_param *conn_param)
{
	int ret = 0;
	struct hvnd_dev *nd_dev;
	struct hvnd_ep_obj  *ep_object;
	struct sockaddr_in *raddr = (struct sockaddr_in *)&cm_id->remote_addr;
	struct sockaddr_in *laddr = (struct sockaddr_in *)&cm_id->local_addr;
	struct hvnd_qp *qp;
	struct if_physical_addr phys_addrstruct;
	union nd_sockaddr_inet dest_addr;
	u64 connector_handle;
	union nd_sockaddr_inet addr;
	char addr_buf[50];

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	if (cm_id->remote_addr.sin_family != AF_INET) {
		hvnd_error("cm_id->remote_addr.ss_family=%d not AF_INET\n", cm_id->remote_addr.sin_family);
#else
	if (cm_id->remote_addr.ss_family != AF_INET) {
		hvnd_error("cm_id->remote_addr.ss_family=%d not AF_INET\n", cm_id->remote_addr.ss_family);
#endif
		return -ENOSYS;
	}

	qp = get_qpp(to_nd_dev(cm_id->device), conn_param->qpn);

	if (!qp)
	{
		hvnd_error("failed to find qp conn_param->qpn=%d\n", conn_param->qpn);
		return -EINVAL;
	}

	cm_id->provider_data = qp;
	cm_id->add_ref(cm_id);
	qp->cm_id = cm_id;

	/*
	 * Set the read/write limits.
	 * Can we change the limits on a created QP? Luke?
	 */
	nd_dev = to_nd_dev(cm_id->device);
	ep_object = hvnd_setup_ep(cm_id, ND_CONNECTOR, nd_dev, qp->uctx);
	hvnd_debug("active connection: local irp is %d\n", ep_object->local_irp);
	if (!ep_object) {
		hvnd_error("hvnd_setup_ep failure\n");
		ret = -ENOMEM;
		goto err_limit;
	}

	ret = hvnd_cr_connector(nd_dev, qp->uctx,
				&connector_handle);

	if (ret) {
		hvnd_error("hvnd_cr_connector failure ret=%d\n", ret);
		goto err_cr_connector;
	}

	hvnd_acquire_uctx_ref(qp->uctx);
	ep_object->ep_handle = connector_handle;
	ep_object->incoming = false;
	qp->connector = ep_object;

	/*
	 * Bind the local address to the connector.
	 */
	hvnd_debug("Connect local address is %s\n", debug_inet_ntoa(laddr->sin_addr, addr_buf));

	memcpy(&addr.ipv4, laddr, sizeof(struct sockaddr_in));
	hvnd_debug("CONNECT AF %d port %d addr %s\n", addr.ipv4.sin_family, addr.ipv4.sin_port, debug_inet_ntoa(addr.ipv4.sin_addr, addr_buf));

	ret = hvnd_bind_connector(nd_dev, qp->uctx,
				connector_handle,
				&addr);

	if (ret) {
		hvnd_error("hvnd_bind_connector failed ret=%d\n", ret);
		goto err_bind_connector;
	}

	ret = hvnd_resolve_addr(laddr, raddr, &phys_addrstruct);
	if (ret) {
		hvnd_error("hvnd_resolve_addr failed ret=%d\n", ret);
		goto err_bind_connector;
	}

	memcpy(&dest_addr.ipv4, raddr, sizeof(struct sockaddr_in));



	/*
	 * Now attempt to connect.
	 */

	hvnd_debug("About to initiate connection\n");

	if (!ep_add_work_pending(ep_object))
		goto err_bind_connector;

	ep_object->cm_state = hvnd_cm_connect_received;
	ret = hvnd_connector_connect(nd_dev, qp->uctx,
					ep_object->ep_handle,
					conn_param->ird, conn_param->ord,
					conn_param->private_data_len,
					(u8 *)conn_param->private_data,
					qp->qp_handle, 
					&phys_addrstruct, &dest_addr,
					ep_object);

	if (ret == 0) {
		return 0;
	} else {
		ep_object->cm_state = hvnd_cm_idle;
		ep_del_work_pending(ep_object);
		hvnd_error("hvnd_connector_connect failed ret=%d\n", ret);
	}

err_bind_connector:
	qp->connector = NULL;
	hvnd_free_connector(nd_dev, qp->uctx,
			    connector_handle);
	hvnd_drop_uctx_ref(nd_dev, qp->uctx);

err_cr_connector:
	kfree(ep_object);

err_limit:
	cm_id->provider_data = NULL;
	qp->cm_id = NULL;
	cm_id->rem_ref(cm_id);
	return ret;
}

static int hvnd_accept_cr(struct iw_cm_id *cm_id,
			  struct iw_cm_conn_param *conn_param)
{
	int ret = 0;
	struct hvnd_dev *nd_dev;
	struct hvnd_qp *qp;
	struct hvnd_ep_obj *connector;
	enum ibv_qp_state new_qp_state;

	hvnd_debug("Accepting connection - PASSIVE\n");
	nd_dev = to_nd_dev(cm_id->device);
	qp = get_qpp(to_nd_dev(cm_id->device), conn_param->qpn);

	if (!qp) {
		hvnd_error("get_qpp failed conn_param->qpn=%d\n", conn_param->qpn);
		return -EINVAL;
	}


	connector = (struct hvnd_ep_obj *)cm_id->provider_data;
	qp->connector = connector;

	if (connector == NULL) {
		hvnd_error("NULL connector!\n");
		return -EINVAL;
	}
	hvnd_debug("connector's cm_id is %p caller cm_id=%p\n", connector->cm_id, cm_id);

	connector->cq = qp->recv_cq;


	/*
	 * Setup state for the accepted connection.
	 */
	cm_id->add_ref(cm_id);
	connector->cm_id = cm_id;
        if (conn_param == NULL) {
                hvnd_error("NULL conn_param!\n");
                return -EINVAL;
        }

        connector->ord = conn_param->ord;
        connector->ird = conn_param->ird;

	if (!ep_add_work_pending(connector))
		goto error;

	init_completion(&connector->connector_accept_event);

	ret = hvnd_connector_accept(nd_dev, qp->uctx, connector->ep_handle,
				    qp->qp_handle, conn_param->ird,
				    conn_param->ord, conn_param->private_data_len,
				    conn_param->private_data,
				    &new_qp_state, connector); 

	if (ret) {
		ep_del_work_pending(connector);
		hvnd_error("connector accept failed\n");
		goto error;
	}

	wait_for_completion(&connector->connector_accept_event);
	ret = connector->connector_accept_status;

	if(ret) {
		hvnd_error("connector_accept failed status=%x\n", ret);
		ret = -EIO;
		goto error;
	}

	hvnd_debug("Passive Connection Accepted; new qp state is %d\n", new_qp_state);
	connector->cm_state = hvnd_cm_accept_sent;
	return 0;

error:
	ep_stop(connector);
	connector->cm_id = NULL;
	connector->cm_state = hvnd_cm_idle;

	qp->connector = NULL;
	cm_id->rem_ref(cm_id);

	return ret;
}

static int hvnd_reject_cr(struct iw_cm_id *cm_id, const void *pdata,
			  u8 pdata_len)
{
	debug_check(__func__, __LINE__);
	return 0;
}

void hvnd_process_disconnect(struct hvnd_ep_obj *ep_object, int status)
{
	struct iw_cm_event cm_event;

	switch (status) {
	case STATUS_SUCCESS:
	case STATUS_CANCELLED:
		break;

	default:
		hvnd_warn("disconnect complete failed: status:%d\n", status);
	}


	hvnd_debug("active disconnect processed\n");
	memset(&cm_event, 0, sizeof(cm_event));

	complete(&ep_object->disconnect_event);
}


void hvnd_process_notify_disconnect(struct hvnd_ep_obj *ep_object, int status)
{
	struct iw_cm_event cm_event;

	// make sure we only disconnect once
	if (atomic_xchg(&ep_object->disconnect_notified, 1))
		return;

	/*
	 * Turn off CQ monitoring.
	 */
	if (ep_object->cq)
		ep_object->cq->monitor = false;

	switch(ep_object->cm_state) {
		case hvnd_cm_connect_reply_sent:
		case hvnd_cm_established_sent:
		case hvnd_cm_accept_sent:
			break;

		default:
			hvnd_error("unexpected cm_state=%d\n", ep_object->cm_state);
			return;
	}

	switch (status) {
	case STATUS_SUCCESS:
	case STATUS_CANCELLED:
	case STATUS_DISCONNECTED:
		break;

	default:
		hvnd_warn("notify disconnect complete failed: status:%d\n", status);
	}

	hvnd_debug("passive disconnect notified\n");
	memset(&cm_event, 0, sizeof(cm_event));

	/*
	 * Other end disconnected.
	 * Connection has been disconnected; 
	 * notify the cm layer.
	 */
	cm_event.status = -ECONNRESET;
	cm_event.event = IW_CM_EVENT_CLOSE;

	if ((ep_object->cm_id) &&
	    (ep_object->cm_id->event_handler)) {

		ep_object->cm_id->event_handler(ep_object->cm_id, &cm_event);

		ep_object->cm_id->rem_ref(ep_object->cm_id);
		ep_object->cm_state = hvnd_cm_close_sent;
	}
}

void hvnd_process_connector_accept(struct hvnd_ep_obj *ep_object, int status)
{
	struct iw_cm_event cm_event;
	int ret;

	/* this is the problem area the return status may be 
	   1: 0xc00000b5 (3221225653) - {Device Timeout}  The specified I/O operation on %hs was not completed before the time-out period expired
	   2: NTSTATUS 0xc0000241 (3221226049) - The transport connection was aborted by the local system.
	 if we do nothing here, iwcm will wait for IW_CM_EVENT_ESTABLISHED forever, and unable to clean shutdown
	 need to fail the call eariler on accept 
	*/

	ep_object->connector_accept_status = status;

	if (status) {
		hvnd_error("Connector accept failed; status is %x\n", status);
		complete(&ep_object->connector_accept_event);
		return;
	}

	memset(&cm_event, 0, sizeof(cm_event));
	cm_event.event = IW_CM_EVENT_ESTABLISHED;
	cm_event.ird = ep_object->ird;
	cm_event.ord = ep_object->ord;
	cm_event.provider_data = (void*)ep_object;

	/*
	 * We have successfully passively accepted the
	 * incoming connection.
	 */

	hvnd_debug("Passive connection accepted!!\n");
	if ((ep_object->cm_id) &&
	    (ep_object->cm_id->event_handler)) {
		ep_object->cm_id->event_handler(ep_object->cm_id, &cm_event);
		ep_object->cm_state = hvnd_cm_established_sent;
	}

	complete(&ep_object->connector_accept_event);

	/*
	 * Request notification if the other end
	 * were to disconnect.
	 */
	if (!ep_add_work_pending(ep_object))
		return;

	ret = hvnd_connector_notify_disconnect(ep_object->nd_dev,
						   ep_object->uctx,
						   ep_object->ep_handle,
						   ep_object);

	if (ret) {
		ep_del_work_pending(ep_object);
		hvnd_error("Connector notify disconnect failed; ret: %d\n", ret);
	}
}


void hvnd_process_cq_event_pending(struct hvnd_ep_obj *ep_object,
					 int status)
{

	struct ib_cq *ibcq;
	struct hvnd_cq *cq;

	cq = ep_object->cq;
	ibcq = &ep_object->cq->ibcq;

	if (!cq->monitor)
		return;

	// call the previous CQ complete
	if (status == STATUS_PENDING && cq->upcall_pending && ibcq->comp_handler) {
		ibcq->comp_handler(ibcq, ibcq->cq_context);
		cq->upcall_pending = false;
		hvnd_debug("CQ comp_handler called arm_sn=%d\n", cq->arm_sn);
//		printk_ratelimited("CQ comp_handler called arm_sn=%d\n", cq->arm_sn);
	}

	if (status != STATUS_PENDING && ibcq->comp_handler && ibcq->cq_context) {
		ibcq->comp_handler(ibcq, ibcq->cq_context);
		hvnd_error("CQ comp_handler called status=%x\n", status);
	} 
}

void hvnd_process_cq_event_complete(struct hvnd_ep_obj *ep_object,
					 int status)
{
	struct ib_cq *ibcq;
	struct hvnd_cq *cq;
	int ret;

	cq = ep_object->cq;
	ibcq = &ep_object->cq->ibcq;

	// call hte previous CQ complete
	if(cq->upcall_pending && ibcq->comp_handler){
		ibcq->comp_handler(ibcq, ibcq->cq_context);
		cq->upcall_pending = false;
		hvnd_debug("CQ comp_handler called arm_sn=%d\n", cq->arm_sn);
//		printk_ratelimited("CQ comp_handler called arm_sn=%d\n", cq->arm_sn);
	}

	cq->upcall_pending = true;
	if (!ep_add_work_pending(ep_object))
		return;

	ret = hvnd_notify_cq(ep_object->nd_dev,
			ep_object->cq,
			ND_CQ_NOTIFY_ANY,
    			(u64)ep_object);

	if (ret) {
		ep_del_work_pending(ep_object);
//		hvnd_manage_io_state(ep_object, true);
		hvnd_error("hvnd_notify_cq failed ret=%d\n", ret);
	}

	if ((status != 0) && (status != STATUS_CANCELLED)) {
		if (ibcq->event_handler) {
			struct ib_event event;
			event.device = ibcq->device;
			event.event = IB_EVENT_CQ_ERR;
			event.element.cq = ibcq;
			ibcq->event_handler(&event, ibcq->cq_context);

			hvnd_warn("CQ event_handler called status=%x\n", status);
		}
	}
}

int init_cm_event(struct hvnd_ep_obj *ep_object, struct iw_cm_event *cm_event,
		  int event)
{
	struct sockaddr_in *laddr = (struct sockaddr_in *)&cm_event->local_addr;
	struct sockaddr_in *raddr = (struct sockaddr_in *)&cm_event->remote_addr;
	struct nd_read_limits rd_limits;
	union nd_sockaddr_inet local_addr;
	union nd_sockaddr_inet remote_addr;
	int ret;

	/*
	 * Now get the local address.
	 */
	ret = hvnd_connector_get_local_addr(ep_object->nd_dev,
					    ep_object->uctx,
					    ep_object->ep_handle,
					    &local_addr);

	if (ret) {
		hvnd_error("Connector get addr failed; ret: %d\n", ret);
		return ret;
	}
	/*
	 * Now get the remote address.
	 */
	ret = hvnd_connector_get_peer_addr(ep_object->nd_dev,
					   ep_object->uctx,
					   ep_object->ep_handle,
					   &remote_addr);

	if (ret) {
		hvnd_error("Connector get peer addr failed; ret: %d\n", ret);
		return ret;
	}

	/*
	 * Get other connection parameters.
	 */

	ret = hvnd_connector_get_rd_limits(ep_object->nd_dev,
					   ep_object->uctx,
					   ep_object->ep_handle,
					   &rd_limits);

	if (ret) {
		hvnd_error("Connector rd limits failed; ret: %d\n", ret);
		return ret;
	}
	
	/*
	 * XXXKYS: Luke: What about the length of the priv data?
	 */
	ret = hvnd_connector_get_priv_data(ep_object->nd_dev,
					   ep_object->uctx,
					   ep_object->ep_handle,
					   ep_object->priv_data);

	if (ret) {
		hvnd_error("Connector get priv data failed; ret: %d\n", ret);
		return ret;
	}
	/*
	 * Initialize CM structure.
	 */
	laddr->sin_addr.s_addr = local_addr.ipv4.sin_addr.s_addr;
	hvnd_debug("Local addr is %d\n", laddr->sin_addr.s_addr);
	laddr->sin_port = local_addr.ipv4.sin_port;
	laddr->sin_family = AF_INET;

	raddr->sin_addr.s_addr = remote_addr.ipv4.sin_addr.s_addr;
	hvnd_debug("Remote addr is %d\n", raddr->sin_addr.s_addr);
	raddr->sin_port = remote_addr.ipv4.sin_port;
	raddr->sin_family = AF_INET;

	cm_event->private_data_len = MAX_PRIVATE_DATA_LEN; //KYS; LUke: is it always 148 bytes?
	cm_event->private_data = ep_object->priv_data;

	cm_event->ird = rd_limits.inbound;
	cm_event->ord = rd_limits.outbound;
	cm_event->event = event;

	ep_object->ird = cm_event->ird;
	ep_object->ord = cm_event->ord;

	return 0;
}

static void hvnd_refuse_connection(struct hvnd_ep_obj *connector, int status)
{
	struct iw_cm_event cm_event;

	memset(&cm_event, 0, sizeof(cm_event));

	cm_event.event = IW_CM_EVENT_CONNECT_REPLY;
	cm_event.status = status;

	hvnd_debug("returning status %d on connector %p\n", status, connector);

	if (connector->cm_id && connector->cm_id->event_handler) {
		connector->cm_id->event_handler(connector->cm_id, &cm_event);
		connector->cm_id->rem_ref(connector->cm_id);
		connector->cm_state = hvnd_cm_connect_reply_refused;
	}
}

void hvnd_process_events(struct work_struct *work)
{
	struct hvnd_work *wrk; 
	struct nd_read_limits rd_limits;
	struct hvnd_ep_obj *ep_object;
	struct hvnd_ep_obj *parent;
	struct iw_cm_event cm_event;
	struct sockaddr_in *laddr = (struct sockaddr_in *)&cm_event.local_addr;
	struct sockaddr_in *raddr = (struct sockaddr_in *)&cm_event.remote_addr;
	struct ndv_packet_hdr_control_1 *ctrl_hdr;
	union nd_sockaddr_inet local_addr;
	union nd_sockaddr_inet remote_addr;
	struct pkt_nd_get_connection_listener *connection_pkt;
	struct iw_cm_id *cm_id = NULL;
	int status;
	int ioctl;
	int ret;
	char priv_data[MAX_PRIVATE_DATA_LEN];
	enum ibv_qp_state new_qp_state;
	struct incoming_pkt *incoming_pkt;
	unsigned long flags;

	memset(&cm_event, 0, sizeof(cm_event));
	memset(&priv_data, 0, MAX_PRIVATE_DATA_LEN);


	wrk = container_of(work, struct hvnd_work, work);

	/*
	 * Now call into the connection manager.
	 */
	ep_object = (struct hvnd_ep_obj *)wrk->callback_arg;
	parent = ep_object->parent;

process_next:
	incoming_pkt = NULL;
	spin_lock_irqsave(&ep_object->incoming_pkt_list_lock, flags);
	if (!list_empty(&ep_object->incoming_pkt_list)) {
		incoming_pkt = list_first_entry(&ep_object->incoming_pkt_list, struct incoming_pkt, list_entry);
		list_del(&incoming_pkt->list_entry);
	}
	spin_unlock_irqrestore(&ep_object->incoming_pkt_list_lock, flags);
	if (incoming_pkt == NULL)
		return;

	ctrl_hdr = (struct ndv_packet_hdr_control_1 *)incoming_pkt->pkt;
	status = ctrl_hdr->io_status;
	ioctl = ctrl_hdr->io_cntrl_code;

	hvnd_debug("Process Events IOCTL is: %s; iostatus failure: %x in work queue\n", hvnd_get_op_name(ioctl), status);
	
	if (status != 0) {
		bool log_error = true;

		if (ioctl == IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT && status == STATUS_DISCONNECTED) // expected
			log_error = false;

		if (log_error)
			hvnd_warn("Process Events IOCTL is: %s; iostatus failure: %x\n", hvnd_get_op_name(ioctl), status);
	}

	cm_event.status = status;

	switch (ep_object->type) {
	case ND_CONNECTOR:
		switch (ioctl) {
		case IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST:

			if (ep_object->parent != NULL) {

				// Do nothing with this connection request if listener is stopping
				if (!ep_add_work_pending(ep_object->parent))
					break;

				cm_id = ep_object->parent->cm_id; //Listener
			}

			connection_pkt = (struct pkt_nd_get_connection_listener *) ctrl_hdr;

			if ((status == 0) || (status == STATUS_CANCELLED)) {
				hvnd_get_incoming_connections(ep_object->parent,
				 	ep_object->parent->nd_dev, ep_object->uctx);
			}

			if (status)
				goto get_connection_request_done;

			/*
			 * Now get the local address.
	 		 */
			ret = hvnd_connector_get_local_addr(ep_object->nd_dev,
						     ep_object->uctx,
						     ep_object->ep_handle,
						     &local_addr);

			if (ret) {
				hvnd_error("Connector get addr failed; ret: %d\n", ret);
				goto get_connection_request_done;
			}
			/*
			 * Now get the remote address.
			 */
			ret = hvnd_connector_get_peer_addr(ep_object->nd_dev,
						     ep_object->uctx,
						     ep_object->ep_handle,
						     &remote_addr);

			if (ret) {
				hvnd_error("Connector get peer addr failed; ret: %d\n", ret);
				goto get_connection_request_done;
			}
			/*
			 * Get other connection parameters.
			 */

			ret = hvnd_connector_get_rd_limits(ep_object->nd_dev,
							   ep_object->uctx,
							   ep_object->ep_handle,
							   &rd_limits);

			if (ret) {
				hvnd_error("Connector rd limits failed; ret: %d\n", ret);
				goto get_connection_request_done;
			}
	
			/*
			 * XXXKYS: Luke: What about the length of the priv data?
			 */
			ret = hvnd_connector_get_priv_data(ep_object->nd_dev,
							   ep_object->uctx,
							   ep_object->ep_handle,
							   ep_object->priv_data);

			if (ret) {
				hvnd_error("Connector get priv data failed; ret: %d\n", ret);
				goto get_connection_request_done;
			}

			cm_event.event = IW_CM_EVENT_CONNECT_REQUEST;
			cm_event.provider_data = (void*)ep_object;

			laddr->sin_addr.s_addr = local_addr.ipv4.sin_addr.s_addr;
			hvnd_debug("Local addr is %d\n", laddr->sin_addr.s_addr);
			laddr->sin_port = local_addr.ipv4.sin_port;
			laddr->sin_family = AF_INET;

			raddr->sin_addr.s_addr = remote_addr.ipv4.sin_addr.s_addr;
			hvnd_debug("Remote addr is %d\n", raddr->sin_addr.s_addr);
			raddr->sin_port = remote_addr.ipv4.sin_port;
			raddr->sin_family = AF_INET;

			cm_event.private_data_len = MAX_PRIVATE_DATA_LEN; //KYS; LUke: is it always 148 bytes?
			cm_event.private_data = ep_object->priv_data;

			cm_event.ird = rd_limits.inbound;
			cm_event.ord = rd_limits.outbound;

			ep_object->ird = cm_event.ird;
			ep_object->ord = cm_event.ord;


			if ((cm_id != NULL) && cm_id->event_handler) {
				cm_id->event_handler(cm_id, &cm_event);
				ep_object->cm_state = hvnd_cm_connect_request_sent;
			}

get_connection_request_done:
			if (ep_object->parent != NULL) {

				ep_del_work_pending(ep_object->parent);
			}
			break;

		case IOCTL_ND_CONNECTOR_CONNECT:

			cm_event.event = IW_CM_EVENT_CONNECT_REPLY;
			if(status == STATUS_TIMEOUT && ep_object->connector_connect_retry<3) { //TIMEOUT retry

				if (!ep_add_work_pending(ep_object)) 
					goto refuse_connection;

				hvnd_warn("Connector connect timed out, reconnecting... retry count: %d\n", ep_object->connector_connect_retry);
				ep_object->connector_connect_retry++;
					ret = hvnd_send_ioctl_pkt(ep_object->nd_dev, &ep_object->connector_connect_pkt.hdr,
						sizeof(ep_object->connector_connect_pkt),
		      	    			(u64)&ep_object->connector_connect_pkt);

				if (ret) {
					hvnd_error("Connector on time out failed: %d\n", ret);
					ep_del_work_pending(ep_object);
					goto refuse_connection;
				}
				break;
			}

refuse_connection:
			if (status) {
				cm_event.status = -ECONNREFUSED;
				if (status == STATUS_TIMEOUT)
					cm_event.status = -ETIMEDOUT;

				hvnd_refuse_connection(ep_object, cm_event.status);
				break;
			}

			hvnd_debug("ACTIVE Connection ACCEPTED\n");
			ret = init_cm_event(ep_object, &cm_event, IW_CM_EVENT_CONNECT_REPLY);
			if (ret) {
				hvnd_error("init_cm_event failed ret=%d\n", ret);
				goto process_done;
			}

			ret = hvnd_connector_complete_connect(ep_object->nd_dev,
						ep_object->uctx,
						ep_object->ep_handle,
						&new_qp_state);
			if (ret) {
				hvnd_error("connector_complete failed\n");
				goto process_done;
			}

			cm_event.provider_data = (void*)ep_object;

			if ((ep_object->cm_id) &&
	    			(ep_object->cm_id->event_handler)) {
				ep_object->cm_id->event_handler(ep_object->cm_id, &cm_event);
				ep_object->cm_state = hvnd_cm_connect_reply_sent;
			}
			/*
		 	 * Rquest notification if the other end
		 	 * were to disconnect.
		 	 */
			if (!ep_add_work_pending(ep_object))
				goto process_done;

			ret = hvnd_connector_notify_disconnect(ep_object->nd_dev,
							   ep_object->uctx,
							   ep_object->ep_handle,
							   ep_object);

			if (ret) {
				ep_del_work_pending(ep_object);
				hvnd_error("Connector notify disconnect failed; ret: %d\n", ret);
			}

			break;

		case IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT:
			hvnd_process_notify_disconnect(ep_object, status);
			break;

			
		default:
			hvnd_error("Unknown Connector IOCTL\n");
			break;
		}
		break;
	default:
		hvnd_error("Unknown endpoint object\n");
		break;
	}
process_done:
	kfree(incoming_pkt);
	ep_del_work_pending(ep_object);

	goto process_next;
}


static struct hvnd_ep_obj *hvnd_setup_ep(struct iw_cm_id *cm_id, int ep_type,
					struct hvnd_dev *nd_dev,
					struct hvnd_ucontext *uctx) 
{
	struct hvnd_ep_obj *ep_object;
	int ret;

	ep_object = kzalloc(sizeof(struct hvnd_ep_obj), GFP_KERNEL);

	if (!ep_object)
		return NULL;

	ret = hvnd_init_ep(ep_object, cm_id, ep_type, nd_dev, uctx);

	if (ret) {
		hvnd_error("hvnd_init_ep failed ret=%d\n", ret);
		kfree(ep_object);
		return NULL;
	}
		
	return ep_object;
}

/* 
return value:
	true: I/O state is stopped, we should not do upcall
	flase: I/O state is running and normal

static bool hvnd_manage_io_state(struct hvnd_ep_obj *ep, bool failure)
{
	unsigned long flags;

	spin_lock_irqsave(&ep->ep_lk, flags);
	if (ep->to_be_destroyed) {
		hvnd_warn("ep being destroyed\n");
		if (ep->io_outstanding) {
			hvnd_warn("ep being destroyed i/O pending waking up on %p\n", &ep->block_event);
			complete(&ep->block_event);
			ep->io_outstanding = false;
		}
		spin_unlock_irqrestore(&ep->ep_lk, flags);
		return true;
	}
	if (!failure)
		ep->io_outstanding = true;
	spin_unlock_irqrestore(&ep->ep_lk, flags);
	return false;
}
*/

static int hvnd_get_incoming_connections(struct hvnd_ep_obj *listener,
					 struct hvnd_dev *nd_dev,
					 struct hvnd_ucontext *uctx)
{
	struct hvnd_ep_obj *connector;
	u64 connector_handle;
	int ret;

	/*
	 * First handle the protocol for
	 * destruction - outstanding I/O.
	 */

//	if (hvnd_manage_io_state(listener, false))
//		return 0;
	/*
	 * Create a connector.
	 */
	connector = hvnd_setup_ep(listener->cm_id, ND_CONNECTOR, nd_dev, uctx);
	if (!connector) {
		hvnd_error("hvnd_setup_ep failed\n");
		ret = -ENOMEM;
		goto con_alloc_err;
	}
  
	ret = hvnd_cr_connector(nd_dev, uctx,
				&connector_handle);
	if (ret) {
		hvnd_error("hvnd_cr_connector failed ret=%d\n", ret);
		goto con_cr_err;
	}

	/*
	 * Now get a connection if one is pending.
	 */
	connector->ep_handle = connector_handle;
	connector->parent = listener;

	if (!ep_add_work_pending(connector))
		goto get_connection_err;

	ret = hvnd_get_connection_listener(nd_dev, uctx,
					listener->ep_handle,
					connector_handle,
					(u64)connector); 

	if (ret) {
		hvnd_debug("listener_get_connection failed\n");
		ep_del_work_pending(connector);
		goto get_connection_err;
	}

	hvnd_acquire_uctx_ref(uctx);
	listener->outstanding_handle = connector_handle;
	listener->outstanding_ep = connector;
	hvnd_debug("outstanding handle is %p\n", (void *)connector_handle);
	return 0;

get_connection_err:
	hvnd_free_handle(nd_dev, uctx,
			connector_handle,
			IOCTL_ND_CONNECTOR_FREE);

con_cr_err:
	kfree(connector);
con_alloc_err:
//	hvnd_manage_io_state(listener, true);
	return ret;
}

static int hvnd_create_listen(struct iw_cm_id *cm_id, int backlog)
{
	int ret = 0;
	struct hvnd_dev *nd_dev;
	struct hvnd_ucontext *uctx; 
	struct hvnd_ep_obj *ep_object;
	union nd_sockaddr_inet addr;
	union nd_sockaddr_inet local_addr;
	u64 listener_handle;	
	struct sockaddr_in *laddr = (struct sockaddr_in *)&cm_id->local_addr;
	union nd_sockaddr_inet og_addr;


	nd_dev = to_nd_dev(cm_id->device);
	uctx = get_uctx(nd_dev, current_pid());
	hvnd_debug("uctx is %p; pid is %d\n", uctx, current_pid());
	if (!uctx) {
		hvnd_error("no user context found for the current process\n");
		return -ENODATA;
	}

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
	if (cm_id->local_addr.sin_family != AF_INET) {
		hvnd_error("cm_id->local_addr.ss_family =%d not AF_INET\n", cm_id->local_addr.sin_family);
#else
	if (cm_id->local_addr.ss_family != AF_INET) {
		hvnd_error("cm_id->local_addr.ss_family =%d not AF_INET\n", cm_id->local_addr.ss_family);
#endif
		return -ENOSYS;
	}

	/*
	 * If the local address is LOOPBACK or INADDR_ANY, get an an address
	 * to bind the listener. For now, just get the first address
	 * available.
	 */

	if (IN_LOOPBACK(ntohl(laddr->sin_addr.s_addr)) ||
		(laddr->sin_addr.s_addr == INADDR_ANY)) {

		hvnd_debug("need to get an address\n");
		ret = hvnd_get_outgoing_rdma_addr(nd_dev, uctx, &og_addr);

		if (ret) {
			hvnd_error("failed to get the og address\n");
			return ret;
		}

		laddr->sin_addr.s_addr = og_addr.ipv4.sin_addr.s_addr;
	}

	cm_id->add_ref(cm_id);

	ep_object = hvnd_setup_ep(cm_id, ND_LISTENER, nd_dev, uctx);

	if (!ep_object) {
		hvnd_error("hvnd_setup_ep returned NULL\n");
		goto alloc_err;
	}

	ret = hvnd_cr_listener(nd_dev, uctx,
				&listener_handle);
	if (ret) {
		hvnd_error("hvnd_cr_listener failed ret=%d\n", ret);
		goto cr_err;
	}

	ep_object->ep_handle = listener_handle;

	cm_id->provider_data = ep_object;

	/*
	 * Now bind the listener.
	 * IPV4 support only.
	 */
	memcpy(&addr.ipv4, laddr, sizeof(struct sockaddr_in));
	
	ret = hvnd_bind_listener(nd_dev, uctx,
				listener_handle,
				&addr);
	if (ret) {
		hvnd_error("hvnd_bind_listener failed ret=%d\n", ret);
		goto bind_err;
	}
 	
	/*
	 * Now get the local address.
	 */
	ret = hvnd_get_addr_listener(nd_dev, uctx,
					listener_handle,
					&local_addr);
	if (ret) {
		hvnd_error("hvnd_get_addr_listener failed ret=%d\n", ret);
		goto bind_err;
	}

	/*
	 * Now put the listener in the listen mode.
	 */

	ret = hvnd_listen_listener(nd_dev, uctx,
				listener_handle,
				backlog);

	if (ret) {
		hvnd_error("hvnd_listen_listener failed ret=%d\n", ret);
		goto bind_err;
	}


	/*
	 * Now get a pending connection if one is pending.
	 */
	ret = hvnd_get_incoming_connections(ep_object, nd_dev, uctx);
	if (ret) {
		hvnd_error("hvnd_get_incoming_connections failed ret=%d\n", ret);
		goto bind_err;
	}

	hvnd_acquire_uctx_ref(uctx);
	hvnd_debug("cm_id=%p\n", cm_id);
	return 0;

bind_err:
	hvnd_free_handle(nd_dev, uctx,
			listener_handle,
			IOCTL_ND_LISTENER_FREE);
cr_err:
	kfree(ep_object);
alloc_err:
	cm_id->provider_data = NULL;
	cm_id->rem_ref(cm_id);
	return ret;
}

static int hvnd_destroy_listen(struct iw_cm_id *cm_id)
{
	struct hvnd_dev *nd_dev;
	struct hvnd_ucontext *uctx; 
	struct hvnd_ep_obj *ep_object;

	nd_dev = to_nd_dev(cm_id->device);

	ep_object = (struct hvnd_ep_obj *)cm_id->provider_data;

	hvnd_debug("uctx is %p\n", ep_object->uctx);
	hvnd_debug("Destroying Listener cm_id=%p\n", cm_id);
	uctx = ep_object->uctx;

	// make sure there is nothing in progress on this ep
	ep_stop(ep_object);

	hvnd_free_handle(nd_dev, uctx,
			ep_object->ep_handle,
			IOCTL_ND_LISTENER_FREE);

	/*
	 * We may have an ouststanding connector for
	 * incoming connection requests; clean it up.
	 */

	if (ep_object->outstanding_handle != 0) {

		// make sure there is nothing in progress on this ep
		ep_stop(ep_object->outstanding_ep);

		hvnd_free_handle(nd_dev, uctx,
				ep_object->outstanding_handle,
				IOCTL_ND_CONNECTOR_FREE);


		hvnd_drop_uctx_ref(nd_dev, uctx);
		hvnd_destroy_ep(ep_object->outstanding_ep);
	}

	/*
	 * Now everything should have stopped
	 */

	cm_id->rem_ref(cm_id);
	hvnd_destroy_ep(ep_object);
	cm_id->provider_data = NULL;
	hvnd_drop_uctx_ref(nd_dev, uctx);

	hvnd_debug("cm_id=%p\n", cm_id);
	return 0;
}

static void hvnd_qp_add_ref(struct ib_qp *ibqp)
{
	struct hvnd_qp *qp = to_nd_qp(ibqp);
	atomic_inc(&qp->refcnt);
}

void hvnd_qp_rem_ref(struct ib_qp *ibqp)
{
	struct hvnd_qp *qp = to_nd_qp(ibqp);
	if (atomic_dec_and_test(&qp->refcnt))
		wake_up(&qp->wait);
}

static DEVICE_ATTR(hw_rev, S_IRUGO, hvnd_show_rev, NULL);
static DEVICE_ATTR(fw_ver, S_IRUGO, hvnd_show_fw_ver, NULL);
static DEVICE_ATTR(hca_type, S_IRUGO, hvnd_show_hca, NULL);
static DEVICE_ATTR(board_id, S_IRUGO, hvnd_show_board, NULL);

static struct device_attribute *hvnd_class_attributes[] = {
	&dev_attr_hw_rev,
	&dev_attr_fw_ver,
	&dev_attr_hca_type,
	&dev_attr_board_id,
};

int hvnd_register_device(struct hvnd_dev *dev, char *ip_addr, char *mac_addr)
{
	int ret;
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4)
	int i;
#endif

	dev->ibdev.owner = THIS_MODULE;
	dev->device_cap_flags = IB_DEVICE_LOCAL_DMA_LKEY | IB_DEVICE_MEM_WINDOW;
	dev->ibdev.local_dma_lkey = 0;
	dev->ibdev.uverbs_cmd_mask =
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POLL_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POST_SEND) |
	    (1ull << IB_USER_VERBS_CMD_POST_RECV);
	dev->ibdev.node_type = RDMA_NODE_RNIC;
	memcpy(dev->ibdev.node_desc, HVND_NODE_DESC, sizeof(HVND_NODE_DESC));
	memcpy(&dev->ibdev.node_guid, mac_addr, 6);
	dev->ibdev.phys_port_cnt = 1; //dev->nports;
	dev->ibdev.num_comp_vectors = 1;
	dev->ibdev.query_device = hvnd_query_device;
	dev->ibdev.query_port = hvnd_query_port;
	dev->ibdev.get_link_layer = hvnd_get_link_layer;
	dev->ibdev.query_pkey = hvnd_query_pkey;
	dev->ibdev.query_gid = hvnd_query_gid;
	dev->ibdev.alloc_ucontext = hvnd_alloc_ucontext;
	dev->ibdev.dealloc_ucontext = hvnd_dealloc_ucontext;
	dev->ibdev.mmap = hvnd_mmap;
	dev->ibdev.alloc_pd = hvnd_allocate_pd;
	dev->ibdev.dealloc_pd = hvnd_deallocate_pd;
	dev->ibdev.create_ah = hvnd_ah_create;
	dev->ibdev.destroy_ah = hvnd_ah_destroy;
	dev->ibdev.create_qp = hvnd_ib_create_qp;
	dev->ibdev.modify_qp = hvnd_ib_modify_qp;
	dev->ibdev.query_qp = hvnd_ib_query_qp;
	dev->ibdev.destroy_qp = hvnd_destroy_qp;
	dev->ibdev.create_cq = hvnd_ib_create_cq;
	dev->ibdev.destroy_cq = hvnd_ib_destroy_cq;
	dev->ibdev.resize_cq = hvnd_resize_cq;
	dev->ibdev.poll_cq = hvnd_poll_cq;
	dev->ibdev.get_dma_mr = hvnd_get_dma_mr;
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3)
	dev->ibdev.reg_phys_mr = hvnd_register_phys_mem;
	dev->ibdev.rereg_phys_mr = hvnd_reregister_phys_mem;
	dev->ibdev.bind_mw = hvnd_bind_mw;
	dev->ibdev.alloc_fast_reg_mr = hvnd_alloc_fast_reg_mr;
	dev->ibdev.alloc_fast_reg_page_list = hvnd_alloc_fastreg_pbl;
	dev->ibdev.free_fast_reg_page_list = hvnd_free_fastreg_pbl;
	dev->ibdev.get_protocol_stats = hvnd_get_mib;
#endif
	dev->ibdev.reg_user_mr = hvnd_reg_user_mr;
	dev->ibdev.dereg_mr = hvnd_dereg_mr;
	dev->ibdev.alloc_mw = hvnd_alloc_mw;
	dev->ibdev.dealloc_mw = hvnd_dealloc_mw;
	dev->ibdev.attach_mcast = hvnd_multicast_attach;
	dev->ibdev.detach_mcast = hvnd_multicast_detach;
	dev->ibdev.process_mad = hvnd_process_mad;
	dev->ibdev.req_notify_cq = hvnd_arm_cq;
	dev->ibdev.post_send = hvnd_post_send;
	dev->ibdev.post_recv = hvnd_post_receive;
	dev->ibdev.uverbs_abi_ver = MLX4_IB_UVERBS_ABI_VERSION;

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
	dev->ibdev.get_port_immutable = hvnd_get_port_immutable;
#endif

	//DMA ops for mapping all possible addresses
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	dev->ibdev.dma_device = &(dev->hvdev->device);
	dev->ibdev.dma_device->archdata.dma_ops = &vmbus_dma_ops;
#else
	dev->ibdev.dev.parent = &(dev->hvdev->device);
	dev->ibdev.dev.dma_mask = (u64 *) DMA_BIT_MASK(64);
	dev->ibdev.dev.coherent_dma_mask = DMA_BIT_MASK(64);
	set_dma_ops(&dev->ibdev.dev, &vmbus_dma_ops);
#endif

	dev->ibdev.iwcm = kmalloc(sizeof(struct iw_cm_verbs), GFP_KERNEL);
	if (!dev->ibdev.iwcm)
		return -ENOMEM;

	dev->ibdev.iwcm->connect = hvnd_connect;
	dev->ibdev.iwcm->accept = hvnd_accept_cr;
	dev->ibdev.iwcm->reject = hvnd_reject_cr;
	dev->ibdev.iwcm->create_listen = hvnd_create_listen;
	dev->ibdev.iwcm->destroy_listen = hvnd_destroy_listen;
	dev->ibdev.iwcm->add_ref = hvnd_qp_add_ref;
	dev->ibdev.iwcm->rem_ref = hvnd_qp_rem_ref;
	dev->ibdev.iwcm->get_qp = hvnd_get_qp;

	strlcpy(dev->ibdev.name, "mlx4_%d", IB_DEVICE_NAME_MAX);
	ret = ib_register_device(&dev->ibdev, NULL);
	if (ret) {
		hvnd_error("ib_register_device failed ret=%d\n", ret);
		goto bail1;
	}

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4)
	for (i = 0; i < ARRAY_SIZE(hvnd_class_attributes); ++i) {
		ret = device_create_file(&dev->ibdev.dev,
					 hvnd_class_attributes[i]);
		if (ret) {
			hvnd_error("device_create_file failed ret=%d\n", ret);
			ib_unregister_device(&dev->ibdev);
			goto bail1;
		}
	}
#endif

	dev->ib_active = true;
	return 0;
bail1:
	kfree(dev->ibdev.iwcm);
	return ret;
}

void hvnd_unregister_device(struct hvnd_dev *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hvnd_class_attributes); ++i)
		device_remove_file(&dev->ibdev.dev,
				   hvnd_class_attributes[i]);
	ib_unregister_device(&dev->ibdev);
	kfree(dev->ibdev.iwcm);
	ib_dealloc_device((struct ib_device *)dev);
	return;
}

static int hvnd_try_bind_nic(unsigned char *mac, __be32 ip)
{
	int ret;
	struct hvnd_dev *nd_dev = g_nd_dev;

	mutex_lock(&nd_dev->bind_mutex);
	if (nd_dev->bind_complete) {
		mutex_unlock(&nd_dev->bind_mutex);
		return 1;
	}

	memcpy(nd_dev->mac_addr, mac, 6);
	*(__be32*)(nd_dev->ip_addr) = ip;

	/*
	* Bind the NIC.
	*/
	hvnd_info("trying to bind to IP %pI4 MAC %pM\n", nd_dev->ip_addr, nd_dev->mac_addr);
	ret = hvnd_bind_nic(nd_dev, false, nd_dev->ip_addr, nd_dev->mac_addr);
	if (ret || nd_dev->bind_pkt.pkt_hdr.status) {
		mutex_unlock(&nd_dev->bind_mutex);
		return 1;
	}

	/* if we reach here, this means bind_nic is a success */
	hvnd_error("successfully bound to IP %pI4 MAC %pM\n", nd_dev->ip_addr, nd_dev->mac_addr);
	nd_dev->bind_complete=1;
	complete_all(&nd_dev->addr_set);
	mutex_unlock(&nd_dev->bind_mutex);

	ret = hvnd_register_device(nd_dev, nd_dev->ip_addr, nd_dev->mac_addr);

	if (!ret)
		return 0;

	hvnd_error("hvnd_register_device failed ret=%d\n", ret);

	/* roll back all allocated resources on error */
	iounmap(nd_dev->mmio_virt);
	release_resource(&nd_dev->mmio_resource);

	vmbus_close(nd_dev->hvdev->channel);
	ib_dealloc_device((struct ib_device *)nd_dev);

	return 1;
}

static void hvnd_inetaddr_event_up(unsigned long event, struct in_ifaddr *ifa)
{
	hvnd_try_bind_nic(ifa->ifa_dev->dev->dev_addr, ifa->ifa_address);
}

static int hvnd_inetaddr_event(struct notifier_block *notifier, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	switch(event) {
	case NETDEV_UP:
		hvnd_inetaddr_event_up(event, ifa);
		break;
	default:
		hvnd_debug("Received inetaddr event %lu\n", event);
	}

	return NOTIFY_DONE;
}

static struct notifier_block hvnd_inetaddr_notifier = {
	.notifier_call = hvnd_inetaddr_event,
};

static int start_bind_nic(void)
{
	struct net_device *dev;
	struct in_device *idev;
	struct in_ifaddr *ifa;

	register_inetaddr_notifier(&hvnd_inetaddr_notifier);

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		idev = in_dev_get(dev);
		if (!idev)
			continue;
		for (ifa = (idev)->ifa_list; ifa && !(ifa->ifa_flags&IFA_F_SECONDARY); ifa = ifa->ifa_next) {
			hvnd_try_bind_nic(dev->dev_addr, ifa->ifa_address);
		}
	}
	rtnl_unlock();

	return 0;
}

static int hvnd_probe(struct hv_device *dev,
		      const struct hv_vmbus_device_id *dev_id)
{
	struct hvnd_dev *nd_dev;
	int ret = 0;

	hvnd_debug("hvnd starting\n");

	nd_dev = (struct hvnd_dev *)ib_alloc_device(sizeof(struct hvnd_dev));
	if (!nd_dev) {
		ret = -ENOMEM;
		goto err_out0;
	}

	nd_dev->hvdev = dev;
	/*
	 * We are going to masquerade as MLX4 device;
	 * Set the vendor and device ID accordingly.
	 */
	dev->vendor_id = 0x15b3; //Mellanox
	dev->device_id = 0x1003; //Mellanox HCA
	INIT_LIST_HEAD(&nd_dev->listentry);
	spin_lock_init(&nd_dev->uctxt_lk);
	nd_dev->ib_active = false;

	/*
	 * Initialize the state for the id table.
	 */
	spin_lock_init(&nd_dev->id_lock);
	idr_init(&nd_dev->cqidr);
	idr_init(&nd_dev->qpidr);
	idr_init(&nd_dev->mmidr);
	idr_init(&nd_dev->irpidr);
	idr_init(&nd_dev->uctxidr);

	atomic_set(&nd_dev->open_cnt, 0);

	sema_init(&nd_dev->query_pkt_sem, 1);
	
	ret = vmbus_open(dev->channel, HVND_RING_SZ, HVND_RING_SZ, NULL, 0,
			 hvnd_callback, dev);

	if (ret) {
		hvnd_error("vmbus_open failed ret=%d\n", ret);
		goto err_out1;
	}

	hv_set_drvdata(dev, nd_dev);

	ret = hvnd_negotiate_version(nd_dev);

	if (ret) {
		hvnd_error("hvnd_negotiate_version failed ret=%d\n", ret);
		goto err_out2;
	}

	/*
	 * Register resources with the host.
	 */
	ret = hvnd_init_resources(nd_dev);
	if (ret) {
		hvnd_error("hvnd_init_resources failed ret=%d\n", ret);
		goto err_out2;
	}

	/*
	 * Try to bind every NIC to ND channel,
	 * ND host will only return success for the correct one
	 */
	nd_dev->bind_complete = 0;
	mutex_init(&nd_dev->bind_mutex);
	init_completion(&nd_dev->addr_set);

	g_nd_dev = nd_dev;
	start_bind_nic();

	return 0;

err_out2:
	vmbus_close(dev->channel);

err_out1:
	ib_dealloc_device((struct ib_device *)nd_dev);

err_out0:
	return ret;
}

static int hvnd_remove(struct hv_device *dev)
{
	struct hvnd_dev *nd_dev = hv_get_drvdata(dev);

	unregister_inetaddr_notifier(&hvnd_inetaddr_notifier);
	hvnd_bind_nic(nd_dev, true, nd_dev->ip_addr, nd_dev->mac_addr);
	hvnd_unregister_device(nd_dev);
	vmbus_close(dev->channel);
	iounmap(nd_dev->mmio_virt);
	release_resource(&nd_dev->mmio_resource);
	return 0;
}

static const struct hv_vmbus_device_id id_table[] = {
	/* VMBUS RDMA class guid */
	/* 8c2eaf3d-32a7-4b09-ab99-bd1f1c86b501 */
	{ HV_ND_GUID, },
	{ },
};

MODULE_DEVICE_TABLE(vmbus, id_table);

static  struct hv_driver hvnd_drv = {
	.name = "hv_guest_rdma",
	.id_table = id_table,
	.probe =  hvnd_probe,
	.remove =  hvnd_remove,
};


static int __init init_hvnd_drv(void)
{

	pr_info("Registered HyperV networkDirect Driver\n");
	hvnd_addr_init();
	return(vmbus_driver_register(&hvnd_drv));
	
}

static void exit_hvnd_drv(void)
{
	pr_info("De-Registered HyperV networkDirect Driver\n");
	hvnd_addr_deinit();
	vmbus_driver_unregister(&hvnd_drv);
}


module_init(init_hvnd_drv);
module_exit(exit_hvnd_drv);

MODULE_DESCRIPTION("Hyper-V NetworkDirect Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(HV_DRV_VERSION);
