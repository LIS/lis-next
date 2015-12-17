/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * KYS: made some modifications.
 */

#ifndef MX_ABI_H
#define MX_ABI_H



/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * Specifically:
 *  - Do not use pointer types -- pass pointers in UINT64 instead.
 *  - Make sure that any structure larger than 4 bytes is padded to a
 *    multiple of 8 bytes.  Otherwise the structure size will be
 *    different between 32-bit and 64-bit architectures.
 */

enum ibv_get_context_mappings {
	IBV_GET_CONTEXT_UAR,
	IBV_GET_CONTEXT_BF,
	IBV_GET_CONTEXT_MAPPING_MAX
};

struct ibv_get_context_req {

	union nd_mapping mappings[IBV_GET_CONTEXT_MAPPING_MAX];
};

struct ibv_get_context_resp {

	// mmap UAR and BF
	struct nd_mapping_result  mapping_results[IBV_GET_CONTEXT_MAPPING_MAX];
	
	// mmap Blue Flame
	int bf_buf_size;
	int bf_offset;
	
	// mlx4_query_device result 
	int max_qp_wr;
	int max_sge;
	int max_cqe;

	// general parameters
	u32 cqe_size;
	u32 vend_id;
	u16 dev_id;
	u16 bf_reg_size;
	u16 bf_regs_per_page;
	u16 reserved1;

	// ibv_cmd_get_context result 
	u32 qp_tab_size;

	u32 reserved2;
};

struct ibv_alloc_pd_resp {
	u64 pd_handle;
	u32 pdn;
	u32 reserved;
};

struct ibv_reg_mr {
	u64 start;
	u64 length;
	u64 hca_va;
	u32 access_flags;
	u32 pdn;
	u64 pd_handle;
};

struct ibv_reg_mr_resp {
	u64 mr_handle;
	u32 lkey;
	u32 rkey;
};


enum mlx4_ib_create_cq_mapping {
	MLX4_IB_CREATE_CQ_BUF,
	MLX4_IB_CREATE_CQ_DB,
	MLX4_IB_CREATE_CQ_ARM_SN,   // Windows specific
	MLX4_IB_CREATE_CQ_MAPPING_MAX
};

#define MLX4_CQ_FLAGS_ARM_IN_KERNEL     1

struct ibv_create_cq {
	union nd_mapping mappings[MLX4_IB_CREATE_CQ_MAPPING_MAX];
	u32  flags;
};

struct ibv_create_cq_resp {
	struct nd_mapping_result mapping_results[MLX4_IB_CREATE_CQ_MAPPING_MAX];
	u32  cqn;
	u32  cqe;
};

enum mlx4_ib_create_srq_mappings {
	MLX4_IB_CREATE_SRQ_BUF,
	MLX4_IB_CREATE_SRQ_DB,
	MLX4_IB_CREATE_SRQ_MAPPINGS_MAX
};

struct ibv_create_srq {
	union nd_mapping mappings[MLX4_IB_CREATE_SRQ_MAPPINGS_MAX];
};

struct ibv_create_srq_resp {
	struct nd_mapping_result mapping_results[MLX4_IB_CREATE_SRQ_MAPPINGS_MAX];
};

enum mlx4_ib_create_qp_mappings {
	MLX4_IB_CREATE_QP_BUF,
	MLX4_IB_CREATE_QP_DB,
	MLX4_IB_CREATE_QP_MAPPINGS_MAX
};

struct ibv_create_qp {
	union nd_mapping mappings[MLX4_IB_CREATE_QP_MAPPINGS_MAX];
	u8	log_sq_bb_count;
	u8	log_sq_stride;
	u8	sq_no_prefetch;
	u8	reserved;
};

struct ibv_create_qp_resp {
	struct nd_mapping_result mapping_results[MLX4_IB_CREATE_QP_MAPPINGS_MAX];
	// struct ib_uverbs_create_qp_resp
	u64 qp_handle;
	u32 qpn;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_inline_data;
};

enum ibv_qp_attr_mask {
	IBV_QP_STATE			= 1 << 0,
	IBV_QP_CUR_STATE		= 1 << 1,
	IBV_QP_EN_SQD_ASYNC_NOTIFY	= 1 << 2,
	IBV_QP_ACCESS_FLAGS		= 1 << 3,
	IBV_QP_PKEY_INDEX		= 1 << 4,
	IBV_QP_PORT			= 1 << 5,
	IBV_QP_QKEY			= 1 << 6,
	IBV_QP_AV			= 1 << 7,
	IBV_QP_PATH_MTU			= 1 << 8,
	IBV_QP_TIMEOUT			= 1 << 9,
	IBV_QP_RETRY_CNT		= 1 << 10,
	IBV_QP_RNR_RETRY		= 1 << 11,
	IBV_QP_RQ_PSN			= 1 << 12,
	IBV_QP_MAX_QP_RD_ATOMIC		= 1 << 13,
	IBV_QP_ALT_PATH			= 1 << 14,
	IBV_QP_MIN_RNR_TIMER		= 1 << 15,
	IBV_QP_SQ_PSN			= 1 << 16,
	IBV_QP_MAX_DEST_RD_ATOMIC	= 1 << 17,
	IBV_QP_PATH_MIG_STATE		= 1 << 18,
	IBV_QP_CAP			= 1 << 19,
	IBV_QP_DEST_QPN			= 1 << 20
};

enum ibv_qp_state {
	IBV_QPS_RESET,
	IBV_QPS_INIT,
	IBV_QPS_RTR,
	IBV_QPS_RTS,
	IBV_QPS_SQD,
	IBV_QPS_SQE,
	IBV_QPS_ERR
};


struct ibv_modify_qp_resp {
	enum ibv_qp_attr_mask attr_mask;
	u8 qp_state;
	u8 reserved[3];
};

struct ibv_create_ah_resp {
	u64 start;
};

/*
 * Some mlx4 specific kernel definitions. Perhaps could be in 
 * separate file.
 */

struct mlx4_ib_user_db_page {
	struct list_head        list;
	struct ib_umem         *umem;
	unsigned long           user_virt;
	int                     refcnt;
};


#endif /* MX_ABI_H */
