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


#ifndef _VMBUS_RDMA_H
#define _VMBUS_RDMA_H


#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/ib_verbs.h>
#include <linux/idr.h>
#include <linux/if_ether.h>

/* NetworkDirect version Numbers.
 */
#define ND_VERSION_1    0x1
#define ND_VERSION_2    0x20000

#ifndef NDVER
#define NDVER      ND_VERSION_2
#endif

#define ND_ADAPTER_FLAG_IN_ORDER_DMA_SUPPORTED              0x00000001
#define ND_ADAPTER_FLAG_CQ_INTERRUPT_MODERATION_SUPPORTED   0x00000004
#define ND_ADAPTER_FLAG_MULTI_ENGINE_SUPPORTED              0x00000008
#define ND_ADAPTER_FLAG_CQ_RESIZE_SUPPORTED                 0x00000100
#define ND_ADAPTER_FLAG_LOOPBACK_CONNECTIONS_SUPPORTED      0x00010000

#define ND_CQ_NOTIFY_ERRORS                                 0
#define ND_CQ_NOTIFY_ANY                                    1
#define ND_CQ_NOTIFY_SOLICITED                              2

#define ND_MR_FLAG_ALLOW_LOCAL_WRITE                        0x00000001
#define ND_MR_FLAG_ALLOW_REMOTE_READ                        0x00000002
#define ND_MR_FLAG_ALLOW_REMOTE_WRITE                       0x00000005
#define ND_MR_FLAG_RDMA_READ_SINK                           0x00000008
#define ND_MR_FLAG_DO_NOT_SECURE_VM                         0x80000000

#define ND_OP_FLAG_SILENT_SUCCESS                           0x00000001
#define ND_OP_FLAG_READ_FENCE                               0x00000002
#define ND_OP_FLAG_SEND_AND_SOLICIT_EVENT                   0x00000004
#define ND_OP_FLAG_ALLOW_READ                               0x00000008
#define ND_OP_FLAG_ALLOW_WRITE                              0x00000010

#if NDVER >= ND_VERSION_2
#define ND_OP_FLAG_INLINE                                   0x00000020
#endif

#define ND_AF_INET6	23
#define IF_MAX_ADDR_LENGTH 32

struct group_affinity {
	u64 mask; //KYS: usually 0
	u16 group; // KYS usually -1
	u16 reserved[3];
};

struct if_physical_addr {
	u16 length;
	u8 addr[IF_MAX_ADDR_LENGTH];
};

struct adapter_info_v2 {
	u32 info_version;
	u16 vendor_id;
	u16 device_id;
	u64 adapter_id;
	size_t max_registration_size;
	size_t max_window_size;
	u32 max_initiator_sge;
	u32 max_recv_sge;
	u32 max_read_sge;
	u32 max_transfer_length;
	u32 max_inline_data_size;
	u32 max_inbound_read_limit;
	u32 max_outbound_read_limit;
	u32 max_recv_q_depth;
	u32 max_initiator_q_depth;
	u32 max_shared_recv_q_depth;
	u32 max_completion_q_depth;
	u32 inline_request_threshold;
	u32 large_request_threshold;
	u32 max_caller_data;
	u32 max_callee_data;
	u32 adapter_flags;
} __packed;

struct nd2_adapter_info_32 { //KYS: Check what this is
	u32 info_version;
	u16 vendor_id;
	u16 devic_id;
	u64 adapter_id;
	u32 max_registration_size;
	u32 max_window_size;
	u32 max_initiator_sge;
	u32 max_recv_sge;
	u32 max_read_sge;
	u32 max_transfer_length;
	u32 max_inline_data_size;
	u32 max_inbound_read_limit;
	u32 max_outbound_read_limit;
	u32 max_recv_q_depth;
	u32 max_initiator_q_depth;
	u32 max_shared_recv_q_depth;
	u32 max_completion_q_depth;
	u32 inline_request_threshold;
	u32 large_request_threshold;
	u32 max_caller_data;
	u32 max_callee_data;
	u32 adapter_flags;
} __packed;

enum nd2_request_type {
	ND2_RT_RECEIVE,
	ND2_RT_SEND,
	ND2_RT_BIND,
	ND2_RT_INVALIDATE,
	ND2_RT_READ,
	ND2_RT_WRITE
};

struct nd2_result {
	u32 status;
	u32 bytes_transferred;
	void *qp_ctx;
	void *request_ctx;
	enum nd2_request_type request_type;
} __packed;

struct nd2_sge {
	void *buffer;
	u32 buffer_length;
	u32 mr_token;
} __packed;

/*
 * The communication with the host via ioctls using VMBUS
 * as the transport.
 */

#define ND_IOCTL_VERSION    1

enum nd_mapping_type {
	ND_MAP_IOSPACE,
	ND_MAP_MEMORY,
	ND_MAP_MEMORY_COALLESCE,
	ND_MAP_PAGES,
	ND_MAP_PAGES_COALLESCE,
	ND_UNMAP_IOSPACE,
	ND_UNMAP_MEMORY,
	ND_MAX_MAP_TYPE
};

enum nd_caching_type {
	ND_NON_CACHED = 0,
	ND_CACHED,
	ND_WRITE_COMBINED,
	ND_MAX_CACHE_TYPE
};

enum nd_aceess_type {
	ND_READ_ACCESS = 0,
	ND_WRITE_ACCESS,
	ND_MODIFY_ACCESS
};

struct nd_map_io_space {
	enum nd_mapping_type map_type;
	enum nd_caching_type cache_type;
	u32 cb_length;
};

struct nd_map_memory {
	enum nd_mapping_type map_type;
	enum nd_aceess_type access_type;
	u64 address;
	u32 cb_length;
};

struct nd_mapping_id {
	enum nd_mapping_type map_type;
	u64 id;
};

struct ndk_map_pages {
	struct nd_map_memory header;
	u32 page_offset;
};

union nd_mapping {
	enum nd_mapping_type map_type;
	struct nd_map_io_space map_io_space;
	struct nd_map_memory map_memory;
	struct nd_mapping_id mapping_id;
	struct ndk_map_pages map_pages;
};

struct nd_mapping_result {
	u64 id;
	u64 info;
};

struct nd_resource_descriptor {
	u64 handle;
	u32 ce_mapping_results;
	u32 cb_mapping_results_offset;
};

struct nd_handle {
	u32 version;
	u32 reserved;
	u64 handle;
};

union nd_sockaddr_inet {
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
	u16 address_family; //KYS how is this supposed to work?
};

struct nd_address_element {
	union nd_sockaddr_inet addr;
	char mac_addr[ETH_ALEN];
};

struct nd_resolve_address {
	u32 version;
	u32 reserved;
	union nd_sockaddr_inet address;
};

struct nd_open_adapter {
	u32 version;
	u32 reserved;
	u32 ce_mapping_cnt;
	u32 cb_mapping_offset;
	u64 adapter_id;
};

struct nd_adapter_query {
	u32 version;
	u32 info_version;
	u64 adapter_handle;
};

struct nd_create_cq {
	u32 version;
	u32 queue_depth;
	u32 ce_mapping_cnt;
	u32 cb_mapping_offset;
	u64 adapter_handle;
	struct group_affinity affinity;
};

struct nd_create_srq {
	u32 version;
	u32 queue_depth;
	u32 ce_mapping_cnt;
	u32 cb_mapping_offset;
	u32 max_request_sge;
	u32 notify_threshold;
	u64 pd_handle;
	struct group_affinity affinity;
};

struct nd_create_qp_hdr {
	u32 version;
	u32 cb_max_inline_data;
	u32 ce_mapping_cnt;
	u32 cb_mapping_offset; //KYS: what is this prefix - ce/cb
	u32 initiator_queue_depth;
	u32 max_initiator_request_sge;
	u64 receive_cq_handle;
	u64 initiator_cq_handle;
	u64 pd_handle;
};

struct nd_create_qp {
	struct nd_create_qp_hdr hdr;
	u32 receive_queue_depth;
	u32 max_receive_request_sge;
};

struct nd_create_qp_with_srq {
	struct nd_create_qp_hdr header;
	u64 srq_handle;
};

struct nd_srq_modify {
	u32 version;
	u32 queue_depth;
	u32 ce_mapping_cnt;
	u32 cb_mapping_offset;
	u32 notify_threshold;
	u32 reserved;
	u64 srq_handle;
};

struct nd_cq_modify {
	u32 version;
	u32 queue_depth;
	u32 ce_mapping_count;
	u32 cb_mappings_offset;
	u64 cq_handle;
};

struct nd_cq_notify {
	u32 version;
	u32 type;
	u64 cq_handle;
};

struct nd_mr_register_hdr {
	u32 version;
	u32 flags;
	u64 cb_length;
	u64 target_addr;
	u64 mr_handle;
};

struct nd_mr_register {
	struct nd_mr_register_hdr header;
	u64 address;
};

struct nd_bind {
	u32 version;
	u32 reserved;
	u64 handle;
	union nd_sockaddr_inet address;
};

struct nd_read_limits {
	u32 inbound;
	u32 outbound;
};

struct nd_connect {
	u32 version;
	u32 reserved;
	struct nd_read_limits read_limits;
	u32 cb_private_data_length;
	u32 cb_private_data_offset;
	u64 connector_handle;
	u64 qp_handle;
	union nd_sockaddr_inet destination_address;
	struct if_physical_addr phys_addr;	
};

struct nd_accept {
	u32 version;
	u32 reserved;
	struct nd_read_limits read_limits;
	u32 cb_private_data_length;
	u32 cb_private_data_offset;
	u64 connector_handle;
	u64 qp_handle;
};

struct nd_reject {
	u32 version;
	u32 reserved;
	u32 cb_private_data_length;
	u32 cb_private_data_offset;
	u64 connector_handle;
};

struct nd_listen {
	u32 version;
	u32 back_log;
	u64 listener_handle;
};

struct nd_get_connection_request {
	u32 version;
	u32 reserved;
	u64 listener_handle;
	u64 connector_handle;
};

enum ndv_mmio_type {
	ND_PARTITION_KERNEL_VIRTUAL,
	ND_PARTITION_SYSTEM_PHYSICAL,
	ND_PARTITION_GUEST_PHYSICAL,
	ND_MAXIMUM_MMIO_TYPE
};

struct ndv_resolve_adapter_id {
	u32 version;
	struct if_physical_addr phys_addr;	
};

struct ndv_partition_create {
	u32 version;
	enum ndv_mmio_type mmio_type;
	u64 adapter_id;
	u64 xmit_cap;
};

struct ndv_partition_bind_luid {
	u32 version;
	u32 reserved;
	u64 partition_handle;
	struct if_physical_addr phys_addr;	
	//IF_LUID luid; //KYS?
};

struct ndv_partition_bind_address {
	u32 version;
	u32 reserved;
	u64 partition_handle;
	union nd_sockaddr_inet address;
	struct if_physical_addr guest_phys_addr;	
	struct if_physical_addr phys_addr;	
};

struct ndk_mr_register {
	struct nd_mr_register_hdr hdr;
	u32 cb_logical_page_addresses_offset;
};

struct ndk_bind {
	struct nd_bind hdr;
	u64 authentication_id;
	bool is_admin;
};

#define FDN 0x12
#define METHOD_BUFFERED 0x0
#define FAA 0x0

#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define ND_FUNCTION(r_, i_)    ((r_) << 6 | (i_))
#define IOCTL_ND(r_, i_) \
		 CTL_CODE( FDN, ND_FUNCTION((r_), (i_)), METHOD_BUFFERED, FAA )

#define ND_FUNCTION_FROM_CTL_CODE(ctrlCode_)     ((ctrlCode_ >> 2) & 0xFFF)
#define ND_RESOURCE_FROM_CTL_CODE(ctrlCode_)     (ND_FUNCTION_FROM_CTL_CODE(ctrlCode_) >> 6)
#define ND_OPERATION_FROM_CTRL_CODE(ctrlCode_)   (ND_FUNCTION_FROM_CTL_CODE(ctrlCode_) & 0x3F)

#define ND_DOS_DEVICE_NAME L"\\DosDevices\\Global\\NetworkDirect"
#define ND_WIN32_DEVICE_NAME L"\\\\.\\NetworkDirect"

enum nd_resource_type {
	ND_PROVIDER = 0,
	ND_ADAPTER,
	ND_PD,
	ND_CQ,
	ND_MR,
	ND_MW,
	ND_SRQ,
	ND_CONNECTOR,
	ND_LISTENER,
	ND_QP,
	ND_VIRTUAL_PARTITION,
	ND_RESOURCE_TYPE_COUNT
};

#define ND_OPERATION_COUNT 14

#define IOCTL_ND_PROVIDER(i_)		IOCTL_ND(ND_PROVIDER, i_)
#define IOCTL_ND_ADAPTER(i_)		IOCTL_ND(ND_ADAPTER, i_)
#define IOCTL_ND_PD(i_)			IOCTL_ND(ND_PD, i_)
#define IOCTL_ND_CQ(i_)			IOCTL_ND(ND_CQ, i_)
#define IOCTL_ND_MR(i_)			IOCTL_ND(ND_MR, i_)
#define IOCTL_ND_MW(i_)			IOCTL_ND(ND_MW, i_)
#define IOCTL_ND_SRQ(i_)		IOCTL_ND(ND_SRQ, i_)
#define IOCTL_ND_CONNECTOR(i_)		IOCTL_ND(ND_CONNECTOR, i_)
#define IOCTL_ND_LISTENER(i_)		IOCTL_ND(ND_LISTENER, i_)
#define IOCTL_ND_QP(i_)			IOCTL_ND(ND_QP, i_)
#define IOCTL_ND_VIRTUAL_PARTITION(i_)	IOCTL_ND(ND_VIRTUAL_PARTITION, i_)

/* Provider IOCTLs */
#define IOCTL_ND_PROVIDER_INIT				IOCTL_ND_PROVIDER( 0 )
#define IOCTL_ND_PROVIDER_BIND_FILE			IOCTL_ND_PROVIDER( 1 )
#define IOCTL_ND_PROVIDER_QUERY_ADDRESS_LIST		IOCTL_ND_PROVIDER( 2 )
#define IOCTL_ND_PROVIDER_RESOLVE_ADDRESS		IOCTL_ND_PROVIDER( 3 )
#define IOCTL_ND_PROVIDER_MAX_OPERATION			4

/* Adapter IOCTLs */
#define IOCTL_ND_ADAPTER_OPEN				IOCTL_ND_ADAPTER( 0 )
#define IOCTL_ND_ADAPTER_CLOSE				IOCTL_ND_ADAPTER( 1 )
#define IOCTL_ND_ADAPTER_QUERY				IOCTL_ND_ADAPTER( 2 )
#define IOCTL_ND_ADAPTER_QUERY_ADDRESS_LIST		IOCTL_ND_ADAPTER( 3 )
#define IOCTL_ND_ADAPTER_MAX_OPERATION			4

/* Protection Domain IOCTLs */
#define IOCTL_ND_PD_CREATE				IOCTL_ND_PD( 0 )
#define IOCTL_ND_PD_FREE				IOCTL_ND_PD( 1 )
#define IOCTL_ND_PD_MAX_OPERATION			2

/* Completion Queue IOCTLs */
#define IOCTL_ND_CQ_CREATE				IOCTL_ND_CQ( 0 )
#define IOCTL_ND_CQ_FREE				IOCTL_ND_CQ( 1 )
#define IOCTL_ND_CQ_CANCEL_IO				IOCTL_ND_CQ( 2 )
#define IOCTL_ND_CQ_GET_AFFINITY			IOCTL_ND_CQ( 3 )
#define IOCTL_ND_CQ_MODIFY				IOCTL_ND_CQ( 4 )
#define IOCTL_ND_CQ_NOTIFY				IOCTL_ND_CQ( 5 )
#define IOCTL_ND_CQ_MAX_OPERATION			6

/* Memory Region IOCTLs */
#define IOCTL_ND_MR_CREATE				IOCTL_ND_MR( 0 )
#define IOCTL_ND_MR_FREE				IOCTL_ND_MR( 1 )
#define IOCTL_ND_MR_CANCEL_IO				IOCTL_ND_MR( 2 )
#define IOCTL_ND_MR_REGISTER				IOCTL_ND_MR( 3 )
#define IOCTL_ND_MR_DEREGISTER				IOCTL_ND_MR( 4 )
#define IOCTL_NDK_MR_REGISTER				IOCTL_ND_MR( 5 )
#define IOCTL_ND_MR_MAX_OPERATION			6

/* Memory Window IOCTLs */
#define IOCTL_ND_MW_CREATE				IOCTL_ND_MW( 0 )
#define IOCTL_ND_MW_FREE				IOCTL_ND_MW( 1 )
#define IOCTL_ND_MW_MAX_OPERATION			2

/* Shared Receive Queue IOCTLs */
#define IOCTL_ND_SRQ_CREATE				IOCTL_ND_SRQ( 0 )
#define IOCTL_ND_SRQ_FREE				IOCTL_ND_SRQ( 1 )
#define IOCTL_ND_SRQ_CANCEL_IO				IOCTL_ND_SRQ( 2 )
#define IOCTL_ND_SRQ_GET_AFFINITY			IOCTL_ND_SRQ( 3 )
#define IOCTL_ND_SRQ_MODIFY				IOCTL_ND_SRQ( 4 )
#define IOCTL_ND_SRQ_NOTIFY				IOCTL_ND_SRQ( 5 )
#define IOCTL_ND_SRQ_MAX_OPERATION			6

/* Connector IOCTLs */
#define IOCTL_ND_CONNECTOR_CREATE			IOCTL_ND_CONNECTOR( 0 )
#define IOCTL_ND_CONNECTOR_FREE				IOCTL_ND_CONNECTOR( 1 )
#define IOCTL_ND_CONNECTOR_CANCEL_IO			IOCTL_ND_CONNECTOR( 2 )
#define IOCTL_ND_CONNECTOR_BIND				IOCTL_ND_CONNECTOR( 3 )
#define IOCTL_ND_CONNECTOR_CONNECT			IOCTL_ND_CONNECTOR( 4 )
#define IOCTL_ND_CONNECTOR_COMPLETE_CONNECT		IOCTL_ND_CONNECTOR( 5 )
#define IOCTL_ND_CONNECTOR_ACCEPT			IOCTL_ND_CONNECTOR( 6 )
#define IOCTL_ND_CONNECTOR_REJECT			IOCTL_ND_CONNECTOR( 7 )
#define IOCTL_ND_CONNECTOR_GET_READ_LIMITS		IOCTL_ND_CONNECTOR( 8 )
#define IOCTL_ND_CONNECTOR_GET_PRIVATE_DATA		IOCTL_ND_CONNECTOR( 9 )
#define IOCTL_ND_CONNECTOR_GET_PEER_ADDRESS		IOCTL_ND_CONNECTOR( 10 )
#define IOCTL_ND_CONNECTOR_GET_ADDRESS			IOCTL_ND_CONNECTOR( 11 )
#define IOCTL_ND_CONNECTOR_NOTIFY_DISCONNECT		IOCTL_ND_CONNECTOR( 12 )
#define IOCTL_ND_CONNECTOR_DISCONNECT			IOCTL_ND_CONNECTOR( 13 )
#define IOCTL_ND_CONNECTOR_MAX_OPERATION		14

/* Listener IOCTLs */
#define IOCTL_ND_LISTENER_CREATE			IOCTL_ND_LISTENER( 0 )
#define IOCTL_ND_LISTENER_FREE				IOCTL_ND_LISTENER( 1 )
#define IOCTL_ND_LISTENER_CANCEL_IO			IOCTL_ND_LISTENER( 2 )
#define IOCTL_ND_LISTENER_BIND				IOCTL_ND_LISTENER( 3 )
#define IOCTL_ND_LISTENER_LISTEN			IOCTL_ND_LISTENER( 4 )
#define IOCTL_ND_LISTENER_GET_ADDRESS			IOCTL_ND_LISTENER( 5 )
#define IOCTL_ND_LISTENER_GET_CONNECTION_REQUEST	IOCTL_ND_LISTENER( 6 )
#define IOCTL_ND_LISTENER_MAX_OPERATION			7

/* Queue Pair IOCTLs */
#define IOCTL_ND_QP_CREATE				IOCTL_ND_QP( 0 )
#define IOCTL_ND_QP_CREATE_WITH_SRQ			IOCTL_ND_QP( 1 )
#define IOCTL_ND_QP_FREE				IOCTL_ND_QP( 2 )
#define IOCTL_ND_QP_FLUSH				IOCTL_ND_QP( 3 )
#define IOCTL_ND_QP_MAX_OPERATION			4

/* Kernel-mode only IOCTLs (IRP_MJ_INTERNAL_DEVICE_CONTROL) */
#define IOCTL_NDV_PARTITION_RESOLVE_ADAPTER_ID	IOCTL_ND_VIRTUAL_PARTITION( 0 )
#define IOCTL_NDV_PARTITION_CREATE		IOCTL_ND_VIRTUAL_PARTITION( 1 )
#define IOCTL_NDV_PARTITION_FREE		IOCTL_ND_VIRTUAL_PARTITION( 2 )
#define IOCTL_NDV_PARTITION_BIND		IOCTL_ND_VIRTUAL_PARTITION( 3 )
#define IOCTL_NDV_PARTITION_UNBIND		IOCTL_ND_VIRTUAL_PARTITION( 4 )
#define IOCTL_NDV_PARTITION_BIND_LUID		IOCTL_ND_VIRTUAL_PARTITION( 5 )
#define IOCTL_NDV_PARTITION_MAX_OPERATION	6


#define MB_SHIFT 20


/* Ringbuffer size for the channel */
#define NDV_NUM_PAGES_IN_RING_BUFFER 64

#define NDV_MAX_PACKETS_PER_RECEIVE 8

#define NDV_MAX_PACKET_COUNT    16304

#define NDV_MAX_NUM_OUTSTANDING_RECEIVED_PACKETS (16304)
#define NDV_MAX_HANDLE_TABLE_SIZE (16304)
#define NDV_HOST_MAX_HANDLE_TABLE_SIZE (NDV_MAX_HANDLE_TABLE_SIZE * 16)


#define NDV_MAX_MAPPINGS 4

#define NDV_STATE_NONE			0x00000000
#define NDV_STATE_CREATED		0x00000001
#define NDV_STATE_CONNECTING		0x00000002
#define NDV_STATE_INITIALIZING		0x00000003
#define NDV_STATE_OPERATIONAL		0xEFFFFFFF
#define NDV_STATE_FAILED		0xFFFFFFFF


#define NDV_MAX_PRIVATE_DATA_SIZE 64
#define NDV_MAX_IOCTL_SIZE        256

/* max size of buffer for vector of ND_MAPPING */
#define NDV_MAX_MAPPING_BUFFER_SIZE \
	(NDV_MAX_MAPPINGS * sizeof(union nd_mapping))

/* max expected ioctl buffer size from users */
#define NDV_MAX_IOCTL_BUFFER_SIZE \
	(NDV_MAX_IOCTL_SIZE + \
	NDV_MAX_MAPPING_BUFFER_SIZE + \
	NDV_MAX_PRIVATE_DATA_SIZE)

/*  max PFN array for inline buffers */
#define NDV_MAX_INLINE_PFN_ARRAY_LENGTH 32

/* Field header size for inline buffer */
#define NDV_MAX_MAPPING_PACKET_FILED_BUFFER_SIZE \
	(NDV_MAX_MAPPINGS * sizeof(NDV_PACKET_FIELD))

/* Max for a single field */

#define NDV_MAX_SINGLE_MAPPING_FIELD  ( sizeof(GPA_RANGE) + \
	(sizeof(PFN_NUMBER) * NDV_MAX_INLINE_PFN_ARRAY_LENGTH))

/* Max for all inine data */

#define NDV_MAX_MAPPING_DATA_SIZE (NDV_MAX_MAPPING_PACKET_FILED_BUFFER_SIZE + \
	(NDV_MAX_MAPPINGS * NDV_MAX_SINGLE_MAPPING_FIELD))


#define NDV_MAX_PACKET_HEADER_SIZE 256

#define NDV_MAX_PACKET_SIZE    (NDV_MAX_PACKET_HEADER_SIZE + \
				NDV_MAX_IOCTL_BUFFER_SIZE + \
				NDV_MAX_MAPPING_DATA_SIZE)

/* Well known message type INIT is defined for the channel
 * not for the protocol.
 */

#define NDV_PACKET_TYPE_INIT  0xFFFFFFFF

/* Invalid protocol version to to identify uninitialized channels */

#define NDV_PROTOCOL_VERSION_INVALID  0xFFFFFFFF

/* Flags that control the bahavior of packet handling */

enum ndv_packet_options {
	NDV_PACKET_OPTION_NONE = 0x00,

	/* Indicates that the ExternalDataMdl parameter is expectected to be
	 * passed and must be handled in the reciever.  This call must be
	 * handled specially to ensure that the MDL can be created correctly.
	 */
	NDV_PACKET_OPTION_EXTERNAL_DATA = 0x01,

	/* Inicates that the reciever must execution the handler at passive. */
	NDV_PACKET_OPTIONS_REQUIRES_PASSIVE = 0x02,

	/* Indicates that the sender does not expect and is not waiting for a
	 * response packet.
	 */
	NDV_PACKET_OPTIONS_POST = 0x04,
};

#define NDV_PACKET_TYPE(id_, opt_) \
	(((opt_)<<24) | (id_))

#define NDV_PACKET_TYPE_OPTIONS(type_) \
	(((type_) >> 24) & 0xFF)

#define NDV_PACKET_TYPE_ID(type_) \
	((type_) & 0xFFFFFF) \

#define NDV_ADD_PACKET_OPTION(type_, opt_) \
	(type_) |= (opt_<<24)

/* The header value sent on all packets */
union ndv_packet_hdr {

	struct {
		/* The type of packet.
		 * This value should be created with the NDV_PACKET_TYPE macro
		 * to include all packet options within the packet type.
		 */
		u32 packet_type;
		/* The size of the entire fixed message structure that exists
		 * before the data. This must be >= sizeof(NDV_PACKET_HEADER)
		 */
		u32 hdr_sz;
		/* This size of the data that follows the message
		 * data_sz + hdr_sz size gives the total size of
		 * the buffer that is used.
		 */
		u32 data_sz;
		/* The status code used to indicate success or failure.
		 * It is only used in completions and during responses.
		 */
		u32 status; //KYS: NTSTATUS?
	};

	u64 padding[2]; //KYS: why?
}; 


/* The core INIT packet.  This message is defined in the channel
 * not in the protocol.  This message should never change size
 * or behavior, as it could impact compatibility in the future.
 * This packet is used to negotiate the protocol version, so chaning
 * this size could break backward compat.
 */

union ndv_packet_init {
	struct {
		u32 packet_type;
		u32 protocol_version;
		u32 flags;
	};
	u64 padding[2];
}  __packed;

#define NDV_PACKET_INIT_SIZE 16

/* Data packing flags used for accessing the dynamic fields inside a packet */
#define NDV_DATA_PACKING_2 0x1
#define NDV_DATA_PACKING_4 0x3
#define NDV_DATA_PACKING_8 0x7


#define NDV_PROTOCOL_VERSION_1        0x0100
#define NDV_PROTOCOL_VERSION_CURRENT  NDV_PROTOCOL_VERSION_1
#define NDV_PROTOCOL_VERSION_COUNT    1

struct ndv_pkt_field {
	u32 size;
	u32 offset;
};

enum ndv_pkt_id {
	NDV_PKT_UNKNOWN = 0,
	/* Version 1 Message ID's */
	NDV_PKT_ID1_BIND,
	NDV_PKT_ID1_CREATE,
	NDV_PKT_ID1_CLEANUP,
	NDV_PKT_ID1_CANCEL,
	NDV_PKT_ID1_CONTROL,
	NDV_PKT_ID1_COMPLETE,
	NDV_PKT_ID1_INIT_RESOURCES,
};

/* The guest will send this as the first messages just after init
 * The resources are reserved per channel.
 */

struct ndv_pkt_hdr_init_resources_1 {

	union ndv_packet_hdr    pkt_hdr;
	u16 io_space_sz_mb;
	u64 io_space_start;

};



/* The guest will send this packet to the host after channel init
 * to query support for the adapters that are registered.
 */

struct ndv_pkt_hdr_bind_1 {
	union ndv_packet_hdr    pkt_hdr;
	bool unbind;
	union nd_sockaddr_inet ip_address;
	struct if_physical_addr phys_addr;	
	u64 guest_id;
}; 

union ndv_context_handle {
	u64 val64;
	struct {
		u32 local;
		u32 remote;
	};
};

struct ndv_pkt_hdr_create_1 {
	union ndv_packet_hdr    pkt_hdr;

	/* Identifies the object used to track this file handle on both
	 * the guest and the host.  When sent from the guest, it will contain
	 * the guest handle.  On success, the host will populate and return
	 * it's handle value as well.
	 */

	union ndv_context_handle handle;

	/* The parameters sent to the CreateFile call */
	u32  access_mask;
	u32 open_options;

	u16 file_attributes; //KYS: This field must be 64 bit aligned

	u16 share_access; //KYS

	u32 kys_padding; //KYS

	u16  ea_length; //KYS; needs to be 64 bit aligned; what is ea length - unused
};


struct ndv_pkt_hdr_cleanup_1 {
	union ndv_packet_hdr    pkt_hdr;

	/* Identifies the object used to track this file handle on both
	 * the guest and the host.  When sent from the guest, it will contain
	 * the both the guest and host handle values.  The host will use this
	 * value to cleanup its resource, then update its portion of the handle
	 * to NDV_HANDLE_NULL before returning the data back to the guest.
	 */ 
	union ndv_context_handle handle;
};

struct ndv_pkt_hdr_cancel_1 {
	union ndv_packet_hdr    pkt_hdr;
	union ndv_context_handle file_handle;
	union ndv_context_handle irp_handle;
};

struct ndv_bind_port_info {
	//LUID authentication_id; //KYS: LUID?
	bool is_admin;
}; 

struct ndv_extended_data_flds {
	union {
		u32 field_count;
		u64 padding;
	};

	//struct ndv_pkt_field fields[ANYSIZE_ARRAY]; //KYS?
};


struct ndv_packet_hdr_control_1 {
	union ndv_packet_hdr    pkt_hdr;
	/* Identifies the object used to track this file handle on both
	 * the guest and the host.  This should always have both guest
	 * and host handle values inside it.
	 */

	union ndv_context_handle file_handle;
 
	/* The handle information for the allocated irp context object.
	 * This information is used when the host/guest starts the cancelation
	 */
	union ndv_context_handle irp_handle;

	/* The input data describing in the IO control parameters */

	u32 io_cntrl_code;
	u32 output_buf_sz;
	u32 input_buf_sz;
	u32 input_output_buf_offset;

	/* These are used in the return message to indicate the status of the IO
	 * operation and the amount of data written to the output buffer.
	 */
	u32 io_status; //KYS: NTSTATUS?
	u32 bytes_returned;

	/* This contains the field information for additional data that is sent
	 * with the packet that is IOCTL specific.
	 */

	struct ndv_pkt_field extended_data;
};

/*
 * Include MLX specific defines.
 */

#include "mx_abi.h"

/* Driver specific state.
 */

/*
 * We need to have host open a file; some
 * Windows constants for open.
 */
#define STANDARD_RIGHTS_ALL   (0x001F0000L)
#define FILE_ATTRIBUTE_NORMAL (0x80)
#define FILE_SHARE_READ	 (0x00000001)
#define FILE_SHARE_WRITE (0x00000002)
#define FILE_SHARE_DELETE (0x00000004)
#define FILE_FLAG_OVERLAPPED (0x40000000) 
#define FILE_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define CREATE_ALWAYS (2)
#define OPEN_EXISTING (3)

#define RTL_NUMBER_OF(_x) \
		sizeof(_x)/sizeof(_x[0])
/*
 * The context structure tracks the open state.
 */

/*
 * Packet layout for open adaptor.
 */

/*
 * Packet for querying the address list.
 */

union query_addr_list_ioctl {
	struct nd_handle in;
	union nd_sockaddr_inet out[16]; //KYS a max of 16 addresses
};

struct pkt_query_addr_list {
	struct ndv_packet_hdr_control_1 hdr;
	union query_addr_list_ioctl ioctl;
	unsigned long activity_id;
};


struct pkt_fld {
	u32 size;
	u32 offset;
};

struct fld_data {
	union {
		u64 padding;
	};
};

struct extended_data_oad {
	union { 
		u32 cnt;
		u64 padding; 
	};
	/* offsets are from start of extended data struct
	 * and should start on 8 byte boundary
	 */
	struct pkt_fld fields[IBV_GET_CONTEXT_MAPPING_MAX];
};

union oad_ioctl {
	struct nd_open_adapter input;
	struct nd_resource_descriptor resrc_desc;
};

union oad_mappings {
	struct ibv_get_context_req ctx_input;
	struct ibv_get_context_resp ctx_output;
};

struct pkt_nd_open_adapter {
	struct ndv_packet_hdr_control_1 hdr;

	union oad_ioctl ioctl;
	union oad_mappings mappings;

	/*
	 * Extended data.
	 */
	struct extended_data_oad ext_data;
};

/*
 * Create CQ IOCTL.
 */

struct cq_db_gpa {
	u32 byte_count;
	u32 byte_offset;
	u64 pfn_array[2];
};

struct cq_sn_gpa {
	u32 byte_count;
	u32 byte_offset;
	u64 pfn_array[2];
};

struct create_cq_ext_data {
	union { 
		u32 cnt;
		u64 padding; 
	};
	/* offsets are from start of extended data struct
	 * and should start on 8 byte boundary
	 */
	struct pkt_fld fields[MLX4_IB_CREATE_CQ_MAPPING_MAX];
	struct cq_db_gpa db_gpa;
	struct cq_sn_gpa sn_gpa;
	struct gpa_range cqbuf_gpa;
};

union create_cq_ioctl {
	struct nd_create_cq input;
	struct nd_resource_descriptor resrc_desc;
};

union create_cq_mappings {
	struct ibv_create_cq cq_in;
	struct ibv_create_cq_resp cq_resp;
};

struct pkt_nd_create_cq {
	struct ndv_packet_hdr_control_1 hdr;

	union create_cq_ioctl ioctl;
	union create_cq_mappings mappings;

	/*
	 * Extended data.
	 */
	struct create_cq_ext_data ext_data;
};

/*
 * IOCTL to free CQ.
 */
struct free_cq_ioctl {
	struct nd_handle in;
};

struct pkt_nd_free_cq {
	struct ndv_packet_hdr_control_1 hdr;

	struct  free_cq_ioctl ioctl;
};


/*
 * IOCTL to QUERY CQ - CQ NOTIFY
 */

struct notify_cq_ioctl {
	struct nd_cq_notify in;
};

struct pkt_nd_notify_cq {
	struct ndv_packet_hdr_control_1 hdr;
	struct notify_cq_ioctl ioctl;
};

/*
 * IOCTL to Create a listner
 */

struct nd_ep_create {
	struct nd_handle hdr;
	bool to_semantics;
	unsigned long activity_id;
};

union listener_cr_ioctl {
	struct nd_ep_create in;
	u64  out;
};

struct pkt_nd_cr_listener {
	struct ndv_packet_hdr_control_1 hdr;
	union listener_cr_ioctl ioctl;
};

/*
 * IOCTL to free listener.
 */

struct listener_free_ioctl {
	struct nd_handle in;
};

struct pkt_nd_free_listener {
	struct ndv_packet_hdr_control_1 hdr;
	struct listener_free_ioctl ioctl;
};

/*
 * IOCTL for listener cancel IO.
 */
struct listener_cancelio_ioctl {
	struct nd_handle in;
};

struct pkt_nd_cancelio_listener {
	struct ndv_packet_hdr_control_1 hdr;
	struct listener_cancelio_ioctl ioctl;
};

/*
 * IOCTL for LISTENER BIND
 */

union listener_bind_ioctl {
	struct ndk_bind  in;
};

struct pkt_nd_bind_listener {
	struct ndv_packet_hdr_control_1 hdr;
	union listener_bind_ioctl ioctl;
};

/*
 * After the listener is bound, enable
 * listening.
 */

union listener_listen_ioctl {
	struct nd_listen  in;
};

struct pkt_nd_listen_listener {
	struct ndv_packet_hdr_control_1 hdr;
	union listener_listen_ioctl ioctl;
};

/*
 * IOCTL for getting the adddress from listener.
 *
 */

union listener_get_addr_ioctl {
	struct nd_handle  in;
	union nd_sockaddr_inet out;
};

struct pkt_nd_get_addr_listener {
	struct ndv_packet_hdr_control_1 hdr;
	union listener_get_addr_ioctl ioctl;
};

/*
 * IOCTL to get a connection from a listener.
 */

union listener_get_connection_ioctl {
	struct nd_get_connection_request  in;
	union nd_sockaddr_inet out;
};

struct pkt_nd_get_connection_listener {
	struct ndv_packet_hdr_control_1 hdr;
	union listener_get_connection_ioctl ioctl;
};


/*
 * Connector IOCTLs
 */

/*
 * IOCTL to create connector.
 */

union connector_cr_ioctl { //KYS should this be a union or struct?
	struct nd_ep_create in;
	u64  out;
};

struct pkt_nd_cr_connector {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_cr_ioctl ioctl; //KYS: union or struct
};

/*
 * IOCTL to free connector.
 */
 
struct connector_free_ioctl {
	struct nd_handle in;
};

struct pkt_nd_free_connector {
	struct ndv_packet_hdr_control_1 hdr;
	struct connector_free_ioctl ioctl;
};

/*
 * IOCTL to cancel I/O on a connector.
 */

struct connector_cancelio_ioctl {
	struct nd_handle in;
};

struct pkt_nd_cancelio_connector {
	struct ndv_packet_hdr_control_1 hdr;
	struct connector_cancelio_ioctl ioctl;
};

/*
 * IOCTL to Bind an address to the connector.
 */

union connector_bind_ioctl {
	struct ndk_bind  in;
};

struct pkt_nd_bind_connector {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_bind_ioctl ioctl;
};

/*
 * IOCTL to connect a connector.
 */

struct connector_connect_in {
	struct nd_connect hdr;
	u8 retry_cnt;
	u8 rnr_retry_cnt;
	u8 priv_data[56];
	unsigned long activity_id;
};

union connector_connect_ioctl {
	struct connector_connect_in in;
};

struct pkt_nd_connector_connect {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_connect_ioctl ioctl;
};

/*
 * IOCTL for connector complete connect
 */

struct complete_connect_in {
	struct nd_handle hdr;
	u8 rnr_nak_to;
	unsigned long activity_id;
};

struct complete_connect_out {
	enum ibv_qp_state state;
};

union connector_complete_connect_ioctl {
	struct complete_connect_in in;
	struct complete_connect_out out;
};

struct pkt_nd_connector_connect_complete {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_complete_connect_ioctl ioctl;
};


#define MAX_PRIVATE_DATA_LEN	148

/*
 * IOCTL for connector accept.
 */

struct connector_accept_in {
	struct nd_accept hdr;
	u8 rnr_retry_cnt;
	u8 rnr_nak_to;
	u8 private_data[MAX_PRIVATE_DATA_LEN];
	unsigned long activity_id;
};

struct connector_accept_out {
	enum ibv_qp_state state;
};

union connector_accept_ioctl {
	struct connector_accept_in in;
	struct connector_accept_out out;
};

struct pkt_nd_connector_accept {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_accept_ioctl ioctl;
};

/*
 * IOCTL for connector to reject a connection.
 */

struct connector_reject_in {
	struct nd_reject hdr;
	u8 private_data[MAX_PRIVATE_DATA_LEN];
};

struct connector_reject_out {
	enum ibv_qp_state state;
};

union connector_reject_ioctl {
	struct connector_reject_in in;
	struct connector_reject_out out;
};

struct pkt_nd_connector_reject {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_reject_ioctl ioctl;
};

/*
 * IOCTL to get connector read limits.
 */

struct connector_get_rd_limits_in {
	struct nd_handle in;
};

struct connector_get_rd_limits_out {
	struct nd_read_limits out;
};

union connector_get_rd_limits_ioctl {
	struct connector_get_rd_limits_in in;
	struct connector_get_rd_limits_out out;
};

struct pkt_nd_connector_get_rd_limits {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_get_rd_limits_ioctl ioctl;
};

/*
 * IOCTL to get connector private data.
 */
union connector_get_priv_data_ioctl {
	struct nd_handle in;
	u8 out[MAX_PRIVATE_DATA_LEN];
};

struct pkt_nd_connector_get_priv_data {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_get_priv_data_ioctl ioctl;
};


/*
 * IOCTL get peer address.
 */

union connector_get_peer_addr_ioctl {
	struct nd_handle in;
	union nd_sockaddr_inet out;
};

struct pkt_nd_connector_get_peer_addr {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_get_peer_addr_ioctl ioctl;
};

/*
 * IOCTL to get connector address.
 */

union connector_get_addr_ioctl {
	struct nd_handle in;
	union nd_sockaddr_inet out;
};

struct pkt_nd_connector_get_addr {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_get_addr_ioctl ioctl;
};

/*
 * IOCTL for disconnect notification.
 */

union connector_notify_disconnect_ioctl {
	struct nd_handle in;
};

struct pkt_nd_connector_notify_disconnect {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_notify_disconnect_ioctl ioctl;
};

union connector_disconnect_ioctl {
	struct nd_handle in;
};

struct pkt_nd_connector_disconnect {
	struct ndv_packet_hdr_control_1 hdr;
	union connector_notify_disconnect_ioctl ioctl;
};

/*
 * IOCTLs for QP operations.
 */

/*
 * Create qp IOCTL.
 */

struct qp_db_gpa {
	u32 byte_count;
	u32 byte_offset;
	u64 pfn_array[1];
};

struct create_qp_ext_data {
	union { 
		u32 cnt;
		u64 padding; 
	};
	/* offsets are from start of extended data struct
	 * and should start on 8 byte boundary
	 */
	struct pkt_fld fields[MLX4_IB_CREATE_QP_MAPPINGS_MAX];
	struct qp_db_gpa db_gpa;
	struct gpa_range qpbuf_gpa;
};

union create_qp_ioctl {
	struct nd_create_qp input;
	struct nd_resource_descriptor resrc_desc;
};

union create_qp_mappings {
	struct ibv_create_qp qp_in;
	struct ibv_create_qp_resp qp_resp;
};

struct pkt_nd_create_qp {
	struct ndv_packet_hdr_control_1 hdr;

	union create_qp_ioctl ioctl;
	union create_qp_mappings mappings;

	/*
	 * Extended data.
	 */
	struct create_qp_ext_data ext_data;
};

/*
 * IOCTL to flush a QP.
 */
struct flush_qp_ioctl {
	struct nd_handle in;
	enum ibv_qp_state out;
};

struct pkt_nd_flush_qp {
	struct ndv_packet_hdr_control_1 hdr;
	struct flush_qp_ioctl ioctl;
};

/*
 * Memory Region IOCTLS
 */
union create_mr_ioctl {
	struct nd_handle in;
	u64 out;
};

struct pkt_nd_create_mr {
	struct ndv_packet_hdr_control_1 hdr;
	union create_mr_ioctl ioctl;
};

struct mr_out {
	u32 lkey;
	u32 rkey;
	unsigned long activity_id;
};


union register_mr_ioctl {
	struct nd_mr_register in;
	struct mr_out out; 
};

struct pkt_nd_register_mr {
	struct ndv_packet_hdr_control_1 hdr;
	union  register_mr_ioctl ioctl;
};

struct deregister_mr_ioctl {
	struct nd_handle in;
};

struct pkt_nd_deregister_mr {
	struct ndv_packet_hdr_control_1 hdr;
	struct deregister_mr_ioctl ioctl;
};

/*
 * IOCTL to disconnect connector
 */

/*
 * Create PD IOCTL.
 */
struct nd_create_pd_ioctl {
	union {
		struct nd_handle in;
		u64 out_handle;
	};
	struct ibv_alloc_pd_resp resp;
};

struct pkt_nd_pd_create {
	struct ndv_packet_hdr_control_1 hdr;
	struct nd_create_pd_ioctl ioctl;
};

/*
 * Free Handle. Check the layout with Luke.
 *
 */
struct free_handle_ioctl {
	struct nd_handle in;
};

struct pkt_nd_free_handle {
	struct ndv_packet_hdr_control_1 hdr;
	struct free_handle_ioctl ioctl;
};

/*
 * Cancel I/O.
 */

struct cancel_io_ioctl {
	struct nd_handle in;
};

struct pkt_nd_cancel_io {
	struct ndv_packet_hdr_control_1 hdr;
	struct cancel_io_ioctl ioctl;
};

/*
 * Connector states:
 */

enum connector_state {
	HVND_CON_INCOMING,
	HVND_CON_INCOMING_ESTABLISHED,
	HVND_CON_INCOMING_REJECTED,
	HVND_CON_OUTGOING_REQUEST
};


/*
 * Adaptor query IOCTL.
 */
struct nd_adap_query_ioctl {
	union {
		struct nd_adapter_query ad_q;
		struct adapter_info_v2 ad_info;
	};
};

struct pkt_nd_query_adaptor {
	struct ndv_packet_hdr_control_1 hdr;
	struct nd_adap_query_ioctl ioctl;
};

struct  nd_ioctl {
	union {
		struct nd_handle handle;
		u8 raw_buffer[NDV_MAX_IOCTL_BUFFER_SIZE];
	};
};

struct pkt_nd_provider_ioctl {
	struct ndv_packet_hdr_control_1 hdr;
	struct nd_ioctl ioctl;
};

struct hvnd_ib_pd {
	struct ib_pd ibpd;
	u32	pdn;
	u64	handle;
};

struct hvnd_work {
	struct work_struct work;
	void *callback_arg;
};

struct hvnd_disconnect_work {
	struct work_struct work;
	int status;
	void *callback_arg;
};

/*
struct hvnd_delayed_work {
	struct delayed_work work;
	void *callback_arg;
};
*/

enum hvnd_cm_state {
	hvnd_cm_idle = 0,
	hvnd_cm_connect_reply_sent, 	//active
	hvnd_cm_connect_reply_refused,
	hvnd_cm_connect_received,	//active
	hvnd_cm_connect_request_sent,	//passive
	hvnd_cm_accept_sent,
	hvnd_cm_close_sent,
	hvnd_cm_established_sent,
};

struct incoming_pkt {
	struct list_head list_entry;
	char pkt[0];
};

struct hvnd_ep_obj {
/*
	spinlock_t ep_lk;
	bool to_be_destroyed;
	bool io_outstanding;

	wait_queue_head_t wait;
	bool stopped;
	atomic_t process_refcnt; // how many NDV_PKT_ID1_COMPLETE packets we are currently processing
*/
	bool stopping;
	wait_queue_head_t wait_pending;
	atomic_t nr_requests_pending;

	enum nd_resource_type type;
	enum connector_state state; //KYS need to look at locking
	struct iw_cm_id *cm_id;
	enum hvnd_cm_state cm_state;
	struct completion block_event;
	struct completion disconnect_event;
	struct completion connector_accept_event;
	int connector_accept_status;
	u64 ep_handle;
	spinlock_t      incoming_pkt_list_lock;
	struct list_head incoming_pkt_list;
	struct hvnd_ep_obj *parent;
	struct hvnd_dev *nd_dev;
	struct hvnd_ucontext *uctx;
	struct hvnd_work wrk;
	struct hvnd_cq *cq;
	u8 ord;
	u8 ird;
	char priv_data[MAX_PRIVATE_DATA_LEN];
	bool incoming;
	atomic_t disconnect_notified;
	u64 outstanding_handle;
	u32 local_irp;
	struct hvnd_ep_obj *outstanding_ep;
	struct pkt_nd_connector_connect connector_connect_pkt;
	int connector_connect_retry;
};

struct hvnd_ucontext {
	struct ib_ucontext      ibucontext;
	struct list_head listentry;
	struct ndv_pkt_hdr_create_1 create_pkt;
	struct ndv_pkt_hdr_create_1 create_pkt_ovl; /* Overlap handle */
	struct pkt_nd_provider_ioctl pr_init_pkt;
	union ndv_context_handle file_handle;
	union ndv_context_handle file_handle_ovl;

	struct pkt_nd_open_adapter o_adap_pkt;

	u64 adaptor_hdl;

	/*
	 * Protection domain state.
	 */
	struct pkt_nd_pd_create pd_cr_pkt;

	u64 uar_base;
	u64 bf_base;
	u32 bf_buf_size;
	u32 bf_offset;
	u32 cqe_size;
	u32 max_qp_wr;
	u32 max_sge;
	u32 max_cqe;
	u32 num_qps;

	/*
	 * State to manage dorbell pages:
	 */
	struct list_head        db_page_list;
	struct mutex            db_page_mutex;

	atomic_t refcnt;

};

struct hvnd_dev {
	struct ib_device ibdev;
	struct hv_device *hvdev;
	u32 device_cap_flags;
	unsigned char nports;
	bool ib_active;

	/* State to manage interaction with the host.
	 */

	spinlock_t uctxt_lk;
	struct list_head listentry;
	
	unsigned long mmio_sz;
	unsigned long mmio_start_addr;
	struct resource mmio_resource;
	void *mmio_virt;

	unsigned long negotiated_version;
	union ndv_packet_init init_pkt;
	struct ndv_pkt_hdr_init_resources_1 resources; 
	struct ndv_pkt_hdr_bind_1 bind_pkt;

	struct ndv_pkt_hdr_create_1 global_create_pkt;
	union ndv_context_handle global_file_handle;

	struct semaphore query_pkt_sem;
	bool query_pkt_set;
	struct pkt_nd_query_adaptor query_pkt;

	/*
	 * ID tables.
	 */
	spinlock_t id_lock;

	struct idr cqidr;
	struct idr qpidr;
	struct idr mmidr;
	struct idr irpidr;
	struct idr uctxidr;
	atomic_t open_cnt;

	char ip_addr[4];
	char mac_addr[6];
	struct completion addr_set;
	int bind_complete;
	struct mutex bind_mutex;
};

struct hvnd_cq {
	struct ib_cq ibcq;
	void *cq_buf;
	void *db_addr;
	u32 arm_sn;
	u32 entries;

	u32 cqn;
	u32 cqe;
	u64 cq_handle;

	struct ib_umem         *umem;
	struct ib_umem	*db_umem;
	struct mlx4_ib_user_db_page user_db_page;
	struct hvnd_ucontext *uctx;
	struct hvnd_ep_obj ep_object; //KYS need to clean this up; have a cq irp state
	bool monitor;
	bool upcall_pending;
};

struct hvnd_qp {
	struct ib_qp ibqp;
	void *qp_buf;
	void *db_addr;
	u32  buf_size;
	u8   port;
	struct hvnd_dev *nd_dev;

	__u8    log_sq_bb_count;
	__u8    log_sq_stride;
	__u8    sq_no_prefetch;

	int rq_wqe_cnt;
	int rq_wqe_shift;
	int rq_max_gs;

	int sq_wqe_cnt;
	int sq_wqe_shift;
	int sq_max_gs;

	u32 max_inline_data;

	u32 initiator_q_depth;
	u32 initiator_request_sge;

	u32 receive_q_depth;
	u32 receive_request_sge;

	struct hvnd_cq *recv_cq;
	struct hvnd_cq *send_cq;

	u64 receive_cq_handle;
	u64 initiator_cq_handle;
	u64 pd_handle;

	u64 qp_handle;
	u32 qpn;
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 max_send_sge;
	u32 max_recv_sge;

	struct ib_umem         *umem;
	struct ib_umem	*db_umem;
	struct mlx4_ib_user_db_page user_db_page;
	struct hvnd_ucontext *uctx;
	struct iw_cm_id *cm_id;

	/*
	 * Current QP state; need to look at locking.
	 * XXXKYS
	 */
	enum ib_qp_state qp_state;
	bool cq_notify;
	wait_queue_head_t wait;
	atomic_t refcnt;
	struct hvnd_ep_obj *connector;
};

struct hvnd_mr {
	struct ib_mr ibmr;
	struct hvnd_ib_pd *pd;
	struct ib_umem *umem;
	u64 start;
	u64 length;
	u64 virt;
	int acc;
	u64 mr_handle;
	u32 mr_lkey;
	u32 mr_rkey;
};

struct hvnd_cookie {
	struct completion host_event;
	void *pkt;
};

/*
 * Definitions to retrieve the IP address.
 */

#define HVND_CURRENT_VERSION 0

struct hvnd_ipaddr_tuple {
	char mac_address[ETH_ALEN];
	struct sockaddr addr;
};

struct hvnd_msg {
	int status;
	struct hvnd_ipaddr_tuple ip_tuple;
};

static inline struct hvnd_ib_pd *to_nd_pd(struct ib_pd *pd)
{
	return container_of(pd, struct hvnd_ib_pd, ibpd);
}

static inline struct hvnd_dev *to_nd_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct hvnd_dev, ibdev);
}

static inline struct hvnd_cq *to_nd_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct hvnd_cq, ibcq);
}

static inline struct hvnd_qp *to_nd_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct hvnd_qp, ibqp);
}

static inline struct hvnd_ucontext *to_nd_context(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct hvnd_ucontext, ibucontext);
}

static inline struct hvnd_ucontext *get_uctx_from_pd(struct ib_pd *pd)
{
	return to_nd_context(pd->uobject->context);
}

static inline struct hvnd_mr *to_nd_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct hvnd_mr, ibmr);
}
/*
 * ID management.
 */

static inline int insert_handle(struct hvnd_dev *dev, struct idr *idr,
				void *handle, u32 id)
{
	int ret;
	unsigned long flags;
#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
	int newid;
	do {
		if (!idr_pre_get(idr, GFP_KERNEL)) {
			return -ENOMEM;
		}
		spin_lock_irqsave(&dev->id_lock, flags);
		ret = idr_get_new_above(idr, handle, id, &newid);
		if (ret != -EAGAIN && newid != id) {
			spin_unlock_irqrestore(&dev->id_lock, flags);
			WARN(1, "hvnd insert_handle: idr allocation failed id=%d newid=%d ret=%d\n", id, newid, ret);
			ret = -ENOSPC;
			break;
		}
		spin_unlock_irqrestore(&dev->id_lock, flags);
	} while (ret == -EAGAIN);
	return ret;
#else
	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&dev->id_lock, flags);
	ret = idr_alloc(idr, handle, id, id + 1, GFP_ATOMIC);
	spin_unlock_irqrestore(&dev->id_lock, flags);
	idr_preload_end();

	WARN(ret < 0, "Failed to allocate for id=%d ret=%d\n", id, ret);
	return ret < 0 ? ret : 0;
#endif
}

static inline void remove_handle(struct hvnd_dev *dev, struct idr *idr, u32 id)
{
	unsigned long flags;
	
	spin_lock_irqsave(&dev->id_lock, flags);
	idr_remove(idr, id);
	spin_unlock_irqrestore(&dev->id_lock, flags);
}

static inline struct hvnd_cq *get_cqp(struct hvnd_dev *dev, u32 cqid)
{
	struct hvnd_cq *cqp;
	unsigned long flags;

	spin_lock_irqsave(&dev->id_lock, flags);
	cqp =  idr_find(&dev->cqidr, cqid);
	spin_unlock_irqrestore(&dev->id_lock, flags);

	return cqp;
}

static inline struct hvnd_qp *get_qpp(struct hvnd_dev *dev, u32 qpid)
{
	struct hvnd_qp *qpp;
	unsigned long flags;

	spin_lock_irqsave(&dev->id_lock, flags);
	qpp = idr_find(&dev->qpidr, qpid);
	spin_unlock_irqrestore(&dev->id_lock, flags);

	return qpp;
}

static inline struct hvnd_ucontext *get_uctx(struct hvnd_dev *dev, u32 pid)
{
	struct hvnd_ucontext *uctx;
	unsigned long flags;

	spin_lock_irqsave(&dev->id_lock, flags);
	uctx = idr_find(&dev->uctxidr, pid);
	spin_unlock_irqrestore(&dev->id_lock, flags);

	return uctx;
}


static inline void *map_irp_to_ctx(struct hvnd_dev *nd_dev, u32 irp)
{
	void *ctx;
	unsigned long flags;

	spin_lock_irqsave(&nd_dev->id_lock, flags);
	ctx = idr_find(&nd_dev->irpidr, irp);
	spin_unlock_irqrestore(&nd_dev->id_lock, flags);

	return ctx;
}



void hvnd_callback(void *context);
int hvnd_negotiate_version(struct hvnd_dev *nd_dev);
int hvnd_init_resources(struct hvnd_dev *nd_dev);
int hvnd_bind_nic(struct hvnd_dev *nd_dev, bool un_bind, char *ip_addr, char *mac_addr);
int hvnd_open_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx);
int hvnd_close_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx);
int hvnd_query_adaptor(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx);
int  hvnd_create_pd(struct hvnd_ucontext *uctx, struct hvnd_dev *nd_dev,
		    struct hvnd_ib_pd *hvnd_pd);

/*
 * CQ operations.
 */
int hvnd_create_cq(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		   struct hvnd_cq *cq);
int hvnd_destroy_cq(struct hvnd_dev *nd_dev, struct hvnd_cq *cq);
int hvnd_notify_cq(struct hvnd_dev *nd_dev, struct hvnd_cq *cq,
		   u32 notify_type, u64 irp_handle);

/*
 * QP operations.
 */
int hvnd_create_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		   struct hvnd_qp *qp);

int hvnd_free_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		 struct hvnd_qp *qp);

int hvnd_flush_qp(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		 struct hvnd_qp *qp);

/*
 * MR operations.
 */

int hvnd_cr_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		u64 pd_handle, u64 *mr_handle);

int hvnd_free_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle);

int hvnd_mr_register(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
		     struct hvnd_mr *mr);
int hvnd_deregister_mr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle);

/*
 * Listner operations
 */
int hvnd_cr_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx, u64 *handle);


int hvnd_free_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle);

int hvnd_bind_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, union nd_sockaddr_inet *addr);

int hvnd_listen_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, u32 backlog);

int hvnd_get_addr_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, union nd_sockaddr_inet *addr);

int hvnd_get_connection_listener(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 listener_handle, u64 connector_handle,
			u64 irp_handle);

/*
 * Connector operations.
 */
int hvnd_cr_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 *connector_handle);

int hvnd_free_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle);

int hvnd_cancelio_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle);
int hvnd_bind_connector(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle, union nd_sockaddr_inet *addr); 

int hvnd_connector_connect(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle, u32 in_rd_limit, u32 out_rd_limit,
			u32 priv_data_length, const u8 *priv_data,
			u64 qp_handle, struct if_physical_addr *phys_addr,
			union nd_sockaddr_inet *dest_addr, struct hvnd_ep_obj *ep);

int hvnd_connector_complete_connect(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,  enum ibv_qp_state *qp_state);

int hvnd_connector_accept(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u64 qp_handle,
			u32 in_rd_limit, u32 out_rd_limit,
			u32 priv_data_length, const u8 *priv_data,
			enum ibv_qp_state *qp_state, struct hvnd_ep_obj *ep);

int hvnd_connector_reject(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u32 priv_data_length, u8 *priv_data,
			enum ibv_qp_state *qp_state);

int hvnd_connector_get_rd_limits(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			struct nd_read_limits *rd_limits);

int hvnd_connector_get_priv_data(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			u8 *priv_data);

int hvnd_connector_get_peer_addr(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			union nd_sockaddr_inet *peer_addr);

int hvnd_connector_get_local_addr(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle,
			union nd_sockaddr_inet *local_addr);

int hvnd_connector_notify_disconnect(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle, struct hvnd_ep_obj *ep);


int hvnd_connector_disconnect(struct hvnd_dev *nd_dev,
			struct hvnd_ucontext *uctx,
			u64 connector_handle, struct hvnd_ep_obj *ep);

int hvnd_free_handle(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
			u64 handle, u32 ioctl);

int hvnd_cancel_io(struct hvnd_ep_obj *ep_object);

char *hvnd_get_op_name(int ioctl);

void hvnd_acquire_uctx_ref(struct hvnd_ucontext *uctx);
void hvnd_drop_uctx_ref(struct hvnd_dev *nd_dev,struct hvnd_ucontext *uctx);
void hvnd_process_events(struct work_struct *work);

void hvnd_process_cq_event_pending(struct hvnd_ep_obj *ep, int status);
void hvnd_process_cq_event_complete(struct hvnd_ep_obj *ep, int status);
void hvnd_process_connector_accept(struct hvnd_ep_obj *ep_object, int status);
void hvnd_process_notify_disconnect(struct hvnd_ep_obj *ep_object, int status);
void hvnd_process_disconnect(struct hvnd_ep_obj *ep_object, int status);

void put_irp_handle(struct hvnd_dev *nd_dev, u32 irp);
int get_irp_handle(struct hvnd_dev *nd_dev, u32 *local, void *irp_ctx);

void hvnd_init_hdr(struct ndv_packet_hdr_control_1 *hdr,
			  u32 data_sz, u32 local, u32 remote,
			  u32 ioctl_code,
			  u32 ext_data_sz, u32 ext_data_offset,
			  u64 irp_handle);

int  hvnd_send_ioctl_pkt(struct hvnd_dev *nd_dev,
				struct ndv_packet_hdr_control_1 *hdr,
				u32 pkt_size, u64 cookie);

int hvnd_get_outgoing_rdma_addr(struct hvnd_dev *nd_dev, struct hvnd_ucontext *uctx,
				union nd_sockaddr_inet *og_addr);

int hvnd_get_neigh_mac_addr(struct sockaddr *local, struct sockaddr *remote, char *mac_addr);

void hvnd_addr_init(void);

void hvnd_addr_deinit(void);

bool ep_add_work_pending(struct hvnd_ep_obj *ep_object);
void ep_del_work_pending(struct hvnd_ep_obj *ep_object);
void ep_stop(struct hvnd_ep_obj *ep_object);

#define current_pid()           (current->pid)
/*
 * NT STATUS defines.
 */

#define STATUS_SUCCESS 0x0
#define STATUS_PENDING 0x00000103
#define STATUS_CANCELLED 0xC0000120
#define STATUS_DISCONNECTED 0xC000020C
#define STATUS_TIMEOUT 0xC00000B5

void inc_ioctl_counter_request(unsigned ioctl);
void inc_ioctl_counter_response(unsigned ioctl);

#define NDV_PROTOCOL_VAERSION_INVALID -1
#define NDV_PACKET_INIT_SIZE 16 /* Size of the INIT packet */

#define HVND_RING_SZ (PAGE_SIZE * 64)

/* logging levels */
#define HVND_ERROR 0
#define HVND_WARN 1
#define HVND_INFO 2
#define HVND_DEBUG 3

extern int hvnd_log_level;

#define hvnd_error(fmt, args...)	hvnd_log(HVND_ERROR, fmt, ##args)
#define hvnd_warn(fmt, args...)		hvnd_log(HVND_WARN, fmt, ##args)
#define hvnd_info(fmt, args...)		hvnd_log(HVND_INFO, fmt, ##args)
#define hvnd_debug(fmt, args...)	hvnd_log(HVND_DEBUG, fmt, ##args)

#define hvnd_log(level, fmt, args...) \
do { \
	if (unlikely(hvnd_log_level >= (level))) \
		printk(KERN_ERR "hvnd %s[%u]: " fmt, __func__, __LINE__, ##args); \
} while (0)

#endif /* _VMBUS_RDMA_H */
