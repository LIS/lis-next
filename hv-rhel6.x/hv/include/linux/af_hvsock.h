#ifndef __AF_HVSOCK_H__
#define __AF_HVSOCK_H__

#include <linux/kernel.h>
#include "hyperv.h"
#include <net/sock.h>

#define VMBUS_RINGBUFFER_SIZE_HVSOCK_RECV (5 * PAGE_SIZE)
#define VMBUS_RINGBUFFER_SIZE_HVSOCK_SEND (5 * PAGE_SIZE)

#define HVSOCK_RCV_BUF_SZ	VMBUS_RINGBUFFER_SIZE_HVSOCK_RECV
#define HVSOCK_SND_BUF_SZ	PAGE_SIZE

#define sk_to_hvsock(__sk)    ((struct hvsock_sock *)(__sk))
#define hvsock_to_sk(__hvsk)   ((struct sock *)(__hvsk))

struct hvsock_sock {
	/* sk must be the first member. */
	struct sock sk;

	struct sockaddr_hv local_addr;
	struct sockaddr_hv remote_addr;

	/* protected by the global hvsock_mutex */
	struct list_head bound_list;
	struct list_head connected_list;

	struct list_head accept_queue;
	/* used by enqueue and dequeue */
	struct mutex accept_queue_mutex;

	struct delayed_work dwork;

	u32 peer_shutdown;

	struct vmbus_channel *channel;

	struct {
		struct vmpipe_proto_header hdr;
		char buf[HVSOCK_SND_BUF_SZ];
	} __packed send;

	struct {
		struct vmpipe_proto_header hdr;
		char buf[HVSOCK_RCV_BUF_SZ];
		unsigned int data_len;
		unsigned int data_offset;
	} __packed recv;
};

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
        return sk->sk_sleep;
}

#if defined(RHEL_RELEASE_UPDATE_CODE) && \
(RHEL_RELEASE_UPDATE_CODE < RHEL_RELEASE_UPDATE_VERSION(6, 4, 358, 18))
#define __sockaddr_check_size(size)	\
        BUILD_BUG_ON(((size) > sizeof(struct __kernel_sockaddr_storage)))
#endif


#endif /* __AF_HVSOCK_H__ */
