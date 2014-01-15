/*
 * An implementation of key value pair (KVP) functionality for Linux.
 *
 *
 * Copyright (C) 2010, Novell, Inc.
 * Author : K. Y. Srinivasan <ksrinivasan@novell.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/net.h>
#include <asm/semaphore.h>
#include <linux/nls.h>
#include <linux/connector.h>
#include <linux/workqueue.h>
#include <linux/cdev.h>
#include <linux/hyperv.h>
#include <linux/cdev.h>

/*
 * Pre win8 version numbers used in ws2008 and ws 2008 r2 (win7)
 */

#define WS2008_SRV_MAJOR	1
#define WS2008_SRV_MINOR	0
#define WS2008_SRV_VERSION	(WS2008_SRV_MAJOR << 16 | WS2008_SRV_MINOR)

#define WIN7_SRV_MAJOR		3
#define WIN7_SRV_MINOR		0
#define WIN7_SRV_VERSION	(WIN7_SRV_MAJOR << 16 | WIN7_SRV_MINOR)

#define WIN8_SRV_MAJOR		4
#define WIN8_SRV_MINOR		0
#define WIN8_SRV_VERSION	(WIN8_SRV_MAJOR << 16 | WIN8_SRV_MINOR)



/*
 * Global state maintained for transaction that is being processed.
 * Note that only one transaction can be active at any point in time.
 *
 * This state is set when we receive a request from the host; we
 * cleanup this state when the transaction is completed - when we respond
 * to the host with the key value.
 */

static struct {
	bool active; /* transaction status - active or not */
	int recv_len; /* number of bytes received. */
	struct hv_kvp_msg  *kvp_msg; /* current message */
	struct hv_kvp_msg  message; /* current message; sent to daemon */
	struct hv_kvp_msg  out_message; /* current message; sent to host */
	struct vmbus_channel *recv_channel; /* chn we got the request */
	u64 recv_req_id; /* request ID. */
	void *kvp_context; /* for the channel callback */
	struct semaphore read_sema;
} kvp_transaction;



static dev_t kvp_dev;
static bool daemon_died = false;
static bool opened; /* currently device opened */
static struct task_struct *dtp; /* daemon task ptr */
/*
 * Before we can accept KVP messages from the host, we need
 * to handshake with the user level daemon. This state tracks
 * if we are in the handshake phase.
 */
static bool in_hand_shake = true;

/*
 * This state maintains the version number registered by the daemon.
 */
static int dm_reg_value;

static void kvp_send_key(void *dummy);


static void kvp_respond_to_host(struct hv_kvp_msg *msg, int error);
static void kvp_work_func(void *dummy);

static DECLARE_DELAYED_WORK(kvp_work, kvp_work_func, &kvp_work);

static u8 *recv_buffer;

static void
kvp_work_func(void *dummy)
{
	/*
	 * If the timer fires, the user-mode component has not responded;
	 * process the pending transaction.
	 */
	kvp_respond_to_host(NULL, HV_E_FAIL);
}

static int kvp_handle_handshake(int op)
{
	int ret = 1;

	switch (op) {
	case KVP_OP_REGISTER1:
		dm_reg_value = KVP_OP_REGISTER1;
		break;
	default:
		pr_info("KVP: incompatible daemon\n");
		pr_info("KVP: KVP version: %d, Daemon version: %d\n",
			KVP_OP_REGISTER1, op);
		ret = 0;
	}

	if (ret) {
		/*
		 * We have a compatible daemon; complete the handshake.
		 */
		pr_info("KVP: user-mode registering done.\n");
		kvp_transaction.active = false;
		set_channel_read_state((struct vmbus_channel *)kvp_transaction.kvp_context,
					true);


		if (kvp_transaction.kvp_context)
			hv_kvp_onchannelcallback(kvp_transaction.kvp_context);

	}
	return ret;
}


static int process_ob_ipinfo(void *in_msg, void *out_msg, int op)
{
	struct hv_kvp_msg *in = in_msg;
	struct hv_kvp_ip_msg *out = out_msg;
	int len;

	switch (op) {
	case KVP_OP_GET_IP_INFO:
		/*
		 * Transform all parameters into utf16 encoding.
		 */
		len = utf8_mbstowcs((wchar_t *)out->kvp_ip_val.ip_addr,
				(char *)in->body.kvp_ip_val.ip_addr,
				strlen((char *)in->body.kvp_ip_val.ip_addr));
		if (len < 0)
			return len;

		len = utf8_mbstowcs((wchar_t *)out->kvp_ip_val.sub_net,
				(char *)in->body.kvp_ip_val.sub_net,
				strlen((char *)in->body.kvp_ip_val.sub_net));
		if (len < 0)
			return len;

		len = utf8_mbstowcs((wchar_t *)out->kvp_ip_val.gate_way,
				(char *)in->body.kvp_ip_val.gate_way,
				strlen((char *)in->body.kvp_ip_val.gate_way));
		if (len < 0)
			return len;

		len = utf8_mbstowcs((wchar_t *)out->kvp_ip_val.dns_addr,
				(char *)in->body.kvp_ip_val.dns_addr,
				strlen((char *)in->body.kvp_ip_val.dns_addr));
		if (len < 0)
			return len;

		len = utf8_mbstowcs((wchar_t *)out->kvp_ip_val.adapter_id,
				(char *)in->body.kvp_ip_val.adapter_id,
				strlen((char *)in->body.kvp_ip_val.adapter_id));
		if (len < 0)
			return len;

		out->kvp_ip_val.dhcp_enabled =
			in->body.kvp_ip_val.dhcp_enabled;
		out->kvp_ip_val.addr_family =
			in->body.kvp_ip_val.addr_family;
	}

	return 0;
}

static void process_ib_ipinfo(void *in_msg, void *out_msg, int op)
{
	struct hv_kvp_ip_msg *in = in_msg;
	struct hv_kvp_msg *out = out_msg;

	switch (op) {
	case KVP_OP_SET_IP_INFO:
		/*
		 * Transform all parameters into utf8 encoding.
		 */
		utf8_wcstombs((__u8 *)out->body.kvp_ip_val.ip_addr,
				(wchar_t *)in->kvp_ip_val.ip_addr,
				MAX_IP_ADDR_SIZE);

		utf8_wcstombs((__u8 *)out->body.kvp_ip_val.sub_net,
				(wchar_t *)in->kvp_ip_val.sub_net,
				MAX_IP_ADDR_SIZE);

		utf8_wcstombs((__u8 *)out->body.kvp_ip_val.gate_way,
				(wchar_t *)in->kvp_ip_val.gate_way,
				MAX_IP_ADDR_SIZE);

		utf8_wcstombs((__u8 *)out->body.kvp_ip_val.dns_addr,
				(wchar_t *)in->kvp_ip_val.dns_addr,
				MAX_IP_ADDR_SIZE);

		out->body.kvp_ip_val.dhcp_enabled = in->kvp_ip_val.dhcp_enabled;

	default:
		utf8_wcstombs((__u8 *)out->body.kvp_ip_val.adapter_id,
				(wchar_t *)in->kvp_ip_val.adapter_id,
				MAX_IP_ADDR_SIZE);

		out->body.kvp_ip_val.addr_family = in->kvp_ip_val.addr_family;
	}
}




static void
kvp_send_key(void *dummy)
{
	struct hv_kvp_msg *message = &kvp_transaction.message;
	struct hv_kvp_msg *in_msg;
	__u8 operation = kvp_transaction.kvp_msg->kvp_hdr.operation;
	__u8 pool = kvp_transaction.kvp_msg->kvp_hdr.pool;
	__u32 val32;
	__u64 val64;

	memset(message, 0, sizeof(struct hv_kvp_msg));

	message->kvp_hdr.operation = operation;
	message->kvp_hdr.pool = pool;
	in_msg = kvp_transaction.kvp_msg;

	/*
	 * The key/value strings sent from the host are encoded in
	 * in utf16; convert it to utf8 strings.
	 * The host assures us that the utf16 strings will not exceed
	 * the max lengths specified. We will however, reserve room
	 * for the string terminating character - in the utf16s_utf8s()
	 * function we limit the size of the buffer where the converted
	 * string is placed to HV_KVP_EXCHANGE_MAX_*_SIZE -1 to gaurantee
	 * that the strings can be properly terminated!
	 */

	switch (message->kvp_hdr.operation) {
	case KVP_OP_SET_IP_INFO:
		process_ib_ipinfo(in_msg, message, KVP_OP_SET_IP_INFO);
		break;
	case KVP_OP_GET_IP_INFO:
		process_ib_ipinfo(in_msg, message, KVP_OP_GET_IP_INFO);
		break;
	case KVP_OP_SET:
		switch (in_msg->body.kvp_set.data.value_type) {
		case REG_SZ:
			/*
			 * The value is a string - utf16 encoding.
			 */
			if (in_msg->body.kvp_set.data.value_size >=
				HV_KVP_EXCHANGE_MAX_VALUE_SIZE) {
				pr_err("KVP: Value size invalid\n");
				goto done;
			}

			message->body.kvp_set.data.value_size =
				utf8_wcstombs(
				message->body.kvp_set.data.value,
				(wchar_t *)in_msg->body.kvp_set.data.value,
				in_msg->body.kvp_set.data.value_size) + 1;
				break;

		case REG_U32:
			/*
			 * The value is a 32 bit scalar.
			 * We save this as a utf8 string.
			 */
			val32 = in_msg->body.kvp_set.data.value_u32;
			message->body.kvp_set.data.value_size =
				sprintf(message->body.kvp_set.data.value,
					"%d", val32) + 1;
			break;

		case REG_U64:
			/*
			 * The value is a 64 bit scalar.
			 * We save this as a utf8 string.
			 */
			val64 = in_msg->body.kvp_set.data.value_u64;
			message->body.kvp_set.data.value_size =
				sprintf(message->body.kvp_set.data.value,
					"%llu", val64) + 1;
			break;

		}
	case KVP_OP_GET:
		if (in_msg->body.kvp_set.data.key_size >=
			HV_KVP_EXCHANGE_MAX_KEY_SIZE) {
			pr_err("KVP: Key size invalid\n");
			goto done;
		}

		message->body.kvp_set.data.key_size =
			utf8_wcstombs(
			message->body.kvp_set.data.key,
			(wchar_t *)in_msg->body.kvp_set.data.key,
			 HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1) + 1;
			break;

	case KVP_OP_DELETE:
		message->body.kvp_delete.key_size =
			utf8_wcstombs(
			message->body.kvp_delete.key,
			(wchar_t *)in_msg->body.kvp_delete.key,
			 HV_KVP_EXCHANGE_MAX_KEY_SIZE - 1) + 1;
			break;

	case KVP_OP_ENUMERATE:
		message->body.kvp_enum_data.index =
			in_msg->body.kvp_enum_data.index;
			break;
	}
done:
	up(&kvp_transaction.read_sema);

	return;
}

/*
 * Send a response back to the host.
 */

static void
kvp_respond_to_host(struct hv_kvp_msg *msg_to_host, int error)
{
	struct hv_kvp_msg  *kvp_msg;
	struct hv_kvp_exchg_msg_value  *kvp_data;
	char	*key_name;
	char	*value;
	struct icmsg_hdr *icmsghdrp;
	int	keylen = 0;
	int	valuelen = 0;
	u32	buf_len;
	struct vmbus_channel *channel;
	u64	req_id;
	int ret;


	/*
	 * Copy the global state for completing the transaction. Note that
	 * only one transaction can be active at a time.
	 */

	buf_len = kvp_transaction.recv_len;
	channel = kvp_transaction.recv_channel;
	req_id = kvp_transaction.recv_req_id;

	kvp_transaction.active = false;

	icmsghdrp = (struct icmsg_hdr *)
			&recv_buffer[sizeof(struct vmbuspipe_hdr)];

	if (channel->onchannel_callback == NULL)
		/*
		 * We have raced with util driver being unloaded;
		 * silently return.
		 */
		return;

	icmsghdrp->status = error;

	/*
	 * If the error parameter is set, terminate the host's enumeration
	 * on this pool.
	 */
	if (error) {
		/*
		 * Something failed or we have timedout;
		 * terminate the current host-side iteration.
		 */
	kvp_msg = (struct hv_kvp_msg *)
			&recv_buffer[sizeof(struct vmbuspipe_hdr) +
			sizeof(struct icmsg_hdr)];

		goto response_done;
	}

	kvp_msg = (struct hv_kvp_msg *)
			&recv_buffer[sizeof(struct vmbuspipe_hdr) +
			sizeof(struct icmsg_hdr)];


	switch (kvp_transaction.kvp_msg->kvp_hdr.operation) {

	case KVP_OP_GET_IP_INFO:
		ret = process_ob_ipinfo(msg_to_host,
				 (struct hv_kvp_ip_msg *)kvp_msg,
				 KVP_OP_GET_IP_INFO);
		if (ret < 0)
			icmsghdrp->status = HV_E_FAIL;

		goto response_done;
	case KVP_OP_SET_IP_INFO:
		goto response_done;
	case KVP_OP_GET:
		kvp_data = &kvp_msg->body.kvp_get.data;
		goto copy_value;

	case KVP_OP_SET:
	case KVP_OP_DELETE:
		goto response_done;

	default:
		break;
	}

	kvp_data = &kvp_msg->body.kvp_enum_data.data;
	key_name = msg_to_host->body.kvp_enum_data.data.key;

	/*
	 * The windows host expects the key/value pair to be encoded
	 * in utf16. Ensure that the key/value size reported to the host
	 * will be less than or equal to the MAX size (including the
	 * terminating character).
	 */
	keylen = utf8_mbstowcs((wchar_t *) kvp_data->key, key_name, strlen(key_name));

	kvp_data->key_size = 2*(keylen + 1); /* utf16 encoding */

copy_value:
	value = msg_to_host->body.kvp_enum_data.data.value;
	valuelen = utf8_mbstowcs((wchar_t *) kvp_data->value, value, strlen(value));
	kvp_data->value_size = 2*(valuelen + 1); /* utf16 encoding */

	/*
	 * If the utf8s to utf16s conversion failed; notify host
	 * of the error.
	 */
	if ((keylen < 0) || (valuelen < 0))
		icmsghdrp->status = HV_E_FAIL;

	kvp_data->value_type = REG_SZ; /* all our values are strings */

response_done:
	icmsghdrp->icflags = ICMSGHDRFLAG_TRANSACTION | ICMSGHDRFLAG_RESPONSE;


	vmbus_sendpacket(channel, recv_buffer, buf_len, req_id,
				VM_PKT_DATA_INBAND, 0);

}

/*
 * This callback is invoked when we get a KVP message from the host.
 * The host ensures that only one KVP transaction can be active at a time.
 * KVP implementation in Linux needs to forward the key to a user-mde
 * component to retrive the corresponding value. Consequently, we cannot
 * respond to the host in the conext of this callback. Since the host
 * guarantees that at most only one transaction can be active at a time,
 * we stash away the transaction state in a set of global variables.
 */

void hv_kvp_onchannelcallback(void *context)
{
	struct vmbus_channel *channel = context;
	u32 recvlen;
	u64 requestid;

	struct hv_kvp_msg *kvp_msg;

	struct icmsg_hdr *icmsghdrp;
	struct icmsg_negotiate *negop = NULL;
        int util_fw_version;
	int kvp_srv_version;


	if (kvp_transaction.active) {
		/*
		 * We will defer processing this callback once
		 * the current transaction is complete.
		 */
		kvp_transaction.kvp_context = context;
		return;
	}

	vmbus_recvpacket(channel, recv_buffer, PAGE_SIZE * 2, &recvlen,
			 &requestid);

	if (recvlen > 0) {
		icmsghdrp = (struct icmsg_hdr *)&recv_buffer[
			sizeof(struct vmbuspipe_hdr)];

		if (icmsghdrp->icmsgtype == ICMSGTYPE_NEGOTIATE) {
			/*
			 * Based on the host, select appropriate
			 * framework and service versions we will
			 * negotiate.
			 */
			switch (vmbus_proto_version) {
			case (VERSION_WS2008):
				util_fw_version = UTIL_WS2K8_FW_VERSION;
				kvp_srv_version = WS2008_SRV_VERSION;
				break;
			case (VERSION_WIN7):
				util_fw_version = UTIL_FW_VERSION;
				kvp_srv_version = WIN7_SRV_VERSION;
				break;
			default:
				util_fw_version = UTIL_FW_VERSION;
				kvp_srv_version = WIN8_SRV_VERSION;
			}
			vmbus_prep_negotiate_resp(icmsghdrp, negop,
				recv_buffer, util_fw_version,
				kvp_srv_version);


		} else {
			kvp_msg = (struct hv_kvp_msg *)&recv_buffer[
				sizeof(struct vmbuspipe_hdr) +
				sizeof(struct icmsg_hdr)];

			/*
			 * Stash away this global state for completing the
			 * transaction; note transactions are serialized.
			 */

			kvp_transaction.recv_len = recvlen;
			kvp_transaction.recv_channel = channel;
			kvp_transaction.recv_req_id = requestid;
			kvp_transaction.kvp_msg = kvp_msg;

			/*
			 * Get the information from the
			 * user-mode component.
			 * component. This transaction will be
			 * completed when we get the value from
			 * the user-mode component.
			 * Set a timeout to deal with
			 * user-mode not responding.
			 */
			kvp_send_key(NULL);
			schedule_delayed_work(&kvp_work.work, 5*HZ);

			return;

		}


		icmsghdrp->icflags = ICMSGHDRFLAG_TRANSACTION
			| ICMSGHDRFLAG_RESPONSE;

		vmbus_sendpacket(channel, recv_buffer,
				       recvlen, requestid,
				       VM_PKT_DATA_INBAND, 0);
	}
}

/*
 * Create a char device that can support read/write for passing
 * KVP payload.
 */
struct cdev kvp_cdev;
struct class *cl;
struct device *sysfs_dev;

static ssize_t kvp_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	size_t remaining;
	int ret;
	/*
	 * Wait until there is something to be read.
	 */
	ret = down_interruptible(&kvp_transaction.read_sema);

	if (ret)
		return ret;

	/*
	 * Now copy the complete KVP message to the user.
	 */

	if (count < sizeof(struct hv_kvp_msg)) {
		return 0;
	}

	remaining = copy_to_user(buf, &kvp_transaction.message,
				 sizeof(struct hv_kvp_msg));

	if (remaining)
		return -EFAULT;

	return (sizeof(struct hv_kvp_msg));
}

static ssize_t kvp_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct hv_kvp_msg *message = &kvp_transaction.out_message;
	struct hv_kvp_msg_enumerate *data;
	size_t copied;
	int error = 0;

	memset(message, 0, sizeof(struct hv_kvp_msg));

	if (count != sizeof(struct hv_kvp_msg)) {
		return 0;
	}

	copied = copy_from_user(message, buf, sizeof(struct hv_kvp_msg));

	if (copied) {
		return -EFAULT;
	}


	if (in_hand_shake) {
		if (kvp_handle_handshake(message->kvp_hdr.operation))
			in_hand_shake = false;
		return 0;
	}

	/*
	 * Based on the version of the daemon, we propagate errors from the
	 * daemon differently.
	 */

	data = &message->body.kvp_enum_data;

	switch (dm_reg_value) {
	case KVP_OP_REGISTER:
		/*
		 * Null string is used to pass back error condition.
		 */
		if (data->data.key[0] == 0)
			error = HV_S_CONT;
		break;

	case KVP_OP_REGISTER1:
		/*
		 * We use the message header information from
		 * the user level daemon to transmit errors.
		 */
		error = message->error;
		break;
	}

	/*
	 * Complete the transaction by forwarding the key value
	 * to the host. But first, cancel the timeout.
	 */
	if (cancel_delayed_work_sync(&kvp_work)) {
		kvp_respond_to_host(message, error);
	}
	
	return (sizeof(struct hv_kvp_msg));
}

int kvp_open(struct inode *inode, struct file *f)
{
	/*
	 * The daemon alive; setup the state.
	 */
	if (opened)
		return -EBUSY;

	opened = true;
	dtp = current;
	daemon_died = false;
	return 0;
}

int kvp_release(struct inode *inode, struct file *f)
{
	/*
	 * The daemon has exited; reset the state.
	 */
	daemon_died = true;
	in_hand_shake = true;
	dtp = NULL;
	return 0;
}


static const struct file_operations kvp_fops = {
        .read           = kvp_read,
        .write          = kvp_write,
	.release	= kvp_release,
	.open		= kvp_open, 
};


static int kvp_dev_init(void)
{
	int result;

	result = alloc_chrdev_region(&kvp_dev, 1, 1, "hv_kvp");

	if (result < 0) {
		printk(KERN_ERR "hv_kvp: cannot get major number\n");
		return result;
	}

	cl = class_create(THIS_MODULE, "chardev");
	if (IS_ERR(cl)) {
		printk(KERN_ERR "Error creating kvp class.\n");
		unregister_chrdev_region(kvp_dev, 1 );
                return PTR_ERR(cl);
        }

	sysfs_dev = device_create(cl, NULL, kvp_dev, "%s", "hv_kvp");
	if (IS_ERR(sysfs_dev)) {
		printk(KERN_ERR "KVP Device creation failed\n");
		class_destroy(cl);
		unregister_chrdev_region(kvp_dev, 1 );
		return  PTR_ERR(sysfs_dev);
	}

	cdev_init(&kvp_cdev, &kvp_fops);
	kvp_cdev.owner = THIS_MODULE;
	kvp_cdev.ops = &kvp_fops;

	result = cdev_add(&kvp_cdev, kvp_dev, 1);

	if (result) {
		printk(KERN_ERR "hv_kvp: cannot cdev_add\n");
		goto dev_error;
	}
	return result;

dev_error:
	printk(KERN_ERR "hv_kvp: cannot add cdev; result: %d\n", result);
	device_destroy(cl, kvp_dev);
	class_destroy(cl);
	unregister_chrdev_region(kvp_dev, 1);
	return result;
}

static void kvp_dev_deinit(void)
{
	/*
	 * first kill the daemon.
	 */
	if (dtp != NULL)
		send_sig(SIGKILL, dtp, 0);
	opened = false;
	device_destroy(cl, kvp_dev);
	class_destroy(cl);
	cdev_del(&kvp_cdev);
	unregister_chrdev_region(kvp_dev, 1);
}


int
hv_kvp_init(struct hv_util_service *srv)
{
	recv_buffer = srv->recv_buffer;

	/*
	 * When this driver loads, the user level daemon that
	 * processes the host requests may not yet be running.
	 * Defer processing channel callbacks until the daemon
	 * has registered.
	 */
	kvp_transaction.active = true;
	sema_init(&kvp_transaction.read_sema, 1);

	return kvp_dev_init();
}

void hv_kvp_deinit(void)
{

	cancel_delayed_work_sync(&kvp_work);
	kvp_dev_deinit();
}
