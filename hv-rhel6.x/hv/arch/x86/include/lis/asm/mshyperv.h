#ifndef _ASM_X86_MSHYPER_H
#define _ASM_X86_MSHYPER_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <asm/hyperv.h>

struct ms_hyperv_info {
	u32 features;
	u32 misc_features;
	u32 hints;
};

extern struct ms_hyperv_info ms_hyperv;

/*
 *  * Declare the MSR used to setup pages used to communicate with the hypervisor.
 *   */
#define HV_X64_MSR_HYPERCALL	0x40000001

union hv_x64_msr_hypercall_contents {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:11;
		u64 guest_physical_address:52;
	};
};

/*
 * The guest OS needs to register the guest ID with the hypervisor.
 * The guest ID is a 64 bit entity and the structure of this ID is
 * specified in the Hyper-V specification:
 *
 * http://msdn.microsoft.com/en-us/library/windows/hardware/ff542653%28v=vs.85%29.aspx
 *
 * While the current guideline does not specify how Linux guest ID(s)
 * need to be generated, our plan is to publish the guidelines for
 * Linux and other guest operating systems that currently are hosted
 * on Hyper-V. The implementation here conforms to this yet
 * unpublished guidelines.
 *
 *
 * Bit(s)
 * 63 - Indicates if the OS is Open Source or not; 1 is Open Source
 * 62:56 - Os Type; Linux is 0x100
 * 55:48 - Distro specific identification
 * 47:16 - Linux kernel version number
 * 15:0  - Distro specific identification
 *
 * Distro specific identification are defined as:
 *   SuSE SLE      0x10
 *   RHEL          0x20
 *   CentOS        0x21
 *   Oracle (RHCK) 0x22
 *   Oracle (UEK)  0x40
 *   Debian        0x60
 *   Ubuntu        0x80
 */

#define HV_LINUX_VENDOR_ID		0x8100

/*
 * Generate the guest ID based on the guideline described above.
 */

static inline  __u64 generate_guest_id(__u8 d_info1, __u32 kernel_version,
					__u16 d_info2)
{
	__u64 guest_id = 0;

	guest_id = (((__u64)HV_LINUX_VENDOR_ID) << 48);
	guest_id |= (((__u64)(d_info1)) << 48);
	guest_id |= (((__u64)(kernel_version)) << 16);
	guest_id |= ((__u64)(d_info2));

	return guest_id;
}

void hyperv_callback_vector(void);
#ifdef CONFIG_TRACING
#define trace_hyperv_callback_vector hyperv_callback_vector
#endif
void hyperv_vector_handler(struct pt_regs *regs);
void hv_setup_vmbus_irq(void (*handler)(void));
void hv_remove_vmbus_irq(void);

void hv_setup_kexec_handler(void (*handler)(void));
void hv_remove_kexec_handler(void);
void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs));
void hv_remove_crash_handler(void);

#define hv_get_synint_state(int_num, val) rdmsrl(int_num, val)
#define hv_set_synint_state(int_num, val) wrmsrl(int_num, val)

#define hv_get_simp(val) rdmsrl(HV_X64_MSR_SIMP, val)
#define hv_set_simp(val) wrmsrl(HV_X64_MSR_SIMP, val)

#define hv_get_siefp(val) rdmsrl(HV_X64_MSR_SIEFP, val)
#define hv_set_siefp(val) wrmsrl(HV_X64_MSR_SIEFP, val)
#define hv_get_synic_state(val) rdmsrl(HV_X64_MSR_SCONTROL, val)
#define hv_set_synic_state(val) wrmsrl(HV_X64_MSR_SCONTROL, val)

#define hv_get_vp_index(index) rdmsrl(HV_X64_MSR_VP_INDEX, index)
void hv_register_vmbus_handler(int irq, irq_handler_t handler);

#endif