#include <linux/timex.h>
#include <linux/hv_compat.h>

#if (RHEL_RELEASE_CODE < 1288)
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	union {
		u64 v64;
		u32 v32[2];
	} d = { dividend };
	u32 upper;

	upper = d.v32[1];
	d.v32[1] = 0;
	if (upper >= divisor) {
		d.v32[1] = upper / divisor;
		upper %= divisor;
	}
	asm ("divl %2" : "=a" (d.v32[0]), "=d" (*remainder) :
		"rm" (divisor), "0" (d.v32[0]), "1" (upper));
	return d.v64;
}

#ifndef div_s64_rem
s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	u64 quotient;

	if (dividend < 0) {
		quotient = div_u64_rem(-dividend, abs(divisor), (u32 *)remainder);
		*remainder = -*remainder;
		if (divisor > 0)
			quotient = -quotient;
	} else {
		quotient = div_u64_rem(dividend, abs(divisor), (u32 *)remainder);
		if (divisor < 0)
			quotient = -quotient;
	}
	return quotient;
}
EXPORT_SYMBOL(div_s64_rem);
#endif
#endif

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5, 9)
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}
EXPORT_SYMBOL(ns_to_timespec);
#endif

struct shutdown_event {
	struct work_struct wq;
	char buf[64];
	char *argv[4];
	char *envp[6];
};

static void hv_usermodehelper(struct shutdown_event *s_event)
{
	call_usermodehelper(s_event->argv[0], s_event->argv, s_event->envp, 1);
}

static struct shutdown_event s_event;

void rhel_5_x_power_off(void)
{
	int cnt = 0;
	s_event.argv[cnt++] = "/sbin/poweroff";
	s_event.argv[cnt++] = 0;

	cnt = 0;

	s_event.envp[cnt++] = "HOME=/";
	s_event.envp[cnt++] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	s_event.envp[cnt++] = 0;
	INIT_WORK(&s_event.wq, (void *)(void *)hv_usermodehelper, &s_event);
	schedule_work(&s_event.wq);
}
EXPORT_SYMBOL(rhel_5_x_power_off);

//KYS

#ifndef netdev_err
void netdev_err(struct net_device *net, const char *fmt, ...) //KYS
{
	va_list args;

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}
EXPORT_SYMBOL(netdev_err);
#endif


