/*
 * Compatiability macros to adapt to older kernel versions
 */

static inline bool compat_napi_complete_done(struct napi_struct *n, int work_done)
{
#if (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,3))
	napi_complete(n);
#else
	napi_complete_done(n, work_done);
#endif
	return true;
}
	
#define napi_complete_done  compat_napi_complete_done

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,2))
static inline void __napi_schedule_irqoff(struct napi_struct *n)
{
	__napi_schedule(n);
}
#endif

