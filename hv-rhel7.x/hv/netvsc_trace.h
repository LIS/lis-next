/* SPDX-License-Identifier: GPL-2.0 */

#if !defined(_NETVSC_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NETVSC_TRACE_H

/* This is purely a stub since older kernels do not have tracing. */

#define trace_rndis_send(ndev, q, msg)
#define trace_rndis_recv(ndev, q, msg)
#define trace_nvsp_send(ndev, msg)
#define trace_nvsp_send_pkt(ndev, chan, rpkt)
#define trace_nvsp_recv(ndev, chan, msg)

#endif /* _NETVSC_TRACE_H */
