/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SELINUX_AVC_SS_H_
#define _SELINUX_AVC_SS_H_

#include "flask.h"
#ifdef CONFIG_USERLAND_WORKER
#include "avc_ss_reset.h"
#endif /* CONFIG_USERLAND_WORKER */

struct selinux_avc;
#ifndef CONFIG_USERLAND_WORKER
int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif /* CONFIG_USERLAND_WORKER */

/* Class/perm mapping support */
struct security_class_mapping {
	const char *name;
	const char *perms[sizeof(u32) * 8 + 1];
};

extern struct security_class_mapping secclass_map[];

extern int ss_initialized; // SEC_SELINUX_PORTING_COMMON

#endif /* _SELINUX_AVC_SS_H_ */

