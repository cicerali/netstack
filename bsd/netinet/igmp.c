/*
 * igmp.c
 *
 *  Created on: Aug 22, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/time.h"

#include "sys/mbuf.h"

#include "sys/socket.h"
#include "sys/protosw.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_var.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/ip_var.h"
#include "netinet/igmp.h"
#include "netinet/igmp_var.h"

extern struct ifnet loif;

static int igmp_timers_are_running = 0;
static u_long igmp_all_hosts_group;

static void igmp_sendreport __P((struct in_multi *));

void
igmp_joingroup(inm)
	struct in_multi *inm;
{

	if (inm->inm_addr.s_addr == igmp_all_hosts_group ||
	    inm->inm_ifp == &loif)
		inm->inm_timer = 0;
	else {
		igmp_sendreport(inm);
		inm->inm_timer = IGMP_RANDOM_DELAY(inm->inm_addr);
		igmp_timers_are_running = 1;
	}
}

void
igmp_leavegroup(inm)
	struct in_multi *inm;
{
	/*
	 * No action required on leaving a group.
	 */
}

static void
igmp_sendreport(inm)
	register struct in_multi *inm;
{
	register struct mbuf *m;
	register struct igmp *igmp;
	register struct ip *ip;
	register struct ip_moptions *imo;
	struct ip_moptions simo;

	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return;
	/*
	 * Assume max_linkhdr + sizeof(struct ip) + IGMP_MINLEN
	 * is smaller than mbuf size returned by MGETHDR.
	 */
	m->m_data += max_linkhdr;
	m->m_len = sizeof(struct ip) + IGMP_MINLEN;
	m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = sizeof(struct ip) + IGMP_MINLEN;
	ip->ip_off = 0;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src.s_addr = INADDR_ANY;
	ip->ip_dst = inm->inm_addr;

	m->m_data += sizeof(struct ip);
	m->m_len -= sizeof(struct ip);
	igmp = mtod(m, struct igmp *);
	igmp->igmp_type = IGMP_HOST_MEMBERSHIP_REPORT;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = in_cksum(m, IGMP_MINLEN);
	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	imo = &simo;
	bzero((caddr_t)imo, sizeof(*imo));
	imo->imo_multicast_ifp = inm->inm_ifp;
	imo->imo_multicast_ttl = 1;
	/*
	 * Request loopback of the report if we are acting as a multicast
	 * router, so that the process-level routing demon can hear it.
	 */
#ifdef MROUTING
    {
	extern struct socket *ip_mrouter;
	imo->imo_multicast_loop = (ip_mrouter != NULL);
    }
#endif
	ip_output(m, NULL, NULL, 0, imo);

	++igmpstat.igps_snd_reports;
}
