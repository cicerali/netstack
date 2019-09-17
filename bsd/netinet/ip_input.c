/*
 * ip_input.c
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/time.h"

#include "sys/systm.h"
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/domain.h"
#include "sys/protosw.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/in_var.h"
#include "netinet/ip_var.h"
#include "netinet/ip_icmp.h"

#ifndef	IPFORWARDING
#ifdef GATEWAY
#define	IPFORWARDING	1	/* forward IP packets not for us */
#else /* GATEWAY */
#define	IPFORWARDING	0	/* don't forward IP packets not for us */
#endif /* GATEWAY */
#endif /* IPFORWARDING */
#ifndef	IPSENDREDIRECTS
#define	IPSENDREDIRECTS	1
#endif
int	ipforwarding = IPFORWARDING;
int	ipsendredirects = IPSENDREDIRECTS;
int	ip_defttl = IPDEFTTL;
#ifdef DIAGNOSTIC
int	ipprintfs = 0;
#endif

extern	struct domain inetdomain;
extern	struct protosw inetsw[];
u_char	ip_protox[IPPROTO_MAX];
int	ipqmaxlen = IFQ_MAXLEN;
struct	in_ifaddr *in_ifaddr;			/* first inet address */
struct	ifqueue ipintrq;

/*
 * We need to save the IP options in case a protocol wants to respond
 * to an incoming packet over the same route if the packet got here
 * using IP source routing.  This allows connection establishment and
 * maintenance when the remote end is on a network that is not known
 * to us.
 */
int	ip_nhops = 0;
static	struct ip_srcrt {
	struct	in_addr dst;			/* final destination */
	char	nop;				/* one NOP to align */
	char	srcopt[IPOPT_OFFSET + 1];	/* OPTVAL, OLEN and OFFSET */
	struct	in_addr route[MAX_IPOPTLEN/sizeof(struct in_addr)];
} ip_srcrt;

static void save_rte __P((u_char *, struct in_addr));

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init()
{
	struct protosw *pr;
	int i;

	pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
	if (pr == 0)
		panic("ip_init");
	for (i = 0; i < IPPROTO_MAX; i++)
		ip_protox[i] = pr - inetsw;
	for (pr = inetdomain.dom_protosw;
	    pr < inetdomain.dom_protoswNPROTOSW; pr++)
		if (pr->pr_domain->dom_family == PF_INET &&
		    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW)
			ip_protox[pr->pr_protocol] = pr - inetsw;
	ipq.next = ipq.prev = &ipq;
	struct timeval time;
	gettimeofday(&time, NULL);
	ip_id = time.tv_sec & 0xffff;
	ipintrq.ifq_maxlen = ipqmaxlen;
#ifdef GATEWAY
	i = (if_index + 1) * (if_index + 1) * sizeof (u_long);
	ip_ifmatrix = (u_long *) malloc(i, M_RTABLE, M_WAITOK);
	bzero((char *)ip_ifmatrix, i);
#endif
}

struct	sockaddr_in ipaddr = { sizeof(ipaddr), AF_INET };
struct	route ipforward_rt;

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
        struct ip *ip;
        struct ipq *fp;
        struct in_ifaddr *ia;
        int    i, hlen;
        u_short sum;

#ifdef  DIAGNOSTIC
        if ((m->m_flags & M_PKTHDR) == 0)
                panic("ip_input no HDR");
#endif
        /*
         * If no IP addresses have been set yet but the interfaces
         * are receiving, can't do anything with incoming packets yet.
         */
        if (in_ifaddr == NULL)
                goto bad;
        ipstat.ips_total++;
        if (m->m_len < sizeof (struct ip)) {
                ipstat.ips_toosmall++;
				goto bad;
		}
        ip = mtod(m, struct ip *);
        if (ip->ip_v !=  IPVERSION) {
                ipstat.ips_badvers++;
                goto bad;
        }
        hlen = ip->ip_hl << 2;
        if (hlen < sizeof(struct ip)) { /* minimum header length */
                ipstat.ips_badhlen++;
                goto bad;
        }
        if (hlen > m->m_len) {
                ipstat.ips_badhlen++;
                goto bad;
        }
        if (ip->ip_sum = in_cksum(m, hlen)) {
                ipstat.ips_badsum++;
                goto bad;
        }

        /*
         * Convert fields to host representation.
         */
        NTOHS(ip->ip_len);
        if (ip->ip_len < hlen) {
                ipstat.ips_badlen++;
                goto bad;
        }
        NTOHS(ip->ip_id);
        NTOHS(ip->ip_off);

        /*
         * Check that the amount of data in the buffers
         * is as at least much as the IP header would have us expect.
         * Trim mbufs if longer than we expect.
         * Drop packet if shorter than we expect.
         */
        if (m->m_pkthdr.len < ip->ip_len) {
                ipstat.ips_tooshort++;
                goto bad;
        }
        if (m->m_pkthdr.len > ip->ip_len) {
                if (m->m_len == m->m_pkthdr.len) {
                        m->m_len = ip->ip_len;
                        m->m_pkthdr.len = ip->ip_len;
                } else
                        m_adj(m, ip->ip_len - m->m_pkthdr.len);
        }

        /*
         * Process options and, if not destined for us,
         * ship it on.  ip_dooptions returns 1 when an
         * error was detected (causing an icmp message
         * to be sent and the original packet to be freed).
         */
        ip_nhops = 0;           /* for source routed packets */
        if (hlen > sizeof (struct ip) && ip_dooptions(m))
                return;

        /*
         * Check our list of addresses, to see if the packet is for us.
         */
        for (ia = in_ifaddr; ia; ia = ia->ia_next) {
#define satosin(sa)     ((struct sockaddr_in *)(sa))

                if (IA_SIN(ia)->sin_addr.s_addr == ip->ip_dst.s_addr)
                        goto ours;
				if (ia->ia_ifp->if_flags & IFF_BROADCAST) {
					u_long t;

					if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
						ip->ip_dst.s_addr)
						goto ours;
					if (ip->ip_dst.s_addr == ia->ia_netbroadcast.s_addr)
						goto ours;
					/*
					* Look for all-0's host part (old broadcast addr),
					* either for subnet or net.
					*/
					t = ntohl(ip->ip_dst.s_addr);
					if (t == ia->ia_subnet)
						goto ours;
					if (t == ia->ia_net)
						goto ours;
				}
        }
        if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
                struct in_multi *inm;

                /*
                 * See if we belong to the destination multicast group on the
                 * arrival interface.
                 */
                IN_LOOKUP_MULTI(ip->ip_dst, m->m_pkthdr.rcvif, inm);
                if (inm == NULL) {
                        ipstat.ips_cantforward++;
                        m_freem(m);
                        return;
                }
                goto ours;
        }
        if (ip->ip_dst.s_addr == (u_long)INADDR_BROADCAST)
                goto ours;
        if (ip->ip_dst.s_addr == INADDR_ANY)
                goto ours;

        /*
         * Not for us; forward if possible and desirable.
         */
        if (ipforwarding == 0) {
                ipstat.ips_cantforward++;
                m_freem(m);
        } else
        	// TODO XXX
        	goto bad;
//                ip_forward(m, 0);
        return;

ours:
        /*
         * If offset or IP_MF are set, must reassemble.
         * Otherwise, nothing need be done.
         * (We could look in the reassembly queue to see
         * if the packet was previously fragmented,
         * but it's not worth the time; just let them time out.)
         */
        if (ip->ip_off &~ IP_DF) {
		// TODO use dpdk reasembly
			goto bad;

        } else
                ip->ip_len -= hlen;

        /*
         * Switch out to protocol's input routine.
         */
        ipstat.ips_delivered++;
        (*inetsw[ip_protox[ip->ip_p]].pr_input)(m, hlen);
        return;
bad:
        m_freem(m);
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
ip_freef(struct ipq *fp)
{
    register struct mbuf *q;

    while (fp->ipq_frags) {
            q = fp->ipq_frags;
            fp->ipq_frags = q->m_nextpkt;
            m_freem(q);
    }
    remque(fp);
    (void) m_free(dtom(fp));
}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
void
ip_slowtimo()
{
	struct ipq *fp;

	fp = ipq.next;
	if (fp == 0) {
		return;
	}
	while (fp != &ipq) {
		--fp->ipq_ttl;
		fp = fp->next;
		if (fp->prev->ipq_ttl == 0) {
			ipstat.ips_fragtimeout++;
			ip_freef(fp->prev);
		}
	}
}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain()
{

	while (ipq.next != &ipq) {
		ipstat.ips_fragdropped++;
		ip_freef(ipq.next);
	}
}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
int
ip_dooptions(m)
	struct mbuf *m;
{
	register struct ip *ip = mtod(m, struct ip *);
	register u_char *cp;
	register struct ip_timestamp *ipt;
	register struct in_ifaddr *ia;
	int opt, optlen, cnt, off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr *sin, dst;
	n_time ntime;

	dst = ip->ip_dst;
	cp = (u_char *)(ip + 1);
	cnt = (ip->ip_hl << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[IPOPT_OLEN];
			if (optlen <= 0 || optlen > cnt) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
		}
		switch (opt) {

		default:
			break;

		/*
		 * Source routing with record.
		 * Find interface with current destination address.
		 * If none on this machine then drop if strictly routed,
		 * or do nothing if loosely routed.
		 * Record interface address and bring up next address
		 * component.  If strictly routed make sure next
		 * address is on directly accessible net.
		 */
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			ipaddr.sin_addr = ip->ip_dst;
			ia = (struct in_ifaddr *)
				ifa_ifwithaddr((struct sockaddr *)&ipaddr);
			if (ia == 0) {
				if (opt == IPOPT_SSRR) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				}
				/*
				 * Loose routing, and not at next destination
				 * yet; nothing to do except forward.
				 */
				break;
			}
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr)) {
				/*
				 * End of source route.  Should be for us.
				 */
				save_rte(cp, ip->ip_src);
				break;
			}
			/*
			 * locate outgoing interface
			 */
			bcopy((caddr_t)(cp + off), (caddr_t)&ipaddr.sin_addr,
			    sizeof(ipaddr.sin_addr));
			if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
#define	SA	struct sockaddr *
			    if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0)
				ia = (INA)ifa_ifwithnet((SA)&ipaddr);
			} else
				ia = ip_rtaddr(ipaddr.sin_addr);
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
			    (caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			/*
			 * Let ip_intr's mcast routing check handle mcast pkts
			 */
			forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
			break;

		case IPOPT_RR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			/*
			 * If no space remains, ignore.
			 */
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr))
				break;
			bcopy((caddr_t)(&ip->ip_dst), (caddr_t)&ipaddr.sin_addr,
			    sizeof(ipaddr.sin_addr));
			/*
			 * locate outgoing interface; if we're the destination,
			 * use the incoming interface (should be same).
			 */
			if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0 &&
			    (ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_HOST;
				goto bad;
			}
			bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
			    (caddr_t)(cp + off), sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)cp;
			if (ipt->ipt_len < 5)
				goto bad;
			if (ipt->ipt_ptr > ipt->ipt_len - sizeof (long)) {
				if (++ipt->ipt_oflw == 0)
					goto bad;
				break;
			}
			sin = (struct in_addr *)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr((SA)&ipaddr,
							    m->m_pkthdr.rcvif);
				if (ia == 0)
					continue;
				bcopy((caddr_t)&IA_SIN(ia)->sin_addr,
				    (caddr_t)sin, sizeof(struct in_addr));
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				bcopy((caddr_t)sin, (caddr_t)&ipaddr.sin_addr,
				    sizeof(struct in_addr));
				if (ifa_ifwithaddr((SA)&ipaddr) == 0)
					continue;
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				goto bad;
			}
			ntime = iptime();
			bcopy((caddr_t)&ntime, (caddr_t)cp + ipt->ipt_ptr - 1,
			    sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward) {
		ip_forward(m, 1);
		return (1);
	}
	return (0);
bad:
	ip->ip_len -= ip->ip_hl << 2;   /* XXX icmp_error adds in hdr length */
	icmp_error(m, type, code, 0, 0);
	ipstat.ips_badoptions++;
	return (1);
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
struct in_ifaddr *
ip_rtaddr(dst)
	 struct in_addr dst;
{
	register struct sockaddr_in *sin;

	sin = (struct sockaddr_in *) &ipforward_rt.ro_dst;

	if (ipforward_rt.ro_rt == 0 || dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = dst;

		rtalloc(&ipforward_rt);
	}
	if (ipforward_rt.ro_rt == 0)
		return ((struct in_ifaddr *)0);
	return ((struct in_ifaddr *) ipforward_rt.ro_rt->rt_ifa);
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(option, dst)
	u_char *option;
	struct in_addr dst;
{
	unsigned olen;

	olen = option[IPOPT_OLEN];
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf("save_rte: olen %d\n", olen);
#endif
	if (olen > sizeof(ip_srcrt) - (1 + sizeof(dst)))
		return;
	bcopy((caddr_t)option, (caddr_t)ip_srcrt.srcopt, olen);
	ip_nhops = (olen - IPOPT_OFFSET - 1) / sizeof(struct in_addr);
	ip_srcrt.dst = dst;
}

/*
 * Retrieve incoming source route for use in replies,
 * in the same form used by setsockopt.
 * The first hop is placed before the options, will be removed later.
 */
struct mbuf *
ip_srcroute()
{
	register struct in_addr *p, *q;
	register struct mbuf *m;

	if (ip_nhops == 0)
		return ((struct mbuf *)0);
	m = m_get(M_DONTWAIT, MT_SOOPTS);
	if (m == 0)
		return ((struct mbuf *)0);

#define OPTSIZ	(sizeof(ip_srcrt.nop) + sizeof(ip_srcrt.srcopt))

	/* length is (nhops+1)*sizeof(addr) + sizeof(nop + srcrt header) */
	m->m_len = ip_nhops * sizeof(struct in_addr) + sizeof(struct in_addr) +
	    OPTSIZ;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf("ip_srcroute: nhops %d mlen %d", ip_nhops, m->m_len);
#endif

	/*
	 * First save first hop for return route
	 */
	p = &ip_srcrt.route[ip_nhops - 1];
	*(mtod(m, struct in_addr *)) = *p--;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf(" hops %lx", ntohl(mtod(m, struct in_addr *)->s_addr));
#endif

	/*
	 * Copy option fields and padding (nop) to mbuf.
	 */
	ip_srcrt.nop = IPOPT_NOP;
	ip_srcrt.srcopt[IPOPT_OFFSET] = IPOPT_MINOFF;
	bcopy((caddr_t)&ip_srcrt.nop,
	    mtod(m, caddr_t) + sizeof(struct in_addr), OPTSIZ);
	q = (struct in_addr *)(mtod(m, caddr_t) +
	    sizeof(struct in_addr) + OPTSIZ);
#undef OPTSIZ
	/*
	 * Record return path as an IP source route,
	 * reversing the path (pointers are now aligned).
	 */
	while (p >= ip_srcrt.route) {
#ifdef DIAGNOSTIC
		if (ipprintfs)
			printf(" %lx", ntohl(q->s_addr));
#endif
		*q++ = *p--;
	}
	/*
	 * Last hop goes to final destination.
	 */
	*q = ip_srcrt.dst;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf(" %lx\n", ntohl(q->s_addr));
#endif
	return (m);
}

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * XXX should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(m, mopt)
	register struct mbuf *m;
	struct mbuf *mopt;
{
	int i;
	struct ip *ip = mtod(m, struct ip *);
	caddr_t opts;
	int olen;

	olen = (ip->ip_hl << 2) - sizeof(struct ip);
	opts = (caddr_t)(ip + 1);
	i = m->m_len - (sizeof (struct ip) + olen);
	bcopy(opts  + olen, opts, (unsigned)i);
	m->m_len -= olen;
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.len -= olen;
	ip->ip_hl = sizeof(struct ip) >> 2;
}

u_char inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 * The srcrt parameter indicates whether the packet is being forwarded
 * via a source route.
 */
void
ip_forward(m, srcrt)
	struct mbuf *m;
	int srcrt;
{
	register struct ip *ip = mtod(m, struct ip *);
	register struct sockaddr_in *sin;
	register struct rtentry *rt;
	int error, type = 0, code;
	struct mbuf *mcopy;
	n_long dest;
	struct ifnet *destifp;

	dest = 0;
#ifdef DIAGNOSTIC
	if (ipprintfs)
		printf("forward: src %x dst %x ttl %x\n", ip->ip_src,
			ip->ip_dst, ip->ip_ttl);
#endif
	if (m->m_flags & M_BCAST || in_canforward(ip->ip_dst) == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
		return;
	}
	HTONS(ip->ip_id);
	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return;
	}
	ip->ip_ttl -= IPTTLDEC;

	sin = (struct sockaddr_in *)&ipforward_rt.ro_dst;
	if ((rt = ipforward_rt.ro_rt) == 0 ||
	    ip->ip_dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = ip->ip_dst;

		rtalloc(&ipforward_rt);
		if (ipforward_rt.ro_rt == 0) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, dest, 0);
			return;
		}
		rt = ipforward_rt.ro_rt;
	}

	/*
	 * Save at most 64 bytes of the packet in case
	 * we need to generate an ICMP message to the src.
	 */
	mcopy = m_copy(m, 0, imin((int)ip->ip_len, 64));

#ifdef GATEWAY
	ip_ifmatrix[rt->rt_ifp->if_index +
	     if_index * m->m_pkthdr.rcvif->if_index]++;
#endif
	/*
	 * If forwarding packet using same interface that it came in on,
	 * perhaps should send a redirect to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * and if packet was not source routed (or has any options).
	 * Also, don't send redirect if forwarding using a default route
	 * or a route modified by a redirect.
	 */
#define	satosin(sa)	((struct sockaddr_in *)(sa))
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
	    (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0 &&
	    satosin(rt_key(rt))->sin_addr.s_addr != 0 &&
	    ipsendredirects && !srcrt) {
#define	RTA(rt)	((struct in_ifaddr *)(rt->rt_ifa))
		u_long src = ntohl(ip->ip_src.s_addr);

		if (RTA(rt) &&
		    (src & RTA(rt)->ia_subnetmask) == RTA(rt)->ia_subnet) {
		    if (rt->rt_flags & RTF_GATEWAY)
			dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
		    else
			dest = ip->ip_dst.s_addr;
		    /* Router requirements says to only send host redirects */
		    type = ICMP_REDIRECT;
		    code = ICMP_REDIRECT_HOST;
#ifdef DIAGNOSTIC
		    if (ipprintfs)
		        printf("redirect (%d) to %lx\n", code, (u_long)dest);
#endif
		}
	}

	error = ip_output(m, (struct mbuf *)0, &ipforward_rt, IP_FORWARDING
#ifdef DIRECTED_BROADCAST
			    | IP_ALLOWBROADCAST
#endif
						, 0);
	if (error)
		ipstat.ips_cantforward++;
	else {
		ipstat.ips_forward++;
		if (type)
			ipstat.ips_redirectsent++;
		else {
			if (mcopy)
				m_freem(mcopy);
			return;
		}
	}
	if (mcopy == NULL)
		return;
	destifp = NULL;

	switch (error) {

	case 0:				/* forwarded, but need redirect */
		/* type, code set above */
		break;

	case ENETUNREACH:		/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		break;

	case EMSGSIZE:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_NEEDFRAG;
		if (ipforward_rt.ro_rt)
			destifp = ipforward_rt.ro_rt->rt_ifp;
		ipstat.ips_cantfrag++;
		break;

	case ENOBUFS:
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;
	}
	icmp_error(mcopy, type, code, dest, destifp);
}
