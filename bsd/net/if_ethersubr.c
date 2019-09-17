/*
 * if_ethersubr.c
 *
 *  Created on: Aug 28, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include <sys/time.h>

#include "sys/systm.h"
#include "sys/mbuf.h"

#include "sys/socket.h"
#include "sys/socketvar.h"

#include "net/route.h"
#include "net/if.h"
#include "net/if_dl.h"
#include "net/if_types.h"

#include "netinet/in.h"
#include "netinet/in_var.h"
#include "netinet/if_ether.h"


u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
extern	struct ifnet loif;
#define senderr(e) { error = (e); goto bad;}

/*
 * Ethernet output routine.
 * Encapsulate a packet of type family for the local net.
 * Use trailer local net encapsulation if enough data in first
 * packet leaves a multiple of 512 bytes of data in remainder.
 * Assumes that ifp is actually pointer to arpcom structure.
 */
int
ether_output(ifp, m0, dst, rt0)
	register struct ifnet *ifp;
	struct mbuf *m0;
	struct sockaddr *dst;
	struct rtentry *rt0;
{
	short type;
	int s, error = 0;
 	u_char edst[6];
	register struct mbuf *m = m0;
	register struct rtentry *rt;
	struct mbuf *mcopy = (struct mbuf *)0;
	register struct ether_header *eh;
	int off, len = m->m_pkthdr.len;
	struct arpcom *ac = (struct arpcom *)ifp;

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		senderr(ENETDOWN);
	struct timeval time;
	gettimeofday(&time, NULL);
	ifp->if_lastchange = time;
	if (rt = rt0) {
		if ((rt->rt_flags & RTF_UP) == 0) {
			if (rt0 = rt = rtalloc1(dst, 1))
				rt->rt_refcnt--;
			else
				senderr(EHOSTUNREACH);
		}
		if (rt->rt_flags & RTF_GATEWAY) {
			if (rt->rt_gwroute == 0)
				goto lookup;
			if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
				rtfree(rt); rt = rt0;
			lookup: rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1);
				if ((rt = rt->rt_gwroute) == 0)
					senderr(EHOSTUNREACH);
			}
		}
		if (rt->rt_flags & RTF_REJECT)
			if (rt->rt_rmx.rmx_expire == 0 ||
			    time.tv_sec < rt->rt_rmx.rmx_expire)
				senderr(rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
	}
	switch (dst->sa_family) {

#ifdef INET
	case AF_INET:
		if (!arpresolve(ac, rt, m, dst, edst))
			return (0);	/* if not yet resolved */
		/* If broadcasting on a simplex interface, loopback a copy */
		if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX))
			mcopy = m_copy(m, 0, (int)M_COPYALL);
		off = m->m_pkthdr.len - m->m_len;
		type = ETHERTYPE_IP;
		break;
#endif
#ifdef NS
	case AF_NS:
		type = ETHERTYPE_NS;
 		bcopy((caddr_t)&(((struct sockaddr_ns *)dst)->sns_addr.x_host),
		    (caddr_t)edst, sizeof (edst));
		if (!bcmp((caddr_t)edst, (caddr_t)&ns_thishost, sizeof(edst)))
			return (looutput(ifp, m, dst, rt));
		/* If broadcasting on a simplex interface, loopback a copy */
		if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX))
			mcopy = m_copy(m, 0, (int)M_COPYALL);
		break;
#endif
#ifdef	ISO
	case AF_ISO: {
		int	snpalen;
		struct	llc *l;
		register struct sockaddr_dl *sdl;

		if (rt && (sdl = (struct sockaddr_dl *)rt->rt_gateway) &&
		    sdl->sdl_family == AF_LINK && sdl->sdl_alen > 0) {
			bcopy(LLADDR(sdl), (caddr_t)edst, sizeof(edst));
		} else if (error =
			    iso_snparesolve(ifp, (struct sockaddr_iso *)dst,
					    (char *)edst, &snpalen))
			goto bad; /* Not Resolved */
		/* If broadcasting on a simplex interface, loopback a copy */
		if (*edst & 1)
			m->m_flags |= (M_BCAST|M_MCAST);
		if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX) &&
		    (mcopy = m_copy(m, 0, (int)M_COPYALL))) {
			M_PREPEND(mcopy, sizeof (*eh), M_DONTWAIT);
			if (mcopy) {
				eh = mtod(mcopy, struct ether_header *);
				bcopy((caddr_t)edst,
				      (caddr_t)eh->ether_dhost, sizeof (edst));
				bcopy((caddr_t)ac->ac_enaddr,
				      (caddr_t)eh->ether_shost, sizeof (edst));
			}
		}
		M_PREPEND(m, 3, M_DONTWAIT);
		if (m == NULL)
			return (0);
		type = m->m_pkthdr.len;
		l = mtod(m, struct llc *);
		l->llc_dsap = l->llc_ssap = LLC_ISO_LSAP;
		l->llc_control = LLC_UI;
		len += 3;
		IFDEBUG(D_ETHER)
			int i;
			printf("unoutput: sending pkt to: ");
			for (i=0; i<6; i++)
				printf("%x ", edst[i] & 0xff);
			printf("\n");
		ENDDEBUG
		} break;
#endif /* ISO */
#ifdef	LLC
/*	case AF_NSAP: */
	case AF_CCITT: {
		register struct sockaddr_dl *sdl =
			(struct sockaddr_dl *) rt -> rt_gateway;

		if (sdl && sdl->sdl_family == AF_LINK
		    && sdl->sdl_alen > 0) {
			bcopy(LLADDR(sdl), (char *)edst,
				sizeof(edst));
		} else goto bad; /* Not a link interface ? Funny ... */
		if ((ifp->if_flags & IFF_SIMPLEX) && (*edst & 1) &&
		    (mcopy = m_copy(m, 0, (int)M_COPYALL))) {
			M_PREPEND(mcopy, sizeof (*eh), M_DONTWAIT);
			if (mcopy) {
				eh = mtod(mcopy, struct ether_header *);
				bcopy((caddr_t)edst,
				      (caddr_t)eh->ether_dhost, sizeof (edst));
				bcopy((caddr_t)ac->ac_enaddr,
				      (caddr_t)eh->ether_shost, sizeof (edst));
			}
		}
		type = m->m_pkthdr.len;
#ifdef LLC_DEBUG
		{
			int i;
			register struct llc *l = mtod(m, struct llc *);

			printf("ether_output: sending LLC2 pkt to: ");
			for (i=0; i<6; i++)
				printf("%x ", edst[i] & 0xff);
			printf(" len 0x%x dsap 0x%x ssap 0x%x control 0x%x\n",
			       type & 0xff, l->llc_dsap & 0xff, l->llc_ssap &0xff,
			       l->llc_control & 0xff);

		}
#endif /* LLC_DEBUG */
		} break;
#endif /* LLC */

	case AF_UNSPEC:
		eh = (struct ether_header *)dst->sa_data;
 		bcopy((caddr_t)eh->ether_dhost, (caddr_t)edst, sizeof (edst));
		type = eh->ether_type;
		break;

	default:
		printf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
			dst->sa_family);
		senderr(EAFNOSUPPORT);
	}


	if (mcopy)
		(void) looutput(ifp, mcopy, dst, rt);
	/*
	 * Add local net header.  If no space in first mbuf,
	 * allocate another.
	 */
	M_PREPEND(m, sizeof (struct ether_header), M_DONTWAIT);
	if (m == 0)
		senderr(ENOBUFS);
	eh = mtod(m, struct ether_header *);
	type = htons((u_short)type);
	bcopy((caddr_t)&type,(caddr_t)&eh->ether_type,
		sizeof(eh->ether_type));
 	bcopy((caddr_t)edst, (caddr_t)eh->ether_dhost, sizeof (edst));
 	bcopy((caddr_t)ac->ac_enaddr, (caddr_t)eh->ether_shost,
	    sizeof(eh->ether_shost));

	/*
	 * Queue message on interface, and start output if interface
	 * not yet active.
	 */
	if (IF_QFULL(&ifp->if_snd)) {
		IF_DROP(&ifp->if_snd);
		senderr(ENOBUFS);
	}
	IF_ENQUEUE(&ifp->if_snd, m);
	if ((ifp->if_flags & IFF_OACTIVE) == 0)
		(*ifp->if_start)(ifp);
	ifp->if_obytes += len + sizeof (struct ether_header);
	if (m->m_flags & M_MCAST)
		ifp->if_omcasts++;
	return (error);

bad:
	if (m)
		m_freem(m);
	return (error);
}

void ip_input(struct mbuf *m);
/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
void
ether_input(ifp, eh, m)
	struct ifnet *ifp;
	register struct ether_header *eh;
	struct mbuf *m;
{
	register struct ifqueue *inq;
	register struct llc *l;
	struct arpcom *ac = (struct arpcom *)ifp;
	int s;

	if ((ifp->if_flags & IFF_UP) == 0) {
		m_freem(m);
		return;
	}
	struct timeval time;
	gettimeofday(&time, NULL);
	ifp->if_lastchange = time;
	ifp->if_ibytes += m->m_pkthdr.len + sizeof (*eh);
	if (bcmp((caddr_t)etherbroadcastaddr, (caddr_t)eh->ether_dhost,
	    sizeof(etherbroadcastaddr)) == 0)
		m->m_flags |= M_BCAST;
	else if (eh->ether_dhost[0] & 1)
		m->m_flags |= M_MCAST;
	if (m->m_flags & (M_BCAST|M_MCAST))
		ifp->if_imcasts++;

	switch (eh->ether_type) {
#ifdef INET
	case ETHERTYPE_IP:
		ip_input(m);
		break;
	case ETHERTYPE_ARP:
		// TODO
		inq = &arpintrq;
		break;
#endif
	default:
	    m_freem(m);
	    return;
	}

return;
}

/*
 * Perform common duties while attaching to interface list
 */
void
ether_ifattach(ifp)
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	register struct sockaddr_dl *sdl;

	ifp->if_type = IFT_ETHER;
	ifp->if_addrlen = 6;
	ifp->if_hdrlen = 14;
	ifp->if_mtu = ETHERMTU;
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
		if ((sdl = (struct sockaddr_dl *)ifa->ifa_addr) &&
		    sdl->sdl_family == AF_LINK) {
			sdl->sdl_type = IFT_ETHER;
			sdl->sdl_alen = ifp->if_addrlen;
			bcopy((caddr_t)((struct arpcom *)ifp)->ac_enaddr,
			      LLADDR(sdl), ifp->if_addrlen);
			break;
		}
}
