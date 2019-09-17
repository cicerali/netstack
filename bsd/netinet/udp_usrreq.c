/*
 * udp_usrreq.c
 *
 *  Created on: Sep 17, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/malloc.h"
#include "sys/time.h"
#include "sys/mbuf.h"
#include "sys/protosw.h"
#include "sys/socket.h"
#include "sys/socketvar.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/in_pcb.h"
#include "netinet/ip_var.h"
#include "netinet/ip_icmp.h"
#include "netinet/udp.h"
#include "netinet/udp_var.h"

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef	COMPAT_42
int	udpcksum = 1;
#else
int	udpcksum = 0;		/* XXX */
#endif

struct	sockaddr_in udp_in = { sizeof(udp_in), AF_INET };
struct	inpcb *udp_last_inpcb = &udb;

static	struct mbuf *udp_saveopt __P((caddr_t, int, int));

void
udp_init()
{
	udb.inp_next = udb.inp_prev = &udb;
}

void
udp_input(m, iphlen)
	register struct mbuf *m;
	int iphlen;
{
	register struct ip *ip;
	register struct udphdr *uh;
	register struct inpcb *inp;
	struct mbuf *opts = 0;
	int len;
	struct ip save_ip;

	udpstat.udps_ipackets++;

	/*
	 * Strip IP options, if any; should skip this,
	 * make available to user, and use on returned packets,
	 * but we don't yet have a way to check the checksum
	 * with options still present.
	 */
	if (iphlen > sizeof (struct ip)) {
		ip_stripoptions(m, (struct mbuf *)0);
		iphlen = sizeof(struct ip);
	}

	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	if (m->m_len < iphlen + sizeof(struct udphdr)) {
			udpstat.udps_hdrops++;
			return;
	}
	uh = (struct udphdr *)((caddr_t)ip + iphlen);

	/*
	 * Make mbuf data length reflect UDP length.
	 * If not enough data to reflect UDP length, drop.
	 */
	len = ntohs((u_short)uh->uh_ulen);
	if (ip->ip_len != len) {
		if (len > ip->ip_len || len < sizeof(struct udphdr)) {
			udpstat.udps_badlen++;
			goto bad;
		}
		m_adj(m, len - ip->ip_len);
		/* ip->ip_len = len; */
	}
	/*
	 * Save a copy of the IP header in case we want restore it
	 * for sending an ICMP error message in response.
	 */
	save_ip = *ip;

	/*
	 * Checksum extended UDP header and data.
	 */
	if (uh->uh_sum) {
		bzero(((struct ipovly *)ip)->ih_x1, 9);
		((struct ipovly *)ip)->ih_len = uh->uh_ulen;
		if (uh->uh_sum = in_cksum(m, len + sizeof (struct ip))) {
			udpstat.udps_badsum++;
			m_freem(m);
			return;
		}
	}

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) ||
	    in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif)) {
		struct socket *last;
		/*
		 * Deliver a multicast or broadcast datagram to *all* sockets
		 * for which the local and remote addresses and ports match
		 * those of the incoming datagram.  This allows more than
		 * one process to receive multi/broadcasts on the same port.
		 * (This really ought to be done for unicast datagrams as
		 * well, but that would cause problems with existing
		 * applications that open both address-specific sockets and
		 * a wildcard socket listening to the same port -- they would
		 * end up receiving duplicates of every unicast datagram.
		 * Those applications open the multiple sockets to overcome an
		 * inadequacy of the UDP socket interface, but for backwards
		 * compatibility we avoid the problem here rather than
		 * fixing the interface.  Maybe 4.5BSD will remedy this?)
		 */

		/*
		 * Construct sockaddr format source address.
		 */
		udp_in.sin_port = uh->uh_sport;
		udp_in.sin_addr = ip->ip_src;
		m->m_len -= sizeof (struct udpiphdr);
		m->m_data += sizeof (struct udpiphdr);
		/*
		 * Locate pcb(s) for datagram.
		 * (Algorithm copied from raw_intr().)
		 */
		last = NULL;
		for (inp = udb.inp_next; inp != &udb; inp = inp->inp_next) {
			if (inp->inp_lport != uh->uh_dport)
				continue;
			if (inp->inp_laddr.s_addr != INADDR_ANY) {
				if (inp->inp_laddr.s_addr !=
				    ip->ip_dst.s_addr)
					continue;
			}
			if (inp->inp_faddr.s_addr != INADDR_ANY) {
				if (inp->inp_faddr.s_addr !=
				    ip->ip_src.s_addr ||
				    inp->inp_fport != uh->uh_sport)
					continue;
			}

			if (last != NULL) {
				struct mbuf *n;

				if ((n = m_copy(m, 0, M_COPYALL)) != NULL) {
					if (sbappendaddr(&last->so_rcv,
						(struct sockaddr *)&udp_in,
						n, (struct mbuf *)0) == 0) {
						m_freem(n);
						udpstat.udps_fullsock++;
					} else
						sorwakeup(last);
				}
			}
			last = inp->inp_socket;
			/*
			 * Don't look for additional matches if this one does
			 * not have either the SO_REUSEPORT or SO_REUSEADDR
			 * socket options set.  This heuristic avoids searching
			 * through all pcbs in the common case of a non-shared
			 * port.  It * assumes that an application will never
			 * clear these options after setting them.
			 */
			if ((last->so_options&(SO_REUSEPORT|SO_REUSEADDR) == 0))
				break;
		}

		if (last == NULL) {
			/*
			 * No matching pcb found; discard datagram.
			 * (No need to send an ICMP Port Unreachable
			 * for a broadcast or multicast datgram.)
			 */
			udpstat.udps_noportbcast++;
			goto bad;
		}
		if (sbappendaddr(&last->so_rcv, (struct sockaddr *)&udp_in,
		     m, (struct mbuf *)0) == 0) {
			udpstat.udps_fullsock++;
			goto bad;
		}
		sorwakeup(last);
		return;
	}
	/*
	 * Locate pcb for datagram.
	 */
	inp = udp_last_inpcb;
	if (inp->inp_lport != uh->uh_dport ||
	    inp->inp_fport != uh->uh_sport ||
	    inp->inp_faddr.s_addr != ip->ip_src.s_addr ||
	    inp->inp_laddr.s_addr != ip->ip_dst.s_addr) {
		inp = in_pcblookup(&udb, ip->ip_src, uh->uh_sport,
		    ip->ip_dst, uh->uh_dport, INPLOOKUP_WILDCARD);
		if (inp)
			udp_last_inpcb = inp;
		udpstat.udpps_pcbcachemiss++;
	}
	if (inp == 0) {
		udpstat.udps_noport++;
		if (m->m_flags & (M_BCAST | M_MCAST)) {
			udpstat.udps_noportbcast++;
			goto bad;
		}
		*ip = save_ip;
		ip->ip_len += iphlen;
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
		return;
	}

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	udp_in.sin_port = uh->uh_sport;
	udp_in.sin_addr = ip->ip_src;
	if (inp->inp_flags & INP_CONTROLOPTS) {
		struct mbuf **mp = &opts;

		if (inp->inp_flags & INP_RECVDSTADDR) {
			*mp = udp_saveopt((caddr_t) &ip->ip_dst,
			    sizeof(struct in_addr), IP_RECVDSTADDR);
			if (*mp)
				mp = &(*mp)->m_next;
		}
#ifdef notyet
		/* options were tossed above */
		if (inp->inp_flags & INP_RECVOPTS) {
			*mp = udp_saveopt((caddr_t) opts_deleted_above,
			    sizeof(struct in_addr), IP_RECVOPTS);
			if (*mp)
				mp = &(*mp)->m_next;
		}
		/* ip_srcroute doesn't do what we want here, need to fix */
		if (inp->inp_flags & INP_RECVRETOPTS) {
			*mp = udp_saveopt((caddr_t) ip_srcroute(),
			    sizeof(struct in_addr), IP_RECVRETOPTS);
			if (*mp)
				mp = &(*mp)->m_next;
		}
#endif
	}
	iphlen += sizeof(struct udphdr);
	m->m_len -= iphlen;
	m->m_pkthdr.len -= iphlen;
	m->m_data += iphlen;
	if (sbappendaddr(&inp->inp_socket->so_rcv, (struct sockaddr *)&udp_in,
	    m, opts) == 0) {
		udpstat.udps_fullsock++;
		goto bad;
	}
	sorwakeup(inp->inp_socket);
	return;
bad:
	m_freem(m);
	if (opts)
		m_freem(opts);
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation with a datagram.
 */
struct mbuf *
udp_saveopt(p, size, type)
	caddr_t p;
	register int size;
	int type;
{
	register struct cmsghdr *cp;
	struct mbuf *m;

	if ((m = m_get(M_DONTWAIT, MT_CONTROL)) == NULL)
		return ((struct mbuf *) NULL);
	cp = (struct cmsghdr *) mtod(m, struct cmsghdr *);
	bcopy(p, CMSG_DATA(cp), size);
	size += sizeof(*cp);
	m->m_len = size;
	cp->cmsg_len = size;
	cp->cmsg_level = IPPROTO_IP;
	cp->cmsg_type = type;
	return (m);
}

/*
 * Notify a udp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
static void
udp_notify(inp, err)
	register struct inpcb *inp;
	int err;
{
	inp->inp_socket->so_error = err;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
}

void
udp_ctlinput(cmd, sa, ip)
	int cmd;
	struct sockaddr *sa;
	register struct ip *ip;
{
	register struct udphdr *uh;
	extern struct in_addr zeroin_addr;
	extern u_char inetctlerrmap[];

	if (!PRC_IS_REDIRECT(cmd) &&
	    ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0))
		return;
	if (ip) {
		uh = (struct udphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		in_pcbnotify(&udb, sa, uh->uh_dport, ip->ip_src, uh->uh_sport,
			cmd, udp_notify);
	} else
		in_pcbnotify(&udb, sa, 0, zeroin_addr, 0, cmd, udp_notify);
}

int
udp_output(inp, m, addr, control)
	register struct inpcb *inp;
	register struct mbuf *m;
	struct mbuf *addr, *control;
{
	register struct udpiphdr *ui;
	register int len = m->m_pkthdr.len;
	struct in_addr laddr;
	int s, error = 0;

	if (control)
		m_freem(control);		/* XXX */

	if (addr) {
		laddr = inp->inp_laddr;
		if (inp->inp_faddr.s_addr != INADDR_ANY) {
			error = EISCONN;
			goto release;
		}
		/*
		 * Must block input while temporarily connected.
		 */
		error = in_pcbconnect(inp, addr);
		if (error) {
			goto release;
		}
	} else {
		if (inp->inp_faddr.s_addr == INADDR_ANY) {
			error = ENOTCONN;
			goto release;
		}
	}
	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP headers.
	 */
	M_PREPEND(m, sizeof(struct udpiphdr), M_DONTWAIT);
	if (m == 0) {
		error = ENOBUFS;
		goto release;
	}

	/*
	 * Fill in mbuf with extended UDP header
	 * and addresses and length put into network format.
	 */
	ui = mtod(m, struct udpiphdr *);
	bzero(ui->ui_x1, sizeof(ui->ui_x1));    /* XXX still needed? */
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons((u_short)len + sizeof (struct udphdr));
	ui->ui_src = inp->inp_laddr;
	ui->ui_dst = inp->inp_faddr;
	ui->ui_sport = inp->inp_lport;
	ui->ui_dport = inp->inp_fport;
	ui->ui_ulen = ui->ui_len;

	/*
	 * Stuff checksum and output datagram.
	 */
	ui->ui_sum = 0;
	if (udpcksum) {
	    if ((ui->ui_sum = in_cksum(m, sizeof (struct udpiphdr) + len)) == 0)
		ui->ui_sum = 0xffff;
	}
	((struct ip *)ui)->ip_len = sizeof (struct udpiphdr) + len;
	((struct ip *)ui)->ip_ttl = inp->inp_ip.ip_ttl;	/* XXX */
	((struct ip *)ui)->ip_tos = inp->inp_ip.ip_tos;	/* XXX */
	udpstat.udps_opackets++;
	error = ip_output(m, inp->inp_options, &inp->inp_route,
	    inp->inp_socket->so_options & (SO_DONTROUTE | SO_BROADCAST),
	    inp->inp_moptions);

	if (addr) {
		in_pcbdisconnect(inp);
		inp->inp_laddr = laddr;
	}
	return (error);

release:
	m_freem(m);
	return (error);
}

u_long	udp_sendspace = 9216;		/* really max datagram size */
u_long	udp_recvspace = 40 * (1024 + sizeof(struct sockaddr_in));
					/* 40 1K datagrams */

static int
udp_abort(struct socket *so)
{
        struct inpcb *inp;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;  /* ??? possible? panic instead? */
        soisdisconnected(so);
		if (inp == udp_last_inpcb)
			udp_last_inpcb = &udb;
        in_pcbdetach(inp);
        return 0;
}

static int
udp_attach(struct socket *so, int proto)
{
        struct inpcb *inp;
        int s, error;

        inp = sotoinpcb(so);
        if (inp != 0)
                return EINVAL;

        error = in_pcballoc(so, &udb);
        if (error)
                return error;
        error = soreserve(so, udp_sendspace, udp_recvspace);
        if (error)
                return error;
        ((struct inpcb *) so->so_pcb)->inp_ip.ip_ttl = ip_defttl;
        return 0;
}

static int
udp_bind(struct socket *so, struct mbuf *nam)
{
        struct inpcb *inp;
        int s, error;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;
        error = in_pcbbind(inp, nam);
        return error;
}

static int
udp_connect(struct socket *so, struct mbuf *nam)
{
        struct inpcb *inp;
        int s, error;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;
        if (inp->inp_faddr.s_addr != INADDR_ANY)
                return EISCONN;
        error = in_pcbconnect(inp, nam);
        if (error == 0)
                soisconnected(so);
        return error;
}

static int
udp_detach(struct socket *so)
{
        struct inpcb *inp;
        int s;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;
        if (inp == udp_last_inpcb)
        		udp_last_inpcb = &udb;
        in_pcbdetach(inp);
        return 0;
}

static int
udp_disconnect(struct socket *so)
{
        struct inpcb *inp;
        int s;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;
        if (inp->inp_faddr.s_addr == INADDR_ANY)
                return ENOTCONN;

        in_pcbdisconnect(inp);
        inp->inp_laddr.s_addr = INADDR_ANY;
        so->so_state &= ~SS_ISCONNECTED;                /* XXX */
        return 0;
}

static int
udp_send(struct socket *so, int flags, struct mbuf *m, struct mbuf *addr,
            struct mbuf *control)
{
        struct inpcb *inp;

        inp = sotoinpcb(so);
        if (inp == 0) {
                m_freem(m);
                return EINVAL;
        }
        return udp_output(inp, m, addr, control);
}

static int
udp_shutdown(struct socket *so)
{
        struct inpcb *inp;

        inp = sotoinpcb(so);
        if (inp == 0)
                return EINVAL;
        socantsendmore(so);
        return 0;
}

/*
 * This is the wrapper function for in_setsockaddr.  We just pass down
 * the pcbinfo for in_setsockaddr to lock.  We don't want to do the locking
 * here because in_setsockaddr will call malloc and might block.
 */
static int
udp_sockaddr(struct socket *so, struct mbuf *nam)
{
		struct inpcb *inp = sotoinpcb(so);
        return (in_setsockaddr(inp, nam));
}

/*
 * This is the wrapper function for in_setpeeraddr.  We just pass down
 * the pcbinfo for in_setpeeraddr to lock.
 */
static int
udp_peeraddr(struct socket *so, struct mbuf *nam)
{
		struct inpcb *inp = sotoinpcb(so);
        return (in_setpeeraddr(inp, nam));
}

/*
 * XXX - this should just be a call to in_control, but we need to get
 * the types worked out.
 */
static int
udp_control(struct socket *so, int cmd, caddr_t arg, struct ifnet *ifp)
{
        return in_control(so, cmd, arg, ifp);
}

struct pr_usrreqs udp_usrreqs = {
		.pru_abort =            udp_abort,
		.pru_accept =			pru_accept_notsupp,
		.pru_attach =           udp_attach,
		.pru_bind =             udp_bind,
		.pru_connect =          udp_connect,
		.pru_connect2 =			pru_connect2_notsupp,
		.pru_control =          udp_control,
		.pru_detach =           udp_detach,
		.pru_disconnect =       udp_disconnect,
		.pru_listen =           pru_listen_notsupp,
		.pru_peeraddr =         udp_peeraddr,
		.pru_rcvd =             pru_rcvd_notsupp,
		.pru_rcvoob =           pru_rcvoob_notsupp,
		.pru_send =             udp_send,
		.pru_sense =			pru_sense_null,
		.pru_shutdown =         udp_shutdown,
		.pru_sockaddr =         udp_sockaddr,
};

