/*
 * raw_ip.c
 *
 *  Created on: Sep 16, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/time.h"
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/protosw.h"
#include "sys/socketvar.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/ip_var.h"
#include "netinet/ip_mroute.h"
#include "netinet/in_pcb.h"

struct inpcb rawinpcb;

/*
 * Nominal space allocated to a raw ip socket.
 */
#define	RIPSNDQ		8192
#define	RIPRCVQ		8192

struct	sockaddr_in ripsrc = { sizeof(ripsrc), AF_INET };

/*
 * Initialize raw connection block q.
 */
void
rip_init()
{

	rawinpcb.inp_next = rawinpcb.inp_prev = &rawinpcb;
}

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
void
rip_input(m)
	struct mbuf *m;
{
	register struct ip *ip = mtod(m, struct ip *);
	register struct inpcb *inp;
	struct socket *last = 0;

	ripsrc.sin_addr = ip->ip_src;
	for (inp = rawinpcb.inp_next; inp != &rawinpcb; inp = inp->inp_next) {
		if (inp->inp_ip.ip_p && inp->inp_ip.ip_p != ip->ip_p)
			continue;
		if (inp->inp_laddr.s_addr &&
		    inp->inp_laddr.s_addr != ip->ip_dst.s_addr)
			continue;
		if (inp->inp_faddr.s_addr &&
		    inp->inp_faddr.s_addr != ip->ip_src.s_addr)
			continue;
		if (last) {
			struct mbuf *n;
			if (n = m_copy(m, 0, (int)M_COPYALL)) {
				if (sbappendaddr(&last->so_rcv,
				    (struct sockaddr *)&ripsrc, n,
				    (struct mbuf *)0) == 0)
					/* should notify about lost packet */
					m_freem(n);
				else
					sorwakeup(last);
			}
		}
		last = inp->inp_socket;
	}
	if (last) {
		if (sbappendaddr(&last->so_rcv, (struct sockaddr *)&ripsrc,
		    m, (struct mbuf *)0) == 0)
			m_freem(m);
		else
			sorwakeup(last);
	} else {
		m_freem(m);
		ipstat.ips_noproto++;
		ipstat.ips_delivered--;
	}
}

/*
 * Generate IP header and pass packet to ip_output.
 * Tack on options user may have setup with control call.
 */
int
rip_output(m, so, dst)
	register struct mbuf *m;
	struct socket *so;
	u_long dst;
{
	register struct ip *ip;
	register struct inpcb *inp = sotoinpcb(so);
	struct mbuf *opts;
	int flags = (so->so_options & SO_DONTROUTE) | IP_ALLOWBROADCAST;

	/*
	 * If the user handed us a complete IP packet, use it.
	 * Otherwise, allocate an mbuf for a header and fill it in.
	 */
	if ((inp->inp_flags & INP_HDRINCL) == 0) {
		M_PREPEND(m, sizeof(struct ip), M_WAIT);
		ip = mtod(m, struct ip *);
		ip->ip_tos = 0;
		ip->ip_off = 0;
		ip->ip_p = inp->inp_ip.ip_p;
		ip->ip_len = m->m_pkthdr.len;
		ip->ip_src = inp->inp_laddr;
		ip->ip_dst.s_addr = dst;
		ip->ip_ttl = MAXTTL;
		opts = inp->inp_options;
	} else {
		ip = mtod(m, struct ip *);
		if (ip->ip_id == 0)
			ip->ip_id = htons(ip_id++);
		opts = NULL;
		/* XXX prevent ip_output from overwriting header fields */
		flags |= IP_RAWOUTPUT;
		ipstat.ips_rawout++;
	}
	return (ip_output(m, opts, &inp->inp_route, flags, inp->inp_moptions));
}

/*
 * Raw IP socket option processing.
 */
int
rip_ctloutput(op, so, level, optname, m)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **m;
{
	register struct inpcb *inp = sotoinpcb(so);
	register int error;

	if (level != IPPROTO_IP) {
		if (op == PRCO_SETOPT && *m)
			(void) m_free(*m);
		return (EINVAL);
	}

	switch (optname) {

	case IP_HDRINCL:
		error = 0;
		if (op == PRCO_SETOPT) {
			if (*m == 0 || (*m)->m_len < sizeof (int))
				error = EINVAL;
			else if (*mtod(*m, int *))
				inp->inp_flags |= INP_HDRINCL;
			else
				inp->inp_flags &= ~INP_HDRINCL;
			if (*m)
				(void)m_free(*m);
		} else {
			*m = m_get(M_WAIT, MT_SOOPTS);
			(*m)->m_len = sizeof (int);
			*mtod(*m, int *) = inp->inp_flags & INP_HDRINCL;
		}
		return (error);

	case DVMRP_INIT:
	case DVMRP_DONE:
	case DVMRP_ADD_VIF:
	case DVMRP_DEL_VIF:
	case DVMRP_ADD_LGRP:
	case DVMRP_DEL_LGRP:
	case DVMRP_ADD_MRT:
	case DVMRP_DEL_MRT:
#ifdef MROUTING
		if (op == PRCO_SETOPT) {
			error = ip_mrouter_cmd(optname, so, *m);
			if (*m)
				(void)m_free(*m);
		} else
			error = EINVAL;
		return (error);
#else
		if (op == PRCO_SETOPT && *m)
			(void)m_free(*m);
		return (EOPNOTSUPP);
#endif

	default:
		if (optname >= DVMRP_INIT) {
#ifdef MROUTING
			if (op == PRCO_SETOPT) {
				error = ip_mrouter_cmd(optname, so, *m);
				if (*m)
					(void)m_free(*m);
			} else
				error = EINVAL;
			return (error);
#else
			if (op == PRCO_SETOPT && *m)
				(void)m_free(*m);
			return (EOPNOTSUPP);
#endif
		}

	}
	return (ip_ctloutput(op, so, level, optname, m));
}

u_long	rip_sendspace = RIPSNDQ;
u_long	rip_recvspace = RIPRCVQ;

static int
rip_attach(struct socket *so, int proto)
{
        struct inpcb *inp;
        int error, s;

        inp = sotoinpcb(so);
        if (inp)
                panic("rip_attach");
        if ((so->so_state & SS_PRIV) == 0)
                return EACCES;

        error = in_pcballoc(so, &rawinpcb);
        if (error)
                return error;
        error = soreserve(so, rip_sendspace, rip_recvspace);
        if (error)
                return error;
        inp = (struct inpcb *)so->so_pcb;
        inp->inp_ip.ip_p = proto;
        return 0;
}

static int
rip_detach(struct socket *so)
{
        struct inpcb *inp;

        inp = sotoinpcb(so);
        if (inp == 0)
                panic("rip_detach");
#ifdef MROUTING
        if (so == ip_mrouter)
                ip_mrouter_done();
#endif
        in_pcbdetach(inp);
        return 0;
}

static int
rip_abort(struct socket *so)
{
        soisdisconnected(so);
        return rip_detach(so);
}

static int
rip_disconnect(struct socket *so)
{
        if ((so->so_state & SS_ISCONNECTED) == 0)
                return ENOTCONN;
        return rip_abort(so);
}

static int
rip_bind(struct socket *so, struct mbuf *nam)
{
        struct inpcb *inp = sotoinpcb(so);
        struct sockaddr_in *addr = mtod(nam, struct sockaddr_in *);

        if (nam->m_len != sizeof(*addr))
        			return EINVAL;

        if ((ifnet == 0) ||
        	((addr->sin_family != AF_INET) &&
             (addr->sin_family != AF_IMPLINK)) ||
            (addr->sin_addr.s_addr &&
             ifa_ifwithaddr((struct sockaddr *)addr) == 0))
                return EADDRNOTAVAIL;
        inp->inp_laddr = addr->sin_addr;
        return 0;
}

static int
rip_connect(struct socket *so, struct mbuf *nam)
{
        struct inpcb *inp = sotoinpcb(so);
        struct sockaddr_in *addr = mtod(nam, struct sockaddr_in *);

        if (nam->m_len != sizeof(*addr))
                return EINVAL;
        if (ifnet == 0)
                return EADDRNOTAVAIL;
        if ((addr->sin_family != AF_INET) &&
            (addr->sin_family != AF_IMPLINK))
                return EAFNOSUPPORT;
        inp->inp_faddr = addr->sin_addr;
        soisconnected(so);
        return 0;
}

static int
rip_shutdown(struct socket *so)
{
        socantsendmore(so);
        return 0;
}

static int
rip_send(struct socket *so, int flags, struct mbuf *m, struct mbuf *nam,
         struct mbuf *control)
{
        struct inpcb *inp = sotoinpcb(so);
        register u_long dst;

        if (so->so_state & SS_ISCONNECTED) {
                if (nam) {
                        m_freem(m);
                        return EISCONN;
                }
                dst = inp->inp_faddr.s_addr;
        } else {
                if (nam == NULL) {
                        m_freem(m);
                        return ENOTCONN;
                }
                dst = mtod(nam, struct sockaddr_in *)->sin_addr.s_addr;
        }
        return rip_output(m, so, dst);
}

/*
 * This is the wrapper function for in_setsockaddr.  We just pass down
 * the pcbinfo for in_setpeeraddr to lock.
 */
static int
rip_sockaddr(struct socket *so, struct mbuf *nam)
{
	struct inpcb *inp = sotoinpcb(so);
	return (in_setsockaddr(inp, nam));
}

/*
 * This is the wrapper function for in_setpeeraddr.  We just pass down
 * the pcbinfo for in_setpeeraddr to lock.
 */
static int
rip_peeraddr(struct socket *so, struct mbuf *nam)
{
	struct inpcb *inp = sotoinpcb(so);
	return (in_setpeeraddr(inp, nam));
}

/*
 * XXX - this should just be a call to in_control, but we need to get
 * the types worked out.
 */
static int
rip_control(struct socket *so, int cmd, caddr_t arg, struct ifnet *ifp)
{
        return in_control(so, cmd, arg, ifp);
}

struct pr_usrreqs rip_usrreqs = {
        .pru_abort =            rip_abort,
        .pru_attach =           rip_attach,
        .pru_bind =             rip_bind,
        .pru_connect =          rip_connect,
        .pru_control =          rip_control,
        .pru_detach =           rip_detach,
        .pru_disconnect =       rip_disconnect,
        .pru_peeraddr =         rip_peeraddr,
        .pru_send =             rip_send,
        .pru_shutdown =         rip_shutdown,
        .pru_sockaddr =         rip_sockaddr,
};
