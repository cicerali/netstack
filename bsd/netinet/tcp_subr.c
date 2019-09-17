/*
 * tcp_subr.c
 *
 *  Created on: Aug 21, 2019
 *      Author: cicerali
 */

#include <sys/param.h>

#include "sys/systm.h"
#include "sys/malloc.h"
#include "sys/mbuf.h"

//#include "compat/panic_compat.h"

#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/protosw.h"

#include "net/route.h"

#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/in_pcb.h"
#include "netinet/ip_var.h"
#include "netinet/tcp.h"
#include "netinet/tcp_fsm.h"
#include "netinet/tcp_seq.h"
#include "netinet/tcp_timer.h"
#include "netinet/tcp_var.h"
#include "netinet/tcpip.h"
#ifdef TCPDEBUG
#include "netinet/tcp_debug.h"
#endif

/* patchable/settable parameters for tcp */
int 	tcp_mssdflt = TCP_MSS;
int 	tcp_rttdflt = TCPTV_SRTTDFLT / PR_SLOWHZ;
int	tcp_do_rfc1323 = 1;

extern struct inpcb *tcp_last_inpcb;

/*
 * Tcp initialization
 */
void
tcp_init()
{

	tcp_iss = random();	/* wrong, but better than a constant */
	tcb.inp_next = tcb.inp_prev = &tcb;
	if (max_protohdr < sizeof(struct tcpiphdr))
		max_protohdr = sizeof(struct tcpiphdr);
	if (max_linkhdr + sizeof(struct tcpiphdr) > MHLEN)
		panic("tcp_init");
}

/*
 * Create template to be used to send tcp packets on a connection.
 * Call after host entry created, allocates an mbuf and fills
 * in a skeletal tcp/ip header, minimizing the amount of work
 * necessary when the connection is used.
 */
struct tcpiphdr *
tcp_template(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct mbuf *m;
	struct tcpiphdr *n;

	if ((n = tp->t_template) == 0)
	{
		m = m_get(M_DONTWAIT, MT_HEADER);
		if (m == NULL)
			return (0);
		m->m_len = sizeof(struct tcpiphdr);
		n = mtod(m, struct tcpiphdr *);
	}
	bzero(n->ti_x1, sizeof(n->ti_x1));
	n->ti_pr = IPPROTO_TCP;
	n->ti_len = htons(sizeof(struct tcpiphdr) - sizeof(struct ip));
	n->ti_src = inp->inp_laddr;
	n->ti_dst = inp->inp_faddr;
	n->ti_sport = inp->inp_lport;
	n->ti_dport = inp->inp_fport;
	n->ti_seq = 0;
	n->ti_ack = 0;
	n->ti_x2 = 0;
	n->ti_off = 5;
	n->ti_flags = 0;
	n->ti_win = 0;
	n->ti_sum = 0;
	n->ti_urp = 0;
	return (n);
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 *
 * * NOTE: If m != NULL, then ti must point to *inside* the mbuf.
 */
void tcp_respond(struct tcpcb *tp, struct tcpiphdr *ti, struct mbuf *m,
		tcp_seq ack, tcp_seq seq, int flags)
{
	int tlen;
	int win = 0;
	struct route *ro = 0;
	struct route sro;

	if (tp)
	{
		if (!(flags & TH_RST))
		{
			win = sbspace(&tp->t_inpcb->inp_socket->so_rcv);
			if (win > (long) TCP_MAXWIN << tp->rcv_scale)
				win = (long) TCP_MAXWIN << tp->rcv_scale;
		}
		ro = &tp->t_inpcb->inp_route;
	} else {
		ro = &sro;
		bzero(ro, sizeof *ro);
	}
	if (m == 0)
	{
		m = m_gethdr(M_DONTWAIT, MT_HEADER);
		if (m == NULL)
			return;
#ifdef TCP_COMPAT_42
		tlen = 1;
#else
		tlen = 0;
#endif
		m->m_data += max_linkhdr;
		*mtod(m, struct tcpiphdr *) = *ti;
		ti = mtod(m, struct tcpiphdr *);
		flags = TH_ACK;
	}
	else
	{
		m_freem(m->m_next);
		m->m_next = 0;
		m->m_len = sizeof(struct tcpiphdr);
		tlen = 0;
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
		xchg(ti->ti_dst.s_addr, ti->ti_src.s_addr, n_long);
		xchg(ti->ti_dport, ti->ti_sport, n_short);
#undef xchg
	}
	ti->ti_len = htons((u_short) (sizeof(struct tcphdr) + tlen));
	tlen += sizeof(struct tcpiphdr);
	m->m_len = tlen;
	m->m_pkthdr.len = tlen;
	m->m_pkthdr.rcvif = (struct ifnet *) 0;
	bzero(ti->ti_x1, sizeof(ti->ti_x1));
	ti->ti_seq = htonl(seq);
	ti->ti_ack = htonl(ack);
	ti->ti_x2 = 0;
	ti->ti_off = sizeof(struct tcphdr) >> 2;
	ti->ti_flags = flags;
	if (tp)
		ti->ti_win = htons((u_short) (win >> tp->rcv_scale));
	else
		ti->ti_win = htons((u_short) win);
	ti->ti_urp = 0;
	ti->ti_sum = 0;
	ti->ti_sum = in_cksum(m, tlen);
	((struct ip *) ti)->ip_len = tlen;
	((struct ip *) ti)->ip_ttl = ip_defttl;
#ifdef TCPDEBUG
        if (tp == NULL || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
                tcp_trace(TA_OUTPUT, 0, tp, ti, 0);
#endif
        (void) ip_output(m, NULL, ro, 0, NULL);
        if (ro == &sro && ro->ro_rt) {
                RTFREE(ro->ro_rt);
        }
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
struct tcpcb *
tcp_newtcpcb(inp)
	struct inpcb *inp;
{
	register struct tcpcb *tp;

	tp = M_malloc(sizeof(*tp), M_PCB, M_NOWAIT);
	if (tp == NULL)
		return ((struct tcpcb *)0);
	bzero((char *) tp, sizeof(struct tcpcb));
	tp->t_segq = NULL;
	tp->t_maxseg = tp->t_maxopd = tcp_mssdflt;

	tp->t_flags = tcp_do_rfc1323 ? (TF_REQ_SCALE|TF_REQ_TSTMP) : 0;
	tp->t_inpcb = inp;
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = tcp_rttdflt * PR_SLOWHZ << 2;
	tp->t_rttmin = TCPTV_MIN;
	TCPT_RANGESET(tp->t_rxtcur,
	    ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
	    TCPTV_MIN, TCPTV_REXMTMAX);
	tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	inp->inp_ip.ip_ttl = ip_defttl;
	inp->inp_ppcb = (caddr_t)tp;
	return (tp);
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *
tcp_drop(struct tcpcb *tp, int err)
{
	struct socket *so = tp->t_inpcb->inp_socket;

	if (TCPS_HAVERCVDSYN(tp->t_state))
	{
		tp->t_state = TCPS_CLOSED;
		(void) tcp_output(tp);
		tcpstat.tcps_drops++;
	}
	else
		tcpstat.tcps_conndrops++;
	if (err == ETIMEDOUT && tp->t_softerror)
		err = tp->t_softerror;
	so->so_error = err;
	return (tcp_close(tp));
}

/* Close a TCP control block:
 *      discard all space held by the tcp
 *      discard internet protocol block
 *      wake up any sleepers
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
	struct mbuf *q;
	struct mbuf *nq;
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct rtentry *rt;
	int dosavessthresh;

	/*
	 * If we got enough samples through the srtt filter,
	 * save the rtt and rttvar in the routing entry.
	 * 'Enough' is arbitrarily defined as the 16 samples.
	 * 16 samples is enough for the srtt filter to converge
	 * to within 5% of the correct value; fewer samples and
	 * we could save a very bogus rtt.
	 *
	 * Don't update the default route's characteristics and don't
	 * update anything that the user "locked".
	 */
	if (tp->t_rttupdated
			>= 16&&
			(rt = inp->inp_route.ro_rt) &&
			((struct sockaddr_in *)rt_key(rt))->sin_addr.s_addr != INADDR_ANY)
	{
		u_long i = 0;

		if ((rt->rt_rmx.rmx_locks & RTV_RTT) == 0)
		{
			i = tp->t_srtt * (RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE));
			if (rt->rt_rmx.rmx_rtt && i)
				/*
				 * filter this update to half the old & half
				 * the new values, converting scale.
				 * See route.h and tcp_var.h for a
				 * description of the scaling constants.
				 */
				rt->rt_rmx.rmx_rtt = (rt->rt_rmx.rmx_rtt + i) / 2;
			else
				rt->rt_rmx.rmx_rtt = i;
			tcpstat.tcps_cachedrtt++;
		}
		if ((rt->rt_rmx.rmx_locks & RTV_RTTVAR) == 0)
		{
			i = tp->t_rttvar * (RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE));
			if (rt->rt_rmx.rmx_rttvar && i)
				rt->rt_rmx.rmx_rttvar = (rt->rt_rmx.rmx_rttvar + i) / 2;
			else
				rt->rt_rmx.rmx_rttvar = i;
			tcpstat.tcps_cachedrttvar++;
		}
		/*
		 * The old comment here said:
		 * update the pipelimit (ssthresh) if it has been updated
		 * already or if a pipesize was specified & the threshhold
		 * got below half the pipesize.  I.e., wait for bad news
		 * before we start updating, then update on both good
		 * and bad news.
		 *
		 * But we want to save the ssthresh even if no pipesize is
		 * specified explicitly in the route, because such
		 * connections still have an implicit pipesize specified
		 * by the global tcp_sendspace.  In the absence of a reliable
		 * way to calculate the pipesize, it will have to do.
		 */
		i = tp->snd_ssthresh;
		if (rt->rt_rmx.rmx_sendpipe != 0)
			dosavessthresh = (i < rt->rt_rmx.rmx_sendpipe / 2);
		else
			dosavessthresh = (i < so->so_snd.sb_hiwat / 2);
		if (((rt->rt_rmx.rmx_locks & RTV_SSTHRESH) == 0 && i != 0
				&& rt->rt_rmx.rmx_ssthresh != 0) || dosavessthresh)
		{
			/*
			 * convert the limit from user data bytes to
			 * packets then to packet data bytes.
			 */
			i = (i + tp->t_maxseg / 2) / tp->t_maxseg;
			if (i < 2)
				i = 2;
			i *= (u_long) (tp->t_maxseg + sizeof(struct tcpiphdr));
			if (rt->rt_rmx.rmx_ssthresh)
				rt->rt_rmx.rmx_ssthresh = (rt->rt_rmx.rmx_ssthresh + i) / 2;
			else
				rt->rt_rmx.rmx_ssthresh = i;
			tcpstat.tcps_cachedssthresh++;
		}
	}
	/* free the reassembly queue, if any */
	for (q = tp->t_segq; q; q = nq)
	{
		nq = q->m_nextpkt;
		tp->t_segq = nq;
		m_freem(q);
	}
	if (tp->t_template)
		(void) m_free(dtom(tp->t_template));
	inp->inp_ppcb = NULL;
	soisdisconnected(so);
	in_pcbdetach(inp);
	tcpstat.tcps_closed++;
	return ((struct tcpcb *) 0);
}

void
tcp_drain()
{

}

/*
 * Notify a tcp user of an asynchronous error;
 * store error as soft error, but wake up user
 * (for now, won't do anything until can select for soft error).
 */
void
tcp_notify(struct inpcb *inp, int error)
{
	struct tcpcb *tp = (struct tcpcb *)inp->inp_ppcb;
	struct socket *so = inp->inp_socket;

	/*
	 * Ignore some errors if we are hooked up.
	 * If connection hasn't completed, has retransmitted several times,
	 * and receives a second error, give up now.  This is better
	 * than waiting a long time to establish a connection that
	 * can never complete.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
	     (error == EHOSTUNREACH || error == ENETUNREACH ||
	      error == EHOSTDOWN)) {
		return;
	} else if (tp->t_state < TCPS_ESTABLISHED && tp->t_rxtshift > 3 &&
	    tp->t_softerror)
		so->so_error = error;
	else
		tp->t_softerror = error;
	wakeup((caddr_t) &so->so_timeo);
	sorwakeup(so);
	sowwakeup(so);
}

void
tcp_ctlinput(int cmd, struct sockaddr *sa, struct ip *ip)
{
	struct tcphdr *th;
	extern struct in_addr zeroin_addr;
	extern u_char inetctlerrmap[];
	void (*notify) __P((struct inpcb *, int)) = tcp_notify;

	if (cmd == PRC_QUENCH)
		notify = tcp_quench;
	else if (!PRC_IS_REDIRECT(cmd) &&
		 ((unsigned)cmd > PRC_NCMDS || inetctlerrmap[cmd] == 0))
		return;
	if (ip) {
		th = (struct tcphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		in_pcbnotify(&tcb, sa, th->th_dport, ip->ip_src, th->th_sport,
			cmd, notify);
	} else
		in_pcbnotify(&tcb, sa, 0, zeroin_addr, 0, cmd, notify);
}

/*
 * When a source quench is received, close congestion window
 * to one segment.  We will gradually open it again as we proceed.
 */
void tcp_quench(struct inpcb *inp, int err)
{
	struct tcpcb *tp = intotcpcb(inp);

	if (tp)
		tp->snd_cwnd = tp->t_maxseg;
}
