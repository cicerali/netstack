/*
 * tcp_usrreq.c
 *
 *  Created on: Aug 27, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/protosw.h"
#include "sys/stat.h"

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
#include "netinet/tcp_debug.h"

#if 0
/*
 * Process a TCP user request for TCP tb.  If this is a send request
 * then m is the mbuf chain of send data.  If this is a timer expiration
 * (called from the software clock routine), then timertype tells which timer.
 */
/*ARGSUSED*/
int
tcp_usrreq(struct socket *so,int req, struct mbuf *m, struct mbuf *nam, struct mbuf *control)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	int s;
	int error = 0;
	int ostate;

	if (req == PRU_CONTROL)
		return (in_control(so, (u_long)m, (caddr_t)nam,
			(struct ifnet *)control));
	if (control && control->m_len) {
		m_freem(control);
		if (m)
			m_freem(m);
		return (EINVAL);
	}

	inp = sotoinpcb(so);
	/*
	 * When a TCP is attached to a socket, then there will be
	 * a (struct inpcb) pointed at by the socket, and this
	 * structure will point at a subsidary (struct tcpcb).
	 */
	if (inp == 0 && req != PRU_ATTACH) {
#if 0
		/*
		 * The following corrects an mbuf leak under rare
		 * circumstances, but has not been fully tested.
		 */
		if (m && req != PRU_SENSE)
			m_freem(m);
#else
		/* safer version of fix for mbuf leak */
		if (m && (req == PRU_SEND || req == PRU_SENDOOB))
			m_freem(m);
#endif
		return (EINVAL);		/* XXX */
	}
	if (inp) {
		tp = intotcpcb(inp);
		/* WHAT IF TP IS 0? */
#ifdef KPROF
		tcp_acounts[tp->t_state][req]++;
#endif
		ostate = tp->t_state;
	} else
		ostate = 0;
	switch (req) {

	/*
	 * TCP attaches to socket via PRU_ATTACH, reserving space,
	 * and an internet control block.
	 */
	case PRU_ATTACH:
		if (inp) {
			error = EISCONN;
			break;
		}
		error = tcp_attach(so);
		if (error)
			break;
		if ((so->so_options & SO_LINGER) && so->so_linger == 0)
			so->so_linger = TCP_LINGERTIME;
		tp = sototcpcb(so);
		break;

	/*
	 * PRU_DETACH detaches the TCP protocol from the socket.
	 * If the protocol state is non-embryonic, then can't
	 * do this directly: have to initiate a PRU_DISCONNECT,
	 * which may finish later; embryonic TCB's can just
	 * be discarded here.
	 */
	case PRU_DETACH:
		if (tp->t_state > TCPS_LISTEN)
			tp = tcp_disconnect(tp);
		else
			tp = tcp_close(tp);
		break;

	/*
	 * Give the socket an address.
	 */
	case PRU_BIND:
		error = in_pcbbind(inp, nam);
		if (error)
			break;
		break;

	/*
	 * Prepare to accept connections.
	 */
	case PRU_LISTEN:
		if (inp->inp_lport == 0)
			error = in_pcbbind(inp, (struct mbuf *)0);
		if (error == 0)
			tp->t_state = TCPS_LISTEN;
		break;

	/*
	 * Initiate connection to peer.
	 * Create a template for use in transmissions on this connection.
	 * Enter SYN_SENT state, and mark socket as connecting.
	 * Start keep-alive timer, and seed output sequence space.
	 * Send initial segment on connection.
	 */
	case PRU_CONNECT:
		if (inp->inp_lport == 0) {
			error = in_pcbbind(inp, (struct mbuf *)0);
			if (error)
				break;
		}
		error = in_pcbconnect(inp, nam);
		if (error)
			break;
		tp->t_template = tcp_template(tp);
		if (tp->t_template == 0) {
			in_pcbdisconnect(inp);
			error = ENOBUFS;
			break;
		}
		/* Compute window scaling to request.  */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
		    (TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
			tp->request_r_scale++;
		soisconnecting(so);
		tcpstat.tcps_connattempt++;
		tp->t_state = TCPS_SYN_SENT;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
		tp->iss = tcp_iss; tcp_iss += TCP_ISSINCR/4;
		tcp_sendseqinit(tp);
		error = tcp_output(tp);
		break;

	/*
	 * Create a TCP connection between two sockets.
	 */
	case PRU_CONNECT2:
		error = EOPNOTSUPP;
		break;

	/*
	 * Initiate disconnect from peer.
	 * If connection never passed embryonic stage, just drop;
	 * else if don't need to let data drain, then can just drop anyways,
	 * else have to begin TCP shutdown process: mark socket disconnecting,
	 * drain unread data, state switch to reflect user close, and
	 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
	 * when peer sends FIN and acks ours.
	 *
	 * SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC TCPCB.
	 */
	case PRU_DISCONNECT:
		tp = tcp_disconnect(tp);
		break;

	/*
	 * Accept a connection.  Essentially all the work is
	 * done at higher levels; just return the address
	 * of the peer, storing through addr.
	 */
	case PRU_ACCEPT:
		in_setpeeraddr(inp, nam);
		break;

	/*
	 * Mark the connection as being incapable of further output.
	 */
	case PRU_SHUTDOWN:
		socantsendmore(so);
		tp = tcp_usrclosed(tp);
		if (tp)
			error = tcp_output(tp);
		break;

	/*
	 * After a receive, possibly send window update to peer.
	 */
	case PRU_RCVD:
		(void) tcp_output(tp);
		break;

	/*
	 * Do a send by putting data in output queue and updating urgent
	 * marker if URG set.  Possibly send more data.
	 */
	case PRU_SEND:
		sbappend(&so->so_snd, m);
		error = tcp_output(tp);
		break;

	/*
	 * Abort the TCP.
	 */
	case PRU_ABORT:
		tp = tcp_drop(tp, ECONNABORTED);
		break;

	case PRU_SENSE:
		((struct stat *) m)->st_blksize = so->so_snd.sb_hiwat;
		return (0);

	case PRU_RCVOOB:
		if ((so->so_oobmark == 0 &&
		    (so->so_state & SS_RCVATMARK) == 0) ||
		    so->so_options & SO_OOBINLINE ||
		    tp->t_oobflags & TCPOOB_HADDATA) {
			error = EINVAL;
			break;
		}
		if ((tp->t_oobflags & TCPOOB_HAVEDATA) == 0) {
			error = EWOULDBLOCK;
			break;
		}
		m->m_len = 1;
		*mtod(m, caddr_t) = tp->t_iobc;
		if (((int)nam & MSG_PEEK) == 0)
			tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
		break;

	case PRU_SENDOOB:
		if (sbspace(&so->so_snd) < -512) {
			m_freem(m);
			error = ENOBUFS;
			break;
		}
		/*
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section.
		 * Otherwise, snd_up should be one lower.
		 */
		sbappend(&so->so_snd, m);
		tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
		tp->t_force = 1;
		error = tcp_output(tp);
		tp->t_force = 0;
		break;

	case PRU_SOCKADDR:
		in_setsockaddr(inp, nam);
		break;

	case PRU_PEERADDR:
		in_setpeeraddr(inp, nam);
		break;

	/*
	 * TCP slow timer went off; going through this
	 * routine for tracing's sake.
	 */
	case PRU_SLOWTIMO:
		tp = tcp_timers(tp, (int)nam);
		req |= (int)nam << 8;		/* for debug's sake */
		break;

	default:
		panic("tcp_usrreq");
	}
	if (tp && (so->so_options & SO_DEBUG))
		tcp_trace(TA_USER, ostate, tp, (struct tcpiphdr *)0, req);
	return (error);
}
#endif

#ifdef TCPDEBUG
#define TCPDEBUG0       int ostate
#define TCPDEBUG1()     ostate = tp ? tp->t_state : 0
#define TCPDEBUG2(req)  if (tp && (so->so_options & SO_DEBUG)) \
                                tcp_trace(TA_USER, ostate, tp, 0, req)
#else
#define TCPDEBUG0
#define TCPDEBUG1()
#define TCPDEBUG2(req)
#endif

/*
 * TCP attaches to socket via pru_attach(), reserving space,
 * and an internet control block.
 */
static int
tcp_usr_attach(struct socket *so, int proto)
{
        int error;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp = 0;
        TCPDEBUG0;

        TCPDEBUG1();
        if (inp) {
                error = EISCONN;
                goto out;
        }

        error = tcp_attach(so);
        if (error)
                goto out;

        if ((so->so_options & SO_LINGER) && so->so_linger == 0)
                so->so_linger = TCP_LINGERTIME * hz;
        tp = sototcpcb(so);
out:
        TCPDEBUG2(PRU_ATTACH);
        return error;
}

/*
 * pru_detach() detaches the TCP protocol from the socket.
 * If the protocol state is non-embryonic, then can't
 * do this directly: have to initiate a pru_disconnect(),
 * which may finish later; embryonic TCB's can just
 * be discarded here.
 */
static int
tcp_usr_detach(struct socket *so)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;
        TCPDEBUG0;

        if (inp == 0) {
                return EINVAL;  /* XXX */
        }
        tp = intotcpcb(inp);
        TCPDEBUG1();
        if (tp->t_state > TCPS_LISTEN)
                tp = tcp_disconnect(tp);
        else
                tp = tcp_close(tp);

        TCPDEBUG2(PRU_DETACH);
        return error;
}

#define COMMON_START()  TCPDEBUG0; \
                        do { \
                                     if (inp == 0) { \
                                             return EINVAL; \
                                     } \
                                     tp = intotcpcb(inp); \
                                     TCPDEBUG1(); \
                     } while(0)

#define COMMON_END(req) out: TCPDEBUG2(req); return error


/*
 * Give the socket an address.
 */
static int
tcp_usr_bind(struct socket *so, struct mbuf *nam)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;
        struct sockaddr_in *sinp;

        COMMON_START();

        /*
         * Must check for multicast addresses and disallow binding
         * to them.
         */
        sinp = mtod(nam, struct sockaddr_in *);
        if (sinp->sin_family == AF_INET &&
            IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
                error = EAFNOSUPPORT;
                goto out;
        }
        error = in_pcbbind(inp, nam);
        if (error)
                goto out;
        COMMON_END(PRU_BIND);

}

/*
 * Prepare to accept connections.
 */
static int
tcp_usr_listen(struct socket *so)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        if (inp->inp_lport == 0)
                error = in_pcbbind(inp, NULL);
        if (error == 0)
                tp->t_state = TCPS_LISTEN;
        COMMON_END(PRU_LISTEN);
}

/*
 * Initiate connection to peer.
 * Create a template for use in transmissions on this connection.
 * Enter SYN_SENT state, and mark socket as connecting.
 * Start keep-alive timer, and seed output sequence space.
 * Send initial segment on connection.
 */
static int
tcp_usr_connect(struct socket *so, struct mbuf *nam)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;
        struct sockaddr_in *sinp;

        COMMON_START();

        /*
         * Must disallow TCP ``connections'' to multicast addresses.
         */
        sinp = mtod(nam, struct sockaddr_in *);
        if (sinp->sin_family == AF_INET
            && IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
                error = EAFNOSUPPORT;
                goto out;
        }

		if (inp->inp_lport == 0) {
			error = in_pcbbind(inp, (struct mbuf *)0);
			if (error)
				goto out;
		}
		error = in_pcbconnect(inp, nam);
		if (error)
			goto out;
		tp->t_template = tcp_template(tp);
		if (tp->t_template == 0) {
			in_pcbdisconnect(inp);
			error = ENOBUFS;
			goto out;
		}
		/* Compute window scaling to request.  */
		while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
		    (TCP_MAXWIN << tp->request_r_scale) < so->so_rcv.sb_hiwat)
			tp->request_r_scale++;
		soisconnecting(so);
		tcpstat.tcps_connattempt++;
		tp->t_state = TCPS_SYN_SENT;
		tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
		tp->iss = tcp_iss; tcp_iss += TCP_ISSINCR/4;
		tcp_sendseqinit(tp);
		error = tcp_output(tp);
        COMMON_END(PRU_CONNECT);
}

/*
 * Initiate disconnect from peer.
 * If connection never passed embryonic stage, just drop;
 * else if don't need to let data drain, then can just drop anyways,
 * else have to begin TCP shutdown process: mark socket disconnecting,
 * drain unread data, state switch to reflect user close, and
 * send segment (e.g. FIN) to peer.  Socket will be really disconnected
 * when peer sends FIN and acks ours.
 *
 * SHOULD IMPLEMENT LATER PRU_CONNECT VIA REALLOC TCPCB.
 */
static int
tcp_usr_disconnect(struct socket *so)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        tp = tcp_disconnect(tp);
        COMMON_END(PRU_DISCONNECT);
}

/*
 * Accept a connection.  Essentially all the work is
 * done at higher levels; just return the address
 * of the peer, storing through addr.
 */
static int
tcp_usr_accept(struct socket *so, struct mbuf *nam)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        in_setpeeraddr(inp, nam);
        COMMON_END(PRU_ACCEPT);
}

/*
 * Mark the connection as being incapable of further output.
 */
static int
tcp_usr_shutdown(struct socket *so)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        socantsendmore(so);
        tp = tcp_usrclosed(tp);
        if (tp)
                error = tcp_output(tp);
        COMMON_END(PRU_SHUTDOWN);
}

/*
 * After a receive, possibly send window update to peer.
 */
static int
tcp_usr_rcvd(struct socket *so, int flags)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        tcp_output(tp);
        COMMON_END(PRU_RCVD);
}

/*
 * Do a send by putting data in output queue and updating urgent
 * marker if URG set.  Possibly send more data.  Unlike the other
 * pru_*() routines, the mbuf chains are our responsibility.  We
 * must either enqueue them or free them.  The other pru_* routines
 * generally are caller-frees.
 */
static int
tcp_usr_send(struct socket *so, int flags, struct mbuf *m, struct mbuf *nam,
             struct mbuf *control)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;
        TCPDEBUG0;

        if (inp == NULL) {
                /*
                 * OOPS! we lost a race, the TCP session got reset after
                 * we checked SS_CANTSENDMORE, eg: while doing uiomove or a
                 * network interrupt in the non-splnet() section of sosend().
                 */
                if (m)
                        m_freem(m);
                if (control)
                        m_freem(control);
                error = ECONNRESET;     /* XXX EPIPE? */
                goto out;
        }
        tp = intotcpcb(inp);
        TCPDEBUG1();
        if (control) {
                /* TCP doesn't do control messages (rights, creds, etc) */
                if (control->m_len) {
                        m_freem(control);
                        if (m)
                                m_freem(m);
                        error = EINVAL;
                        goto out;
                }
                m_freem(control);       /* empty control, just free it */
        }
        if(!(flags & PRUS_OOB)) {
                sbappend(&so->so_snd, m);
                if (flags & PRUS_EOF) {
                        /*
                         * Close the send side of the connection after
                         * the data is sent.
                         */
                        socantsendmore(so);
                        tp = tcp_usrclosed(tp);
                }
                if (tp != NULL)
                        error = tcp_output(tp);
        } else {
                if (sbspace(&so->so_snd) < -512) {
                        m_freem(m);
                        error = ENOBUFS;
                        goto out;
                }
                /*
                 * According to RFC961 (Assigned Protocols),
                 * the urgent pointer points to the last octet
                 * of urgent data.  We continue, however,
                 * to consider it to indicate the first octet
                 * of data past the urgent section.
                 * Otherwise, snd_up should be one lower.
                 */
                sbappend(&so->so_snd, m);
                tp->snd_up = tp->snd_una + so->so_snd.sb_cc;
                tp->t_force = 1;
                error = tcp_output(tp);
                tp->t_force = 0;
        }
        COMMON_END((flags & PRUS_OOB) ? PRU_SENDOOB :
                   ((flags & PRUS_EOF) ? PRU_SEND_EOF : PRU_SEND));
}

/*
 * Abort the TCP.
 */
static int
tcp_usr_abort(struct socket *so)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        tp = tcp_drop(tp, ECONNABORTED);
        COMMON_END(PRU_ABORT);
}

/*
 * Fill in st_bklsize for fstat() operations on a socket.
 */
static int
tcp_usr_sense(struct socket *so, struct stat *sb)
{
        sb->st_blksize = so->so_snd.sb_hiwat;
        return 0;
}

static int
tcp_usr_rcvoob(struct socket *so, struct mbuf *m, int flags)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        if ((so->so_oobmark == 0 &&
             (so->so_state & SS_RCVATMARK) == 0) ||
            so->so_options & SO_OOBINLINE ||
            tp->t_oobflags & TCPOOB_HADDATA) {
                error = EINVAL;
                goto out;
        }
        if ((tp->t_oobflags & TCPOOB_HAVEDATA) == 0) {
                error = EWOULDBLOCK;
                goto out;
        }
        m->m_len = 1;
        *mtod(m, caddr_t) = tp->t_iobc;
        if ((flags & MSG_PEEK) == 0)
                tp->t_oobflags ^= (TCPOOB_HAVEDATA | TCPOOB_HADDATA);
        COMMON_END(PRU_RCVOOB);
}

static int
tcp_usr_sockaddr(struct socket *so, struct mbuf *nam)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        in_setsockaddr(inp, nam);
        COMMON_END(PRU_SOCKADDR);
}

static int
tcp_usr_peeraddr(struct socket *so, struct mbuf *nam)
{
        int error = 0;
        struct inpcb *inp = sotoinpcb(so);
        struct tcpcb *tp;

        COMMON_START();
        in_setpeeraddr(inp, nam);
        COMMON_END(PRU_PEERADDR);
}

/*
 * XXX - this should just be a call to in_control, but we need to get
 * the types worked out.
 */
static int
tcp_usr_control(struct socket *so, int cmd, caddr_t arg, struct ifnet *ifp)
{
        return in_control(so, cmd, arg, ifp);
}

struct pr_usrreqs tcp_usrreqs = {
		.pru_abort =            tcp_usr_abort,
		.pru_accept =           tcp_usr_accept,
		.pru_attach =           tcp_usr_attach,
		.pru_bind =             tcp_usr_bind,
		.pru_connect =          tcp_usr_connect,
		.pru_connect2 =			pru_connect2_notsupp,
		.pru_control =          tcp_usr_control,
		.pru_detach =           tcp_usr_detach,
		.pru_disconnect =       tcp_usr_disconnect,
		.pru_listen =           tcp_usr_listen,
		.pru_peeraddr =         tcp_usr_peeraddr,
		.pru_rcvd =             tcp_usr_rcvd,
		.pru_rcvoob =           tcp_usr_rcvoob,
		.pru_send =             tcp_usr_send,
		.pru_sense = 			tcp_usr_sense,
		.pru_shutdown =         tcp_usr_shutdown,
		.pru_sockaddr =         tcp_usr_sockaddr,
};

int
tcp_ctloutput(int op, struct socket *so, int level, int optname, struct mbuf **mp)
{
	int error = 0, s;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct mbuf *m;
	int i;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		if (op == PRCO_SETOPT && *mp)
			(void) m_free(*mp);
		return (ECONNRESET);
	}
	if (level != IPPROTO_TCP) {
		error = ip_ctloutput(op, so, level, optname, mp);
		return (error);
	}
	tp = intotcpcb(inp);

	switch (op) {

	case PRCO_SETOPT:
		m = *mp;
		switch (optname) {

		case TCP_NODELAY:
			if (m == NULL || m->m_len < sizeof (int))
				error = EINVAL;
			else if (*mtod(m, int *))
				tp->t_flags |= TF_NODELAY;
			else
				tp->t_flags &= ~TF_NODELAY;
			break;

		case TCP_MAXSEG:
			if (m && (i = *mtod(m, int *)) > 0 && i <= tp->t_maxseg)
				tp->t_maxseg = i;
			else
				error = EINVAL;
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (m)
			(void) m_free(m);
		break;

	case PRCO_GETOPT:
		*mp = m = m_get(M_WAIT, MT_SOOPTS);
		m->m_len = sizeof(int);

		switch (optname) {
		case TCP_NODELAY:
			*mtod(m, int *) = tp->t_flags & TF_NODELAY;
			break;
		case TCP_MAXSEG:
			*mtod(m, int *) = tp->t_maxseg;
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	return (error);
}

u_long	tcp_sendspace = 1024*8;
u_long	tcp_recvspace = 1024*8;

/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
int
tcp_attach(so)
	struct socket *so;
{
	register struct tcpcb *tp;
	struct inpcb *inp;
	int error;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, tcp_sendspace, tcp_recvspace);
		if (error)
			return (error);
	}
	error = in_pcballoc(so, &tcb);
	if (error)
		return (error);
	inp = sotoinpcb(so);
	tp = tcp_newtcpcb(inp);
	if (tp == 0) {
		int nofd = so->so_state & SS_NOFDREF;	/* XXX */

		so->so_state &= ~SS_NOFDREF;	/* don't free the socket yet */
		in_pcbdetach(inp);
		so->so_state |= nofd;
		return (ENOBUFS);
	}
	tp->t_state = TCPS_CLOSED;
	return (0);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
struct tcpcb *
tcp_disconnect(tp)
	register struct tcpcb *tp;
{
	struct socket *so = tp->t_inpcb->inp_socket;

	if (tp->t_state < TCPS_ESTABLISHED)
		tp = tcp_close(tp);
	else if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		tp = tcp_drop(tp, 0);
	else {
		soisdisconnecting(so);
		sbflush(&so->so_rcv);
		tp = tcp_usrclosed(tp);
		if (tp)
			(void) tcp_output(tp);
	}
	return (tp);
}


/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
struct tcpcb *
tcp_usrclosed(tp)
	register struct tcpcb *tp;
{

	switch (tp->t_state) {

	case TCPS_CLOSED:
	case TCPS_LISTEN:
	case TCPS_SYN_SENT:
		tp->t_state = TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_RECEIVED:
	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2)
		soisdisconnected(tp->t_inpcb->inp_socket);
	return (tp);
}
