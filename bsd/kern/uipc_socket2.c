/*
 * uipc_socket2.c
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */
#include "sys/param.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sys/systm.h"
#include "sys/proc.h"
#include "sys/malloc.h"
#include "sys/mbuf.h"
#include "sys/protosw.h"
#include "sys/stat.h"
#include "sys/socket.h"
#include "sys/socketvar.h"

/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_q0 for connections in progress
 * and so_q for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_q0 by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_q, making it available to accept().
 *
 * If a socket is closed with sockets on either
 * so_q0 or so_q, these sockets are dropped.
 *
 * If higher level protocols are implemented in
 * the kernel, the wakeups done here will sometimes
 * cause software-interrupt process scheduling.
 */

void
soisconnecting(so)
	register struct socket *so;
{

	so->so_state &= ~(SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTING;
}

void
soisconnected(struct socket *so)
{
	struct socket *head = so->so_head;

	so->so_state &= ~(SS_ISCONNECTING|SS_ISDISCONNECTING|SS_ISCONFIRMING);
	so->so_state |= SS_ISCONNECTED;
	if (head && soqremque(so, 0)) {
		soqinsque(head, so, 1);
		sorwakeup(head);
		wakeup((caddr_t)&head->so_timeo);
	} else {
		wakeup((caddr_t)&so->so_timeo);
		sorwakeup(so);
		sowwakeup(so);
	}
}

void
soisdisconnecting(so)
	register struct socket *so;
{

	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= (SS_ISDISCONNECTING|SS_CANTRCVMORE|SS_CANTSENDMORE);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

void
soisdisconnected(so)
	register struct socket *so;
{

	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_state |= (SS_CANTRCVMORE|SS_CANTSENDMORE);
	wakeup((caddr_t)&so->so_timeo);
	sowwakeup(so);
	sorwakeup(so);
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 *
 * Currently, sonewconn() is defined as sonewconn1() in socketvar.h
 * to catch calls that are missing the (new) second parameter.
 */
struct socket *
sonewconn1(struct socket *head, int connstatus)
{
	struct socket *so;
	int soqueue = connstatus ? 1 : 0;

	if (head->so_qlen + head->so_q0len > 3 * head->so_qlimit / 2)
		return ((struct socket *)0);
	MALLOC(so, struct socket *, sizeof(*so), M_SOCKET, M_DONTWAIT);
	if (so == NULL)
		return ((struct socket *)0);
	bzero((caddr_t)so, sizeof(*so));
	so->so_type = head->so_type;
	so->so_options = head->so_options &~ SO_ACCEPTCONN;
	so->so_linger = head->so_linger;
	so->so_state = head->so_state | SS_NOFDREF;
	so->so_proto = head->so_proto;
	so->so_timeo = head->so_timeo;
	so->so_pgid = head->so_pgid;
	(void) soreserve(so, head->so_snd.sb_hiwat, head->so_rcv.sb_hiwat);
	soqinsque(head, so, soqueue);
	if ((*so->so_proto->pr_usrreq)(so, PRU_ATTACH,
	    (struct mbuf *)0, (struct mbuf *)0, (struct mbuf *)0)) {
		(void) soqremque(so, soqueue);
		FREE((caddr_t)so, M_SOCKET);
		return ((struct socket *)0);
	}
	if (connstatus) {
		sorwakeup(head);
		wakeup((caddr_t)&head->so_timeo);
		so->so_state |= connstatus;
	}
	return (so);
}

void
soqinsque(struct socket *head, struct socket *so, int q)
{

	struct socket **prev;
	so->so_head = head;
	if (q == 0) {
		head->so_q0len++;
		so->so_q0 = 0;
		for (prev = &(head->so_q0); *prev; )
			prev = &((*prev)->so_q0);
	} else {
		head->so_qlen++;
		so->so_q = 0;
		for (prev = &(head->so_q); *prev; )
			prev = &((*prev)->so_q);
	}
	*prev = so;
}

int
soqremque(struct socket *so, int q)
{
	struct socket *head, *prev, *next;

	head = so->so_head;
	prev = head;
	for (;;) {
		next = q ? prev->so_q : prev->so_q0;
		if (next == so)
			break;
		if (next == 0)
			return (0);
		prev = next;
	}
	if (q == 0) {
		prev->so_q0 = next->so_q0;
		head->so_q0len--;
	} else {
		prev->so_q = next->so_q;
		head->so_qlen--;
	}
	next->so_q0 = next->so_q = 0;
	next->so_head = 0;
	return (1);
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */

void
socantsendmore(so)
	struct socket *so;
{

	so->so_state |= SS_CANTSENDMORE;
	sowwakeup(so);
}

void
socantrcvmore(so)
	struct socket *so;
{

	so->so_state |= SS_CANTRCVMORE;
	sorwakeup(so);
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */
int
sbwait(sb)
	struct sockbuf *sb;
{

	sb->sb_flags |= SB_WAIT;
	return (tsleep((caddr_t)&sb->sb_cc,
	    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK | PCATCH, netio,
	    sb->sb_timeo));
}

/*
 * Lock a sockbuf already known to be locked;
 * return any error returned from sleep (EINTR).
 */
int
sb_lock(sb)
	register struct sockbuf *sb;
{
	int error;

	while (sb->sb_flags & SB_LOCK) {
		sb->sb_flags |= SB_WANT;
		if (error = tsleep((caddr_t)&sb->sb_flags,
		    (sb->sb_flags & SB_NOINTR) ? PSOCK : PSOCK|PCATCH,
		    netio, 0))
			return (error);
	}
	sb->sb_flags |= SB_LOCK;
	return (0);
}

/*
* Make all threads sleeping on the specified identifier runnable.
*/
void
wakeup(void *ident)
{
	// TODO
}

/*
 * Wakeup processes waiting on a socket buffer.
 * Do asynchronous notification via SIGIO
 * if the socket has the SS_ASYNC flag set.
 */
void
sowakeup(struct socket *so, struct sockbuf *sb)
{
	// TODO
//	struct proc *p;
//
//	selwakeup(&sb->sb_sel);
//	sb->sb_flags &= ~SB_SEL;
//	if (sb->sb_flags & SB_WAIT) {
//		sb->sb_flags &= ~SB_WAIT;
//		wakeup((caddr_t)&sb->sb_cc);
//	}
//	if (so->so_state & SS_ASYNC) {
//		if (so->so_pgid < 0)
//			gsignal(-so->so_pgid, SIGIO);
//		else if (so->so_pgid > 0 && (p = pfind(so->so_pgid)) != 0)
//			psignal(p, SIGIO);
//	}
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and
 * one for receiving data.  Each buffer contains a queue of mbufs,
 * information about the number of mbufs and amount of data in the
 * queue, and other fields allowing select() statements and notification
 * on data availability to be implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.
 * Each record is a list of mbufs chained together with the m_next
 * field.  Records are chained together with the m_nextpkt field. The upper
 * level routine soreceive() expects the following conventions to be
 * observed when placing information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's
 *    name, then a record containing that name must be present before
 *    any associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really
 *    just additional data associated with the message), and there are
 *    ``rights'' to be received, then a record containing this data
 *    should be present (mbuf's must be of type MT_RIGHTS).
 * 3. If a name or rights record exists, then it must be followed by
 *    a data record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space
 * should be released by calling sbrelease() when the socket is destroyed.
 */

int
soreserve(struct socket *so, u_long sndcc, u_long rcvcc)
{

	if (sbreserve(&so->so_snd, sndcc) == 0)
		goto bad;
	if (sbreserve(&so->so_rcv, rcvcc) == 0)
		goto bad2;
	if (so->so_rcv.sb_lowat == 0)
		so->so_rcv.sb_lowat = 1;
	if (so->so_snd.sb_lowat == 0)
		so->so_snd.sb_lowat = MCLBYTES;
	if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat)
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat;
	return (0);
bad2:
	sbrelease(&so->so_snd);
bad:
	return (ENOBUFS);
}

/*
 * Allot mbufs to a sockbuf.
 * Attempt to scale mbmax so that mbcnt doesn't become limiting
 * if buffering efficiency is near the normal case.
 */
int
sbreserve(struct sockbuf *sb, u_long cc)
{

	if (cc > sb_max * MCLBYTES / (MSIZE + MCLBYTES))
		return (0);
	sb->sb_hiwat = cc;
	sb->sb_mbmax = MIN(cc * 2, sb_max);
	if (sb->sb_lowat > sb->sb_hiwat)
		sb->sb_lowat = sb->sb_hiwat;
	return (1);
}

/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
void
sbrelease(struct sockbuf *sb)
{

	sbflush(sb);
	sb->sb_hiwat = sb->sb_mbmax = 0;
}

/*
 * Routines to add and remove
 * data from an mbuf queue.
 *
 * The routines sbappend() or sbappendrecord() are normally called to
 * append new mbufs to a socket buffer, after checking that adequate
 * space is available, comparing the function sbspace() with the amount
 * of data to be added.  sbappendrecord() differs from sbappend() in
 * that data supplied is treated as the beginning of a new record.
 * To place a sender's address, optional access rights, and data in a
 * socket receive buffer, sbappendaddr() should be used.  To place
 * access rights and data in a socket receive buffer, sbappendrights()
 * should be used.  In either case, the new data begins a new record.
 * Note that unlike sbappend() and sbappendrecord(), these routines check
 * for the caller that there will be enough space to store the data.
 * Each fails if there is not enough space, or if it cannot find mbufs
 * to store additional information in.
 *
 * Reliable protocols may use the socket send buffer to hold data
 * awaiting acknowledgement.  Data is normally copied from a socket
 * send buffer in a protocol with m_copy for output to a peer,
 * and then removing the data from the socket buffer with sbdrop()
 * or sbdroprecord() when the data is acknowledged by the peer.
 */

/*
 * Append mbuf chain m to the last record in the
 * socket buffer sb.  The additional space associated
 * the mbuf chain is recorded in sb.  Empty mbufs are
 * discarded and mbufs are compacted where possible.
 */
void
sbappend(struct sockbuf *sb, struct mbuf *m)
{
	struct mbuf *n;

	if (m == 0)
		return;
	if (n = sb->sb_mb) {
		while (n->m_nextpkt)
			n = n->m_nextpkt;
		do {
			if (n->m_flags & M_EOR) {
				sbappendrecord(sb, m); /* XXXXXX!!!! */
				return;
			}
		} while (n->m_next && (n = n->m_next));
	}
	sbcompress(sb, m, n);
}

/*
 * As above, except the mbuf chain
 * begins a new record.
 */
void
sbappendrecord(struct sockbuf *sb, struct mbuf *m0)
{
	struct mbuf *m;

	if (m0 == 0)
		return;
	if (m = sb->sb_mb)
		while (m->m_nextpkt)
			m = m->m_nextpkt;
	/*
	 * Put the first mbuf on the queue.
	 * Note this permits zero length records.
	 */
	sballoc(sb, m0);
	if (m)
		m->m_nextpkt = m0;
	else
		sb->sb_mb = m0;
	m = m0->m_next;
	m0->m_next = 0;
	if (m && (m0->m_flags & M_EOR)) {
		m0->m_flags &= ~M_EOR;
		m->m_flags |= M_EOR;
	}
	sbcompress(sb, m, m0);
}


/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
int
sbappendaddr(struct sockbuf *sb, struct sockaddr *asa, struct mbuf *m0, struct mbuf *control)
{
	struct mbuf *m, *n;
	int space = asa->sa_len;

if (m0 && (m0->m_flags & M_PKTHDR) == 0)
panic("sbappendaddr");
	if (m0)
		space += m0->m_pkthdr.len;
	for (n = control; n; n = n->m_next) {
		space += n->m_len;
		if (n->m_next == 0)	/* keep pointer to last control buf */
			break;
	}
	if (space > sbspace(sb))
		return (0);
	if (asa->sa_len > MLEN)
		return (0);
	MGET(m, M_DONTWAIT, MT_SONAME);
	if (m == 0)
		return (0);
	m->m_len = asa->sa_len;
	bcopy((caddr_t)asa, mtod(m, caddr_t), asa->sa_len);
	if (n)
		n->m_next = m0;		/* concatenate data to control */
	else
		control = m0;
	m->m_next = control;
	for (n = m; n; n = n->m_next)
		sballoc(sb, n);
	if (n = sb->sb_mb) {
		while (n->m_nextpkt)
			n = n->m_nextpkt;
		n->m_nextpkt = m;
	} else
		sb->sb_mb = m;
	return (1);
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
void
sbcompress(struct sockbuf *sb, struct mbuf *m, struct mbuf *n)
{
	int eor = 0;
	struct mbuf *o;

	while (m) {
		eor |= m->m_flags & M_EOR;
		if (m->m_len == 0 &&
		    (eor == 0 ||
		     (((o = m->m_next) || (o = n)) &&
		    		 o->m_type == m->m_type))) {
			m = m_free(m);
			continue;
		}
		if (n && (n->m_flags & (M_EXT | M_EOR)) == 0 &&
				(n->m_data + n->m_len + m->m_len) < &n->m_dat[MLEN] &&
				n->m_type == m->m_type) {
			bcopy(mtod(m, caddr_t), mtod(n, caddr_t) + n->m_len,
						    (unsigned)m->m_len);
			n->m_len += m->m_len;
			sb->sb_cc += m->m_len;
			m = m_free(m);
			continue;
		}
		if (n)
			n->m_next = m;
		else
			sb->sb_mb = m;
		sballoc(sb, m);
		n = m;
		m->m_flags &= ~M_EOR;
		m = m->m_next;
				n->m_next = 0;
	}
	if (eor) {
		if (n)
			n->m_flags |= eor;
		else
			printf("semi-panic: sbcompress\n");
	}
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
void
sbflush(struct sockbuf *sb)
{

	if (sb->sb_flags & SB_LOCK)
		panic("EXIT_FAILURE"); //TODO
	while (sb->sb_mbcnt)
		sbdrop(sb, (int)sb->sb_cc);
	if (sb->sb_cc || sb->sb_mb)
		panic("EXIT_FAILURE"); //TODO
}

/*
 * Drop data from (the front of) a sockbuf.
 */
void
sbdrop(struct sockbuf *sb, int len)
{
	struct mbuf *m, *mn;
	struct mbuf *next;

	next = (m = sb->sb_mb) ? m->m_nextpkt : 0;
	while (len > 0) {
		if (m == 0) {
			if (next == 0)
				panic("sbdrop");
			m = next;
			next = m->m_nextpkt;
			continue;
		}
		if (m->m_len > len) {
			m->m_len -= len;
			m->m_data += len;
			sb->sb_cc -= len;
			break;
		}
		len -= m->m_len;
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	while (m && m->m_len == 0) {
		sbfree(sb, m);
		MFREE(m, mn);
		m = mn;
	}
	if (m) {
		sb->sb_mb = m;
		m->m_nextpkt = next;
	} else
		sb->sb_mb = next;
}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
void
sbdroprecord(sb)
	register struct sockbuf *sb;
{
	register struct mbuf *m, *mn;

	m = sb->sb_mb;
	if (m) {
		sb->sb_mb = m->m_nextpkt;
		do {
			sbfree(sb, m);
			MFREE(m, mn);
		} while (m = mn);
	}
}

/*
 * Some routines that return EOPNOTSUPP for entry points that are not
 * supported by a protocol.  Fill in as needed.
 */
int
pru_accept_notsupp(struct socket *so, struct mbuf *nam)
{
        return EOPNOTSUPP;
}

int
pru_connect_notsupp(struct socket *so, struct mbuf *nam)
{
        return EOPNOTSUPP;
}

int
pru_connect2_notsupp(struct socket *so1, struct socket *so2)
{
        return EOPNOTSUPP;
}

int
pru_control_notsupp(struct socket *so, int cmd, caddr_t data,
                    struct ifnet *ifp)
{
        return EOPNOTSUPP;
}

int
pru_listen_notsupp(struct socket *so)
{
        return EOPNOTSUPP;
}

int
pru_rcvd_notsupp(struct socket *so, int flags)
{
        return EOPNOTSUPP;
}

int
pru_rcvoob_notsupp(struct socket *so, struct mbuf *m, int flags)
{
        return EOPNOTSUPP;
}

/*
 * This isn't really a ``null'' operation, but it's the default one
 * and doesn't do anything destructive.
 */
int
pru_sense_null(struct socket *so, struct stat *sb)
{
        sb->st_blksize = so->so_snd.sb_hiwat;
        return 0;
}
