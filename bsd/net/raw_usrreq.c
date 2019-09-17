/*
 * raw_usrreq.c
 *
 *  Created on: Aug 21, 2019
 *      Author: cicerali
 */
#include "sys/param.h"

#include "sys/mbuf.h"
#include "sys/protosw.h"
#include "sys/socket.h"
#include "sys/socketvar.h"

#include "net/raw_cb.h"

/*
 * Initialize raw connection block q.
 */
void
raw_init()
{

	rawcb.rcb_next = rawcb.rcb_prev = &rawcb;
}

/*
 * Raw protocol input routine.  Find the socket
 * associated with the packet(s) and move them over.  If
 * nothing exists for this packet, drop it.
 */
/*
 * Raw protocol interface.
 */
void
raw_input(struct mbuf *m0, struct sockproto *proto, struct sockaddr *src, struct sockaddr *dst)
{
	struct rawcb *rp;
	struct mbuf *m = m0;
	int sockets = 0;
	struct socket *last;

	last = 0;
	for (rp = rawcb.rcb_next; rp != &rawcb; rp = rp->rcb_next) {
		if (rp->rcb_proto.sp_family != proto->sp_family)
			continue;
		if (rp->rcb_proto.sp_protocol  &&
		    rp->rcb_proto.sp_protocol != proto->sp_protocol)
			continue;
		/*
		 * We assume the lower level routines have
		 * placed the address in a canonical format
		 * suitable for a structure comparison.
		 *
		 * Note that if the lengths are not the same
		 * the comparison will fail at the first byte.
		 */
#define	equal(a1, a2) \
  (bcmp((caddr_t)(a1), (caddr_t)(a2), a1->sa_len) == 0)
		if (rp->rcb_laddr && !equal(rp->rcb_laddr, dst))
			continue;
		if (rp->rcb_faddr && !equal(rp->rcb_faddr, src))
			continue;
		if (last) {
			struct mbuf *n;
			if (n = m_copy(m, 0, (int)M_COPYALL)) {
				if (sbappendaddr(&last->so_rcv, src,
				    n, (struct mbuf *)0) == 0)
					/* should notify about lost packet */
					m_freem(n);
				else {
					sorwakeup(last);
					sockets++;
				}
			}
		}
		last = rp->rcb_socket;
	}
	if (last) {
		if (sbappendaddr(&last->so_rcv, src,
		    m, (struct mbuf *)0) == 0)
			m_freem(m);
		else {
			sorwakeup(last);
			sockets++;
		}
	} else
		m_freem(m);
}

/*ARGSUSED*/
void
raw_ctlinput(cmd, arg)
	int cmd;
	struct sockaddr *arg;
{

	if (cmd < 0 || cmd > PRC_NCMDS)
		return;
	/* INCOMPLETE */
}

static int
raw_uabort(struct socket *so)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;
        raw_disconnect(rp);
        sofree(so);
        soisdisconnected(so);
        return 0;
}

/* pru_accept is EOPNOTSUPP */

static int
raw_uattach(struct socket *so, int proto)
{
        struct rawcb *rp = sotorawcb(so);
        int error;

        if (rp == 0)
                return EINVAL;
        return raw_attach(so, proto);
}

static int
raw_ubind(struct socket *so, struct mbuf *nam)
{
        return EINVAL;
}

static int
raw_uconnect(struct socket *so, struct mbuf *nam)
{
        return EINVAL;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
raw_udetach(struct socket *so)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;

        raw_detach(rp);
        return 0;
}

static int
raw_udisconnect(struct socket *so)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;
        if (rp->rcb_faddr == 0) {
                return ENOTCONN;
        }
        raw_disconnect(rp);
        soisdisconnected(so);
        return 0;
}

/* pru_listen is EOPNOTSUPP */

static int
raw_upeeraddr(struct socket *so, struct mbuf *nam)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;
        if (rp->rcb_faddr == 0) {
                return ENOTCONN;
        }
        int len = rp->rcb_faddr->sa_len;
        bcopy((caddr_t)rp->rcb_faddr, mtod(nam, caddr_t), (unsigned)len);
        nam->m_len = len;
        return 0;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
raw_usend(struct socket *so, int flags, struct mbuf *m,
          struct mbuf *nam, struct mbuf *control)
{
        int error;
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0) {
                error = EINVAL;
                goto release;
        }

        if (flags & PRUS_OOB) {
                error = EOPNOTSUPP;
                goto release;
        }

        if (control && control->m_len) {
                error = EOPNOTSUPP;
                goto release;
        }
        if (nam) {
                if (rp->rcb_faddr) {
                        error = EISCONN;
                        goto release;
                }
                rp->rcb_faddr = mtod(nam, struct sockaddr *);
        } else if (rp->rcb_faddr == 0) {
                error = ENOTCONN;
                goto release;
        }
        error = (*so->so_proto->pr_output)(m, so);
        m = NULL;
        if (nam)
                rp->rcb_faddr = 0;
release:
        if (m != NULL)
                m_freem(m);
        return (error);
}

/* pru_sense is null */

static int
raw_ushutdown(struct socket *so)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;
        socantsendmore(so);
        return 0;
}

static int
raw_usockaddr(struct socket *so, struct mbuf *nam)
{
        struct rawcb *rp = sotorawcb(so);

        if (rp == 0)
                return EINVAL;
        if (rp->rcb_laddr == 0)
                return EINVAL;
        int len = rp->rcb_laddr->sa_len;
        bcopy((caddr_t)rp->rcb_laddr, mtod(nam, caddr_t), (unsigned)len);
        nam->m_len = len;
        return 0;
}

struct pr_usrreqs raw_usrreqs = {
        .pru_abort =            raw_uabort,
        .pru_attach =           raw_uattach,
        .pru_bind =             raw_ubind,
        .pru_connect =          raw_uconnect,
        .pru_detach =           raw_udetach,
        .pru_disconnect =       raw_udisconnect,
        .pru_peeraddr =         raw_upeeraddr,
        .pru_send =             raw_usend,
        .pru_shutdown =         raw_ushutdown,
        .pru_sockaddr =         raw_usockaddr,
};
