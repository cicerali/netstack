/*
 * protosw.h
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */

#ifndef YATS_SYS_PROTOSW_H_
#define YATS_SYS_PROTOSW_H_

struct socket;
struct stat;

/*
 * Protocol switch table.
 *
 * Each protocol has a handle initializing one of these structures,
 * which is used for protocol-protocol and system-protocol communication.
 *
 * A protocol is called through the pr_init entry before any other.
 * Thereafter it is called every 200ms through the pr_fasttimo entry and
 * every 500ms through the pr_slowtimo for timer based actions.
 * The system will call the pr_drain entry if it is low on space and
 * this should throw away any non-critical data.
 *
 * Protocols pass data between themselves as chains of mbufs using
 * the pr_input and pr_output hooks.  Pr_input passes data up (towards
 * UNIX) and pr_output passes it down (towards the imps); control
 * information passes up and down on pr_ctlinput and pr_ctloutput.
 * The protocol is responsible for the space occupied by any the
 * arguments to these entries and must dispose it.
 *
 * The userreq routine interfaces protocols to the system and is
 * described below.
 */
struct protosw {
	short	pr_type;		/* socket type used for */
	struct	domain *pr_domain;	/* domain protocol a member of */
	short	pr_protocol;		/* protocol number */
	short	pr_flags;		/* see below */
/* protocol-protocol hooks */
	void	(*pr_input)();		/* input to protocol (from below) */
	int	(*pr_output)();		/* output to protocol (from above) */
	void	(*pr_ctlinput)();	/* control input (from below) */
	int	(*pr_ctloutput)();	/* control output (from above) */
/* user-protocol hook */
	int	(*pr_usrreq)();		/* user request: see list below */
/* utility hooks */
	void	(*pr_init)();		/* initialization hook */
	void	(*pr_fasttimo)();	/* fast timeout (200ms) */
	void	(*pr_slowtimo)();	/* slow timeout (500ms) */
	void	(*pr_drain)();		/* flush any excess space possible */
	struct  pr_usrreqs *pr_usrreqs; /* supersedes pr_usrreq() */
};

#define	PR_SLOWHZ	2		/* 2 slow timeouts per second */
#define	PR_FASTHZ	5		/* 5 fast timeouts per second */

/*
 * Values for pr_flags.
 * PR_ADDR requires PR_ATOMIC;
 * PR_ADDR and PR_CONNREQUIRED are mutually exclusive.
 */
#define	PR_ATOMIC	0x01		/* exchange atomic messages only */
#define	PR_ADDR		0x02		/* addresses given with messages */
#define	PR_CONNREQUIRED	0x04		/* connection required by protocol */
#define	PR_WANTRCVD	0x08		/* want PRU_RCVD calls */
#define	PR_RIGHTS	0x10		/* passes capabilities */
#define PR_LISTEN       0x20            /* supports listen(2) and accept(2) */
#define PR_LASTHDR      0x40            /* enforce ipsec policy; last header */
#define PR_ABRTACPTDIS  0x80            /* abort on accept(2) to disconnected socket */
#define PR_PURGEIF      0x100           /* might store struct ifnet pointer;
										   PRU_PURGEIF must be called on ifnet
										   deletion */

/*
 * The arguments to usrreq are:
 *	(*protosw[].pr_usrreq)(up, req, m, nam, opt);
 * where up is a (struct socket *), req is one of these requests,
 * m is a optional mbuf chain containing a message,
 * nam is an optional mbuf chain containing an address,
 * and opt is a pointer to a socketopt structure or nil.
 * The protocol is responsible for disposal of the mbuf chain m,
 * the caller is responsible for any space held by nam and opt.
 * A non-zero return from usrreq gives an
 * UNIX error number which should be passed to higher level software.
 */
#define	PRU_ATTACH		0	/* attach protocol to up */
#define	PRU_DETACH		1	/* detach protocol from up */
#define	PRU_BIND		2	/* bind socket to address */
#define	PRU_LISTEN		3	/* listen for connection */
#define	PRU_CONNECT		4	/* establish connection to peer */
#define	PRU_ACCEPT		5	/* accept connection from peer */
#define	PRU_DISCONNECT		6	/* disconnect from peer */
#define	PRU_SHUTDOWN		7	/* won't send any more data */
#define	PRU_RCVD		8	/* have taken data; more room now */
#define	PRU_SEND		9	/* send this data */
#define	PRU_ABORT		10	/* abort (fast DISCONNECT, DETATCH) */
#define	PRU_CONTROL		11	/* control operations on protocol */
#define	PRU_SENSE		12	/* return status into m */
#define	PRU_RCVOOB		13	/* retrieve out of band data */
#define	PRU_SENDOOB		14	/* send out of band data */
#define	PRU_SOCKADDR		15	/* fetch socket's address */
#define	PRU_PEERADDR		16	/* fetch peer's address */
#define	PRU_CONNECT2		17	/* connect two sockets */
/* begin for protocols internal use */
#define	PRU_FASTTIMO		18	/* 200ms timeout */
#define	PRU_SLOWTIMO		19	/* 500ms timeout */
#define	PRU_PROTORCV		20	/* receive from below */
#define	PRU_PROTOSEND		21	/* send to below */
/* end for protocol's internal use */
#define PRU_SEND_EOF            22      /* send and close */
#define PRU_NREQ                22

#ifdef PRUREQUESTS
static const char *prurequests[] = {
        "ATTACH",       "DETACH",       "BIND",         "LISTEN",
        "CONNECT",      "ACCEPT",       "DISCONNECT",   "SHUTDOWN",
        "RCVD",         "SEND",         "ABORT",        "CONTROL",
        "SENSE",        "RCVOOB",       "SENDOOB",      "SOCKADDR",
        "PEERADDR",     "CONNECT2",     "FASTTIMO",     "SLOWTIMO",
        "PROTORCV",     "PROTOSEND",
        "SEND_EOF",
};
#endif

#define	PRC_IS_REDIRECT(cmd)	\
	((cmd) >= PRC_REDIRECT_NET && (cmd) <= PRC_REDIRECT_TOSHOST)

struct pr_usrreqs {
        int     (*pru_abort) __P((struct socket *so));
        int     (*pru_accept) __P((struct socket *so, struct mbuf *nam));
        int     (*pru_attach) __P((struct socket *so, int proto));
        int     (*pru_bind) __P((struct socket *so, struct mbuf *nam));
        int     (*pru_connect) __P((struct socket *so, struct mbuf *nam));
        int     (*pru_connect2) __P((struct socket *so1, struct socket *so2));
        int     (*pru_control) __P((struct socket *so, int cmd, caddr_t data,
                                    struct ifnet *ifp));
        int     (*pru_detach) __P((struct socket *so));
        int     (*pru_disconnect) __P((struct socket *so));
        int     (*pru_listen) __P((struct socket *so));
        int     (*pru_peeraddr) __P((struct socket *so, struct mbuf *nam));
        int     (*pru_rcvd) __P((struct socket *so, int flags));
        int     (*pru_rcvoob) __P((struct socket *so, struct mbuf *m,
                                   int flags));
        /*
         * The `m' parameter here is almost certainly going to become a
         * `struct uio' at some point in the future.  Similar changes
         * will probably happen for the receive entry points.
         */
        int     (*pru_send) __P((struct socket *so, int flags, struct mbuf *m,
                              struct mbuf *addr, struct mbuf *control));
#define PRUS_OOB        0x1
#define PRUS_EOF        0x2
        int     (*pru_sense) __P((struct socket *so, struct stat *sb));
        int     (*pru_shutdown) __P((struct socket *so));
        int     (*pru_sockaddr) __P((struct socket *so, struct mbuf *nam));
};

struct sockaddr;
int     pru_accept_notsupp __P((struct socket *so, struct mbuf *nam));
int     pru_connect_notsupp __P((struct socket *so, struct mbuf *nam));
int     pru_connect2_notsupp __P((struct socket *so1, struct socket *so2));
int     pru_control_notsupp __P((struct socket *so, int cmd, caddr_t data,
                                 struct ifnet *ifp));
int     pru_listen_notsupp __P((struct socket *so));
int     pru_rcvd_notsupp __P((struct socket *so, int flags));
int     pru_rcvoob_notsupp __P((struct socket *so, struct mbuf *m, int flags));
int     pru_sense_null __P((struct socket *so, struct stat *sb));

/*
 * The arguments to the ctlinput routine are
 *	(*protosw[].pr_ctlinput)(cmd, sa, arg);
 * where cmd is one of the commands below, sa is a pointer to a sockaddr,
 * and arg is an optional caddr_t argument used within a protocol family.
 */
#define	PRC_IFDOWN		0	/* interface transition */
#define	PRC_ROUTEDEAD		1	/* select new route if possible ??? */
#define	PRC_QUENCH2		3	/* DEC congestion bit says slow down */
#define	PRC_QUENCH		4	/* some one said to slow down */
#define	PRC_MSGSIZE		5	/* message size forced drop */
#define	PRC_HOSTDEAD		6	/* host appears to be down */
#define	PRC_HOSTUNREACH		7	/* deprecated (use PRC_UNREACH_HOST) */
#define	PRC_UNREACH_NET		8	/* no route to network */
#define	PRC_UNREACH_HOST	9	/* no route to host */
#define	PRC_UNREACH_PROTOCOL	10	/* dst says bad protocol */
#define	PRC_UNREACH_PORT	11	/* bad port # */
/* was	PRC_UNREACH_NEEDFRAG	12	   (use PRC_MSGSIZE) */
#define	PRC_UNREACH_SRCFAIL	13	/* source route failed */
#define	PRC_REDIRECT_NET	14	/* net routing redirect */
#define	PRC_REDIRECT_HOST	15	/* host routing redirect */
#define	PRC_REDIRECT_TOSNET	16	/* redirect for type of service & net */
#define	PRC_REDIRECT_TOSHOST	17	/* redirect for tos & host */
#define	PRC_TIMXCEED_INTRANS	18	/* packet lifetime expired in transit */
#define	PRC_TIMXCEED_REASS	19	/* lifetime expired on reass q */
#define	PRC_PARAMPROB		20	/* header incorrect */

#define	PRC_NCMDS		21

/*
 * The arguments to ctloutput are:
 *	(*protosw[].pr_ctloutput)(req, so, level, optname, optval);
 * req is one of the actions listed below, so is a (struct socket *),
 * level is an indication of which protocol layer the option is intended.
 * optname is a protocol dependent socket option request,
 * optval is a pointer to a mbuf-chain pointer, for value-return results.
 * The protocol is responsible for disposal of the mbuf chain *optval
 * if supplied,
 * the caller is responsible for any space held by *optval, when returned.
 * A non-zero return from usrreq gives an
 * UNIX error number which should be passed to higher level software.
 */
#define	PRCO_GETOPT	0
#define	PRCO_SETOPT	1

#define	PRCO_NCMDS	2

#ifdef PRCOREQUESTS
char	*prcorequests[] = {
	"GETOPT", "SETOPT",
};
#endif
#ifdef KERNEL
struct sockaddr;
void    pfctlinput(int, struct sockaddr *);
struct protosw *pffindproto __P((int family, int protocol, int type));
struct protosw *pffindtype __P((int family, int type));
#endif
#endif /* YATS_SYS_PROTOSW_H_ */
