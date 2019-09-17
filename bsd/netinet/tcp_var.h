/*
 * tcp_var.h
 *
 *  Created on: Aug 15, 2019
 *      Author: cicerali
 */

#ifndef YATS_TCP_VAR_H_
#define YATS_TCP_VAR_H_

//#include "compat/mbuf_compat.h"

/*
 * Tcp control block, one per tcp; fields:
 */
struct tcpcb {
    struct  mbuf *t_segq;
    int     t_dupacks;              /* consecutive dup acks recd */
    struct  tcpiphdr *t_template;   /* skeletal packet for transmit */

    int     t_timer[TCPT_NTIMERS];  /* tcp timers */

    struct  inpcb *t_inpcb;         /* back pointer to internet pcb */
    int     t_state;                /* state of this connection */
    u_int   t_flags;
#define TF_ACKNOW       0x00001         /* ack peer immediately */
#define TF_DELACK       0x00002         /* ack, but try to delay it */
#define TF_NODELAY      0x00004         /* don't delay packets to coalesce */
#define TF_NOOPT        0x00008         /* don't use tcp options */
#define TF_SENTFIN      0x00010         /* have sent FIN */
#define TF_REQ_SCALE    0x00020         /* have/will request window scaling */
#define TF_RCVD_SCALE   0x00040         /* other side has requested scaling */
#define TF_REQ_TSTMP    0x00080         /* have/will request timestamps */
#define TF_RCVD_TSTMP   0x00100         /* a timestamp was received in SYN */
#define TF_SACK_PERMIT  0x00200         /* other side said I could SACK */
#define TF_NEEDSYN      0x00400         /* send SYN (implicit state) */
#define TF_NEEDFIN      0x00800         /* send FIN (implicit state) */
#define TF_NOPUSH       0x01000         /* don't push */
#define TF_REQ_CC       0x02000         /* have/will request CC */
#define TF_RCVD_CC      0x04000         /* a CC was received in SYN */
#define TF_SENDCCNEW    0x08000         /* send CCnew instead of CC in SYN */
#define TF_MORETOCOME   0x10000         /* More data to be appended to sock */
    int     t_force;                /* 1 if forcing out a byte */

	tcp_seq	snd_una;				/* send unacknowledged */
	tcp_seq	snd_max;				/* highest sequence number sent;
					 	 	 	 	 * used to recognize retransmits
					 	 	 	 	 */
	tcp_seq	snd_nxt;				/* send next */
	tcp_seq	snd_up;					/* send urgent pointer */

	tcp_seq	snd_wl1;				/* window update seg seq number */
	tcp_seq	snd_wl2;				/* window update seg ack number */
	tcp_seq	iss;					/* initial send sequence number */
	tcp_seq	irs;					/* initial receive sequence number */

	tcp_seq	rcv_nxt;				/* receive next */
	tcp_seq	rcv_adv;				/* advertised window */
	u_long  rcv_wnd;                /* receive window */
	tcp_seq rcv_up;                 /* receive urgent pointer */

	u_long  snd_wnd;                /* send window */
	u_long	snd_cwnd;				/* congestion-controlled window */
	u_long	snd_ssthresh;			/* snd_cwnd size threshhold for
					 	 	 	 	 * for slow start exponential to
					 	 	 	 	 * linear switch
					 	 	 	 	 */
	u_int   t_maxopd;               /* mss plus options */

	u_int   t_idle;                 /* inactivity time */
	u_long  t_duration;             /* connection duration */
	int     t_rtt;                  /* round trip time */
	tcp_seq	t_rtseq;				/* sequence number being timed */

	int     t_rxtcur;               /* current retransmit value */
	u_int   t_maxseg;       		/* maximum segment size */
	int		t_srtt;					/* smoothed round-trip time */
	int		t_rttvar;				/* variance in round-trip time */

	int     t_rxtshift;     		/* log(2) of rexmt exp. backoff */
	u_int	t_rttmin;				/* minimum rtt allowed */
	u_long  t_rttupdated;           /* number of times rtt sampled */
	u_long	max_sndwnd;				/* largest window peer has offered */

	int		t_softerror;			/* possible error not yet reported */
/* out-of-band data */
	char	t_oobflags;				/* have some */
	char	t_iobc;					/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
/* RFC 1323 variables */
	u_char	snd_scale;				/* window scaling for send window */
	u_char	rcv_scale;				/* window scaling for recv window */
	u_char	request_r_scale;		/* pending window scaling */
	u_char	requested_s_scale;
	u_long	ts_recent;				/* timestamp echo data */
	u_long	ts_recent_age;			/* when last updated */
	tcp_seq	last_ack_sent;
/* RFC 1644 variables */
	tcp_cc  cc_send;           	 	/* send connection count */
	tcp_cc  cc_recv;            	/* receive connection count */
};

/*
 * Structure to hold TCP options that are only used during segment
 * processing (in tcp_input), but not held in the tcpcb.
 * It's basically used to reduce the number of parameters
 * to tcp_dooptions.
 */
struct tcpopt {
        u_long  to_flag;                /* which options are present */
#define TOF_TS          0x0001          /* timestamp */
#define TOF_CC          0x0002          /* CC and CCnew are exclusive */
#define TOF_CCNEW       0x0004
#define TOF_CCECHO      0x0008
        u_long  to_tsval;
        u_long  to_tsecr;
        tcp_cc  to_cc;          /* holds CC or CCnew */
        tcp_cc  to_ccecho;
};

/*
 * The TAO cache entry which is stored in the protocol family specific
 * portion of the route metrics.
 */
struct rmxp_tao {
        tcp_cc  tao_cc;                 /* latest CC in valid SYN */
        tcp_cc  tao_ccsent;             /* latest CC sent to peer */
        u_short tao_mssopt;             /* peer's cached MSS */
#ifdef notyet
        u_short tao_flags;              /* cache status flags */
#define TAOF_DONT       0x0001          /* peer doesn't understand rfc1644 */
#define TAOF_OK         0x0002          /* peer does understand rfc1644 */
#define TAOF_UNDEF      0               /* we don't know yet */
#endif /* notyet */
};
#define rmx_taop(r)     ((struct rmxp_tao *)(r).rmx_filler)

#define	intotcpcb(ip)	((struct tcpcb *)(ip)->inp_ppcb)
#define	sototcpcb(so)	(intotcpcb(sotoinpcb(so)))

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		8	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		3	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	4	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define	TCP_REXMTVAL(tp) \
	(((tp)->t_srtt >> TCP_RTT_SHIFT) + (tp)->t_rttvar)

/* XXX
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcpcb) are overlayed with an mbuf pointer.
 */
#define REASS_MBUF(ti) (*(struct mbuf **)&((ti)->ti_t))

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcpstat {
	u_long	tcps_connattempt;	/* connections initiated */
	u_long	tcps_accepts;		/* connections accepted */
	u_long	tcps_connects;		/* connections established */
	u_long	tcps_drops;		/* connections dropped */
	u_long	tcps_conndrops;		/* embryonic connections dropped */
	u_long	tcps_closed;		/* conn. closed (includes drops) */
	u_long	tcps_segstimed;		/* segs where we tried to get rtt */
	u_long	tcps_rttupdated;	/* times we succeeded */
	u_long	tcps_delack;		/* delayed acks sent */
	u_long	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	u_long	tcps_rexmttimeo;	/* retransmit timeouts */
	u_long	tcps_persisttimeo;	/* persist timeouts */
	u_long	tcps_keeptimeo;		/* keepalive timeouts */
	u_long	tcps_keepprobe;		/* keepalive probes sent */
	u_long	tcps_keepdrops;		/* connections dropped in keepalive */

	u_long	tcps_sndtotal;		/* total packets sent */
	u_long	tcps_sndpack;		/* data packets sent */
	u_long	tcps_sndbyte;		/* data bytes sent */
	u_long	tcps_sndrexmitpack;	/* data packets retransmitted */
	u_long	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	u_long	tcps_sndacks;		/* ack-only packets sent */
	u_long	tcps_sndprobe;		/* window probes sent */
	u_long	tcps_sndurg;		/* packets sent with URG only */
	u_long	tcps_sndwinup;		/* window update-only packets sent */
	u_long	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	u_long	tcps_rcvtotal;		/* total packets received */
	u_long	tcps_rcvpack;		/* packets received in sequence */
	u_long	tcps_rcvbyte;		/* bytes received in sequence */
	u_long	tcps_rcvbadsum;		/* packets received with ccksum errs */
	u_long	tcps_rcvbadoff;		/* packets received with bad offset */
	u_long	tcps_rcvshort;		/* packets received too short */
	u_long	tcps_rcvduppack;	/* duplicate-only packets received */
	u_long	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	u_long	tcps_rcvpartduppack;	/* packets with some duplicate data */
	u_long	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	u_long	tcps_rcvoopack;		/* out-of-order packets received */
	u_long	tcps_rcvoobyte;		/* out-of-order bytes received */
	u_long	tcps_rcvpackafterwin;	/* packets with data after window */
	u_long	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	u_long	tcps_rcvafterclose;	/* packets rcvd after "close" */
	u_long	tcps_rcvwinprobe;	/* rcvd window probe packets */
	u_long	tcps_rcvdupack;		/* rcvd duplicate acks */
	u_long	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	u_long	tcps_rcvackpack;	/* rcvd ack packets */
	u_long	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	u_long	tcps_rcvwinupd;		/* rcvd window update packets */
	u_long	tcps_pawsdrop;		/* segments dropped due to PAWS */
	u_long	tcps_predack;		/* times hdr predict ok for acks */
	u_long	tcps_preddat;		/* times hdr predict ok for data pkts */
	u_long	tcps_pcbcachemiss;
	u_long  tcps_cachedrtt;         /* times cached RTT in route updated */
	u_long  tcps_cachedrttvar;      /* times cached rttvar updated */
	u_long  tcps_cachedssthresh;    /* times cached ssthresh updated */
	u_long  tcps_usedrtt;           /* times RTT initialized from route */
	u_long  tcps_usedrttvar;        /* times RTTVAR initialized from rt */
	u_long  tcps_usedssthresh;      /* times ssthresh initialized from rt*/
	u_long	tcps_persistdrop;	/* timeout in persist state */
	u_long	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
	u_long  tcps_mturesent;         /* resends due to MTU discovery */
	u_long  tcps_listendrop;        /* listen queue overflows */
};

#ifdef KERNEL
struct	inpcb tcb;		/* head of queue of active tcpcb's */
struct	tcpstat tcpstat;	/* tcp statistics */
u_long	tcp_now;		/* for RFC 1323 timestamps */

int	 tcp_attach __P((struct socket *));
void	 tcp_canceltimers __P((struct tcpcb *));
struct tcpcb *
	 tcp_close __P((struct tcpcb *));
void	 tcp_ctlinput __P((int, struct sockaddr *, struct ip *));
int	 tcp_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
struct tcpcb *
	 tcp_disconnect __P((struct tcpcb *));
struct tcpcb *
	 tcp_drop __P((struct tcpcb *, int));
void	 tcp_drain __P((void));
void	 tcp_fasttimo __P((void));
void	 tcp_init __P((void));
void	 tcp_input __P((struct mbuf *, int));
int	 tcp_mss __P((struct tcpcb *, u_int));
struct tcpcb *
	 tcp_newtcpcb __P((struct inpcb *));
void	 tcp_notify __P((struct inpcb *, int));
int	 tcp_output __P((struct tcpcb *));
void	 tcp_pulloutofband __P((struct socket *,
	    struct tcpiphdr *, struct mbuf *));
void	 tcp_quench __P((struct inpcb *, int));
int	 tcp_reass __P((struct tcpcb *, struct tcpiphdr *, struct mbuf *));
void	 tcp_respond __P((struct tcpcb *,
	    struct tcpiphdr *, struct mbuf *, tcp_seq, tcp_seq, int));
void	 tcp_setpersist __P((struct tcpcb *));
void	 tcp_slowtimo __P((void));
struct tcpiphdr *
	 tcp_template __P((struct tcpcb *));
struct tcpcb *
	 tcp_timers __P((struct tcpcb *, int));
void	 tcp_trace __P((short, short, struct tcpcb *, struct tcpiphdr *, int));
struct tcpcb *
	 tcp_usrclosed __P((struct tcpcb *));
int	 tcp_usrreq __P((struct socket *,
	    int, struct mbuf *, struct mbuf *, struct mbuf *));
void	 tcp_xmit_timer __P((struct tcpcb *, short));
extern  struct pr_usrreqs tcp_usrreqs;
#endif
#endif /* YATS_TCP_VAR_H_ */
