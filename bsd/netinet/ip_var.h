/*
 * ip_var.h
 *
 *  Created on: Aug 15, 2019
 *      Author: cicerali
 */

#ifndef YATS_IP_VAR_H_
#define YATS_IP_VAR_H_

//#include "compat/mbuf_compat.h"

/*
 * Overlay for ip header used by other protocols (tcp, udp).
 */
struct ipovly {
	u_char  ih_x1[9];           /* (unused) */
	u_char	ih_pr;				/* protocol */
	short	ih_len;				/* protocol length */
	struct	in_addr ih_src;		/* source internet address */
	struct	in_addr ih_dst;		/* destination internet address */
};

/*
 * Ip reassembly queue structure.  Each fragment
 * being reassembled is attached to one of these structures.
 * They are timed out after ipq_ttl drops to 0, and may also
 * be reclaimed if memory becomes tight.
 */
struct ipq {
	struct	ipq *next,*prev;	/* to other reass headers */
	u_char	ipq_ttl;		/* time for reass q to live */
	u_char	ipq_p;			/* protocol of this fragment */
	u_short	ipq_id;			/* sequence id for reassembly */
	struct mbuf *ipq_frags;         /* to ip headers of fragments */
	struct	in_addr ipq_src,ipq_dst;
};

/*
 * Structure stored in mbuf in inpcb.ip_options
 * and passed to ip_output when ip options are in use.
 * The actual length of the options (including ipopt_dst)
 * is in m_len.
 */
#define MAX_IPOPTLEN	40

struct ipoption {
	struct	in_addr ipopt_dst;	/* first-hop dst if source routed */
	char	ipopt_list[MAX_IPOPTLEN];	/* options proper */
};

/*
 * Structure attached to inpcb.ip_moptions and
 * passed to ip_output when IP multicast options are in use.
 */
struct ip_moptions {
	struct	ifnet *imo_multicast_ifp; /* ifp for outgoing multicasts */
	u_char	imo_multicast_ttl;	/* TTL for outgoing multicasts */
	u_char	imo_multicast_loop;	/* 1 => hear sends if a member */
	u_short	imo_num_memberships;	/* no. memberships this socket */
	struct	in_multi *imo_membership[IP_MAX_MEMBERSHIPS];
};

struct	ipstat {
	u_long	ips_total;		/* total packets received */
	u_long	ips_badsum;		/* checksum bad */
	u_long	ips_tooshort;		/* packet too short */
	u_long	ips_toosmall;		/* not enough data */
	u_long	ips_badhlen;		/* ip header length < data size */
	u_long	ips_badlen;		/* ip length < ip header length */
	u_long	ips_fragments;		/* fragments received */
	u_long	ips_fragdropped;	/* frags dropped (dups, out of space) */
	u_long	ips_fragtimeout;	/* fragments timed out */
	u_long	ips_forward;		/* packets forwarded */
	u_long	ips_cantforward;	/* packets rcvd for unreachable dest */
	u_long	ips_redirectsent;	/* packets forwarded on same net */
	u_long	ips_noproto;		/* unknown or unsupported protocol */
	u_long	ips_delivered;		/* datagrams delivered to upper level*/
	u_long	ips_localout;		/* total ip packets generated here */
	u_long	ips_odropped;		/* lost packets due to nobufs, etc. */
	u_long	ips_reassembled;	/* total packets reassembled ok */
	u_long	ips_fragmented;		/* datagrams sucessfully fragmented */
	u_long	ips_ofragments;		/* output fragments created */
	u_long	ips_cantfrag;		/* don't fragment flag was set, etc. */
	u_long	ips_badoptions;		/* error in option processing */
	u_long	ips_noroute;		/* packets discarded due to no route */
	u_long	ips_badvers;		/* ip version != 4 */
	u_long	ips_rawout;		/* total raw ip packets generated */
};

#ifdef KERNEL
/* flags passed to ip_output as last parameter */
#define	IP_FORWARDING		0x1		/* most of ip header exists */
#define	IP_RAWOUTPUT		0x2		/* raw ip header exists */
#define	IP_ROUTETOIF		SO_DONTROUTE	/* bypass routing tables */
#define	IP_ALLOWBROADCAST	SO_BROADCAST	/* can send broadcast packets */

struct	ipstat	ipstat;
struct	ipq	ipq;			/* ip reass. queue */
u_short	ip_id;				/* ip packet ctr, for ids */
int	ip_defttl;			/* default IP ttl */
extern struct   pr_usrreqs rip_usrreqs;

int	 	in_control __P((struct socket *, u_long, caddr_t, struct ifnet *));
int	 	ip_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
int	 	ip_dooptions __P((struct mbuf *));
void	ip_drain __P((void));
void	ip_forward __P((struct mbuf *, int));
void	ip_freef __P((struct ipq *));
void	ip_freemoptions __P((struct ip_moptions *));
int	 	ip_getmoptions __P((int, struct ip_moptions *, struct mbuf **));
void	ip_init __P((void));
int	 	ip_optcopy __P((struct ip *, struct ip *));
int	 	ip_output __P((struct mbuf *,
	    	struct mbuf *, struct route *, int, struct ip_moptions *));
int	 	ip_pcbopts __P((struct mbuf **, struct mbuf *));
struct in_ifaddr *
	 	ip_rtaddr __P((struct in_addr));
int	 	ip_setmoptions __P((int, struct ip_moptions **, struct mbuf *));
void	ip_slowtimo __P((void));
struct mbuf *
	 	ip_srcroute __P((void));
void	ip_stripoptions __P((struct mbuf *, struct mbuf *));
int	 	rip_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
void	rip_init __P((void));
void	rip_input __P((struct mbuf *));
int	 	rip_output __P((struct mbuf *, struct socket *, u_long));
#endif

#endif /* YATS_IP_VAR_H_ */
