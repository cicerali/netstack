/*
 * udp_var.h
 *
 *  Created on: Sep 17, 2019
 *      Author: cicerali
 */

#ifndef BSD_NETINET_UDP_VAR_H_
#define BSD_NETINET_UDP_VAR_H_

/*
 * UDP kernel structures and variables.
 */
struct	udpiphdr {
	struct 	ipovly ui_i;		/* overlaid ip structure */
	struct	udphdr ui_u;		/* udp header */
};
#define	ui_x1		ui_i.ih_x1
#define	ui_pr		ui_i.ih_pr
#define	ui_len		ui_i.ih_len
#define	ui_src		ui_i.ih_src
#define	ui_dst		ui_i.ih_dst
#define	ui_sport	ui_u.uh_sport
#define	ui_dport	ui_u.uh_dport
#define	ui_ulen		ui_u.uh_ulen
#define	ui_sum		ui_u.uh_sum

struct	udpstat {
				/* input statistics: */
	u_long	udps_ipackets;		/* total input packets */
	u_long	udps_hdrops;		/* packet shorter than header */
	u_long	udps_badsum;		/* checksum error */
	u_long	udps_badlen;		/* data length larger than packet */
	u_long	udps_noport;		/* no socket on port */
	u_long	udps_noportbcast;	/* of above, arrived as broadcast */
	u_long	udps_fullsock;		/* not delivered, input socket full */
	u_long	udpps_pcbcachemiss;	/* input packets missing pcb cache */
				/* output statistics: */
	u_long	udps_opackets;		/* total output packets */
};

#ifdef KERNEL
extern struct   pr_usrreqs udp_usrreqs;
struct	inpcb udb;
struct	udpstat udpstat;

void	 udp_ctlinput __P((int, struct sockaddr *, struct ip *));
void	 udp_init __P((void));
void	 udp_input __P((struct mbuf *, int));
#endif
#endif /* BSD_NETINET_UDP_VAR_H_ */
