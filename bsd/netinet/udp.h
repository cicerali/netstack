/*
 * udp.h
 *
 *  Created on: Sep 17, 2019
 *      Author: cicerali
 */

#ifndef BSD_NETINET_UDP_H_
#define BSD_NETINET_UDP_H_

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

#endif /* BSD_NETINET_UDP_H_ */
