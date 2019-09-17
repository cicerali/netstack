/*
 * ip_mroute.h
 *
 *  Created on: Sep 17, 2019
 *      Author: cicerali
 */

#ifndef BSD_NETINET_IP_MROUTE_H_
#define BSD_NETINET_IP_MROUTE_H_

/*
 * Definitions for the kernel part of DVMRP,
 * a Distance-Vector Multicast Routing Protocol.
 * (See RFC-1075.)
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 *
 * MROUTING 1.0
 */


/*
 * DVMRP-specific setsockopt commands.
 */
#define	DVMRP_INIT	100
#define	DVMRP_DONE	101
#define	DVMRP_ADD_VIF	102
#define	DVMRP_DEL_VIF	103
#define	DVMRP_ADD_LGRP	104
#define	DVMRP_DEL_LGRP	105
#define	DVMRP_ADD_MRT	106
#define	DVMRP_DEL_MRT	107

#endif /* BSD_NETINET_IP_MROUTE_H_ */
