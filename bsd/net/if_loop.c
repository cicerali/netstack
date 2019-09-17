/*
 * if_loop.c
 *
 *  Created on: Aug 26, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include <sys/time.h>

#include "sys/systm.h"
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/socketvar.h"

#include "net/route.h"
#include "net/if.h"


struct	ifnet loif;

int
looutput(ifp, m, dst, rt)
	struct ifnet *ifp;
	register struct mbuf *m;
	struct sockaddr *dst;
	register struct rtentry *rt;
{
		return (0);
}
