/*
 * tcp_debug.h
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */

#ifndef YATS_TCP_DEBUG_H_
#define YATS_TCP_DEBUG_H_

struct	tcp_debug {
	n_time	td_time;
	short	td_act;
	short	td_ostate;
	caddr_t	td_tcb;
	struct	tcpiphdr td_ti;
	short	td_req;
	struct	tcpcb td_cb;
};

#define	TA_INPUT 	0
#define	TA_OUTPUT	1
#define	TA_USER		2
#define	TA_RESPOND	3
#define	TA_DROP		4

#ifdef TANAMES
static const char	*tanames[] =
    { "input", "output", "user", "respond", "drop" };
#endif

#define	TCP_NDEBUG 100
struct	tcp_debug tcp_debug[TCP_NDEBUG];
int	tcp_debx;

#endif /* YATS_TCP_DEBUG_H_ */
