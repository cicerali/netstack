/*
 * in_proto.c
 *
 *  Created on: Aug 27, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/time.h"
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/protosw.h"
#include "sys/domain.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/ip_var.h"
#include "netinet/in_pcb.h"
#include "netinet/tcp.h"
#include "netinet/tcp_timer.h"
#include "netinet/tcp_var.h"
#include "netinet/udp.h"
#include "netinet/udp_var.h"

/*
 * TCP/IP protocol family: IP, ICMP, UDP, TCP.
 */

extern	struct domain inetdomain;
static  struct pr_usrreqs nousrreqs;

struct protosw inetsw[] = {
{ 		.pr_type = 				0,
		.pr_domain = 			&inetdomain,
		.pr_protocol =          IPPROTO_IP,
		.pr_init = 				ip_init,
		.pr_slowtimo = 			ip_slowtimo,
		.pr_drain = 			ip_drain,
		.pr_usrreqs =   		&nousrreqs
},
{
        .pr_type =              SOCK_DGRAM,
        .pr_domain =            &inetdomain,
        .pr_protocol =          IPPROTO_UDP,
        .pr_flags =             PR_ATOMIC|PR_ADDR,
        .pr_input =             udp_input,
        .pr_ctlinput =          udp_ctlinput,
        .pr_ctloutput =         ip_ctloutput,
        .pr_init =              udp_init,
        .pr_usrreqs =           &udp_usrreqs
},
{ 		.pr_type = 				SOCK_STREAM,
		.pr_domain = 			&inetdomain,
		.pr_protocol = 			IPPROTO_TCP,
		.pr_flags = 			PR_CONNREQUIRED|PR_WANTRCVD,
		.pr_input = 			tcp_input,
		.pr_ctlinput = 			tcp_ctlinput,
		.pr_ctloutput = 		tcp_ctloutput,
		.pr_init = 				tcp_init,
		.pr_slowtimo = 			tcp_slowtimo,
		.pr_drain = 			tcp_drain,
		.pr_usrreqs =           &tcp_usrreqs
},
{
        .pr_type =              SOCK_RAW,
        .pr_domain =            &inetdomain,
        .pr_protocol =          IPPROTO_RAW,
        .pr_flags =             PR_ATOMIC|PR_ADDR,
        .pr_input =             rip_input,
        .pr_ctloutput =         rip_ctloutput,
        .pr_usrreqs =           &rip_usrreqs
},
};

struct domain inetdomain = {
		.dom_family =           AF_INET,
		.dom_name =             "internet",
		.dom_protosw =          inetsw,
		.dom_protoswNPROTOSW =  &inetsw[sizeof(inetsw)/sizeof(inetsw[0])],
		.dom_rtattach =         rn_inithead,
		.dom_rtoffset =         32,
		.dom_maxrtkey =         sizeof(struct sockaddr_in)
};
