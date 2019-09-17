/*
 * test.c
 *
 *  Created on: Sep 12, 2019
 *      Author: cicerali
 */
#include "sys/param.h"
#include "sys/time.h"
#include <stdio.h>
#include <stdlib.h>
#include "sys/mbuf.h"
#include "sys/socket.h"
#include "sys/socketvar.h"

#include "netinet/in.h"
#include "net/route.h"
#include "net/if.h"
#include "net/if_arp.h"
#include "netinet/if_ether.h"


#include "rte_lcore.h"

#define MAX_PORT 16
extern struct ifnet *ifnets[MAX_PORT];

int test_func(void *arg)
{
	unsigned lcore_id = rte_lcore_id();
	printf("rte_lcore_id: %d\n", lcore_id);
	struct rte_mbuf *rm = rte_pktmbuf_alloc(SOCKET_POOL);
	char *data = "\x00\x30\x54\x00\x34\x56\x00\xe0\xed\x01\x6e\xbd\x08\x00\x45\x00" \
			"\x00\x30\x69\xac\x40\x00\x80\x06\x39\x8a\xc0\xa8\x01\x02\x93\xea" \
			"\x01\xfd\x0a\xa0\x00\x15\xaf\x9d\xc3\x0f\x00\x00\x00\x00\x70\x02" \
			"\x40\x00\x6e\x2b\x00\x00\x02\x04\x05\xb4\x01\x01\x04\x02";
	memcpy(rte_pktmbuf_mtod(rm, char *), data, 62);
	rm->port = 0;
	printf("priv->%d\n",rte_pktmbuf_priv_size(SOCKET_POOL));
	struct mbuf *m = rtom(rm);
	m->m_flags &= M_PKTHDR;
	struct ether_header *eh = mtod(m, struct ether_header *);
	eh->ether_type = ntohs(eh->ether_type);
	m_adj(m, sizeof(struct ether_header));
	ether_input(ifnets[rm->port], eh, m);

	return 0;
}

int test_main()
{
	struct test_ext {
		caddr_t	ext_buf;		/* start of buffer */
		void	(*ext_free)();		/* free routine if not the usual */
		u_int	ext_size;		/* size of buffer, for ext_free */
	};
	printf("Hello DPDK core!\n");
	printf("m_hdr->%d\n", sizeof(struct	m_hdr));
	printf("pkthdr->%d\n", sizeof(struct pkthdr));
	printf("m_ext->%d\n", sizeof(struct	test_ext));
	printf("mbuf->%d\n", sizeof(struct mbuf));
	printf("rte_mbuf->%d", sizeof(struct rte_mbuf));

	int argc = 3;
	char *argv[] =
	{ "nt_stack", "--no-huge", "-l 1-2", "--proc-type=primary"};

	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eal_init failed");
//	argc -= ret;
//	argv += ret;
	init_mem();
	domaininit();
	port_attach(0);
	start();

	return 0;
}
