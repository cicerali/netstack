/*
 * init.c
 *
 *  Created on: Sep 11, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/time.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/ioctl.h"

#include "net/route.h"
#include "net/if.h"

#include "netinet/in.h"
#include "netinet/in_var.h"

#include "rte_ethdev.h"
#include "rte_lcore.h"

#define NB_MBUF   8192
#define MBUF_CACHE_SIZE 32
/*
 * must be aligned to RTE_MBUF_PRIV_ALIGN(8)
 * sizof(struct mbuf) = 80 for 64 bit
 */
#define MBUF_PRIV_SIZE 80
struct rte_mempool *socket_pool[RTE_MAX_NUMA_NODES];
#define MAX_PORT 16
struct ifnet *ifnets[MAX_PORT];

int init_mem(void);

int init(int argc, char **argv)
{

	test_main();

}

int test_func(void *arg);

void start(void)
{
	unsigned lcore_id;
	rte_eal_mp_remote_launch(test_func, NULL, SKIP_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return;
	}
}

int port_attach(uint16_t port)
{
//	struct rte_eth_dev_info _dev_info;
//	struct rte_eth_dev_info *dev_info = &_dev_info;
//	rte_eth_dev_info_get(port, dev_info);

	struct ifnet *ifp = (struct ifnet*) malloc(sizeof(struct ifnet));
	char *if_name = (char *) malloc(IFNAMSIZ);
	sprintf(if_name, "%s", "dpdk");
	ifp->if_name = if_name;
	ifp->if_unit = port;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX;
	ifp->if_output = ether_output;

	if_attach(ifp);
	ifnets[port] = ifp;
	port_setaddr();
	if_up(ifp);

	return 0;
}

// TODO
int
port_setaddr()
{
    struct in_aliasreq req;
    bzero(&req, sizeof req);
    strcpy(req.ifra_name, "dpdk0");

    struct sockaddr_in sa;
    bzero(&sa, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = 0x0a0a0a0a;
    bcopy(&sa, &req.ifra_addr, sizeof(sa));

    sa.sin_addr.s_addr = 0xffffff00;
    bcopy(&sa, &req.ifra_mask, sizeof(sa));

    sa.sin_addr.s_addr = 0x0a0a0aff;
    bcopy(&sa, &req.ifra_broadaddr, sizeof(sa));

    struct socket *so = NULL;
    socreate(AF_INET, &so, SOCK_DGRAM, 0);
    int ret = ifioctl(so, SIOCAIFADDR, (caddr_t)&req, NULL);

    sofree(so);

    return ret;
}

int init_mem(void)
{
	char buf[PATH_MAX];
	struct rte_mempool *mp;
	int socket;
	unsigned lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
	{
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		socket = rte_lcore_to_socket_id(lcore_id);
		if (socket_pool[socket] == NULL)
		{
			printf("Creating mempool on socket %i\n", socket);
			snprintf(buf, sizeof(buf), "pool_%i", socket);
			mp = rte_pktmbuf_pool_create(buf, NB_MBUF, MBUF_CACHE_SIZE,
					MBUF_PRIV_SIZE,
					RTE_MBUF_DEFAULT_BUF_SIZE, socket);
			if (mp == NULL)
			{
				printf("Cannot create direct mempool\n");
				return -1;
			}
			socket_pool[socket] = mp;
		}
	}
	return 0;
}

