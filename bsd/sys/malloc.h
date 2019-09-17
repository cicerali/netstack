/*
 * malloc_compat.h
 *
 *  Created on: Aug 22, 2019
 *      Author: cicerali
 */

#ifndef YATS_COMPAT_MALLOC_COMPAT_H_
#define YATS_COMPAT_MALLOC_COMPAT_H_


/*
 * flags to malloc
 */
#define	M_WAITOK	0x0000
#define	M_NOWAIT	0x0001

/*
 * Types of memory to be allocated
 */
#define	M_SOCKET	3	/* socket structure */
#define	M_PCB		4	/* protocol control block */
#define	M_RTABLE	5	/* routing tables */
#define	M_IFADDR	9	/* interface address */
#define	M_FILEDESC	39	/* Open file descriptor table */
#define	M_IPMOPTS	53	/* internet multicast options */
#define	M_IPMADDR	54	/* internet multicast address */


#define M_malloc(size, type, flags) malloc((size_t)(size))
#define M_free(addr, type) free(addr)

#define	MALLOC(space, cast, size, type, flags) \
	(space) = (cast)malloc((size_t)(size))


#define FREE(addr, type) \
{ \
	free(addr); \
}


#endif /* YATS_COMPAT_MALLOC_COMPAT_H_ */
