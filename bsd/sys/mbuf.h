/*
 * mbuf_compat.h
 *
 *  Created on: Aug 16, 2019
 *      Author: cicerali
 */

#ifndef YATS_MBUF_COMPAT_H_
#define YATS_MBUF_COMPAT_H_

#ifndef M_WAITOK
#include <sys/malloc.h>
#endif


#include "rte_mbuf.h"

#define MCLSHIFT        12              /* convert bytes to mbuf clusters */
#define MCLBYTES        (1 << MCLSHIFT) /* size of an mbuf cluster */
#define MSIZE           1024             /* size of an mbuf */
#define MLEN            (MSIZE - sizeof(struct m_hdr))  /* normal data len */
#define MHLEN           (MLEN - sizeof(struct pkthdr))  /* data len w/pkthdr */

#define	MINCLSIZE	(MHLEN + MLEN)	/* smallest amount to put in cluster */

/*
 * Macros for type conversion
 * mtod(m,t) -	convert mbuf pointer to data pointer of correct type
 * dtom(x) -	convert data pointer within mbuf to mbuf pointer (XXX)
 * mtocl(x) -	convert pointer within cluster to cluster index #
 * cltom(x) -	convert cluster # to ptr to beginning of cluster
 */
#define	mtod(m,t)	((t)((m)->m_data))
#define	dtom(x)		((struct mbuf *)((long)(x) & ~(MSIZE-1))) // TODO


/* header at beginning of each mbuf: */
struct m_hdr {
	struct	mbuf *mh_next;		/* next buffer in chain */
	struct	mbuf *mh_nextpkt;	/* next chain in queue/record */
	caddr_t	mh_data;		/* location of data */
	int	mh_len;			/* amount of data in this mbuf */
	short	mh_type;		/* type of data in this mbuf */
	short	mh_flags;		/* flags; see below */
};

/* record/packet header in first mbuf of chain; valid if M_PKTHDR set */
struct	pkthdr {
	struct	ifnet *rcvif;		/* rcv interface */
	int	len;			/* total packet length */
	/* variables for ip and tcp reassembly */
	caddr_t header;                 /* pointer to packet header */
};

/* description of external storage mapped into mbuf, valid if M_EXT set */
struct m_ext {
	caddr_t	ext_buf;		/* start of buffer */
	void	(*ext_free)();		/* free routine if not the usual */
	u_int	ext_size;		/* size of buffer, for ext_free */
};

struct mbuf {
	struct	m_hdr m_hdr;
	union {
		struct {
			struct	pkthdr MH_pkthdr;	/* M_PKTHDR set */
			union {
				struct	m_ext MH_ext;	/* M_EXT set */
				char	*MH_databuf;
			} MH_dat;
		} MH;
		char	*M_databuf;		/* !M_PKTHDR, !M_EXT */
	} M_dat;
};
#define	m_next		m_hdr.mh_next
#define	m_len		m_hdr.mh_len
#define	m_data		m_hdr.mh_data
#define	m_type		m_hdr.mh_type
#define	m_flags		m_hdr.mh_flags
#define	m_nextpkt	m_hdr.mh_nextpkt
#define	m_act		m_nextpkt
#define	m_pkthdr	M_dat.MH.MH_pkthdr
#define	m_ext		M_dat.MH.MH_dat.MH_ext
#define	m_pktdat	M_dat.MH.MH_dat.MH_databuf
#define	m_dat		M_dat.M_databuf


/* mbuf flags */
#define	M_EXT		0x0001	/* has associated external storage */
#define	M_PKTHDR	0x0002	/* start of record */
#define	M_EOR		0x0004	/* end of record */

/* mbuf pkthdr flags, also in m_flags */
#define	M_BCAST		0x0100	/* send/received as link-level broadcast */
#define	M_MCAST		0x0200	/* send/received as link-level multicast */

/* flags copied when copying m_pkthdr */
#define	M_COPYFLAGS	(M_PKTHDR|M_EOR|M_BCAST|M_MCAST)

/* mbuf types */
#define	MT_FREE		0	/* should be on free list */
#define	MT_DATA		1	/* dynamic (data) allocation */
#define	MT_HEADER	2	/* packet header */
#define	MT_SOCKET	3	/* socket structure */
#define	MT_PCB		4	/* protocol control block */
#define	MT_RTABLE	5	/* routing tables */
#define	MT_HTABLE	6	/* IMP host tables */
#define	MT_ATABLE	7	/* address resolution tables */
#define	MT_SONAME	8	/* socket name */
#define	MT_SOOPTS	10	/* socket options */
#define	MT_FTABLE	11	/* fragment reassembly header */
#define	MT_RIGHTS	12	/* access rights */
#define	MT_IFADDR	13	/* interface address */
#define MT_CONTROL	14	/* extra-data protocol message */
#define MT_OOBDATA	15	/* expedited data  */

/* flags to m_get/MGET */
#define	M_DONTWAIT	0x0001
#define	M_WAIT		0x0000

/*
 * DPDK compatibility
 * TODO need a wrapper for mbuf<-->rte_mbuf
 */
extern struct rte_mempool *socket_pool[RTE_MAX_NUMA_NODES];
#define SOCKET_POOL socket_pool[rte_socket_id()]
static inline void * mbuf_to_priv(struct rte_mbuf *m) {
	return RTE_PTR_ADD(m, sizeof(struct rte_mbuf));
}
static inline struct mbuf * rtom(struct rte_mbuf *rm) {
		struct mbuf *m = (struct mbuf *)mbuf_to_priv(rm);
		(m)->m_dat = rte_pktmbuf_mtod(rm, char *);
		(m)->m_type = MT_HEADER;
		(m)->m_next = (struct mbuf *)NULL;
		(m)->m_nextpkt = (struct mbuf *)NULL;
		(m)->m_data = (m)->m_dat;
		(m)->m_flags = 0;
		return m;
}


/*
 * mbuf allocation/deallocation macros:
 *
 *	MGET(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain internal data.
 *
 *	MGETHDR(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain a packet header
 * and internal data.
 */
#define	MGET(m, how, type) { \
	struct rte_mbuf *rm = (struct rte_mbuf *)rte_pktmbuf_alloc(SOCKET_POOL); \
	m = NULL; \
	if (rm) { \
		m = (struct mbuf *)(rm->userdata); \
		(m)->m_dat = rte_pktmbuf_mtod(rm, char *); \
		(m)->m_type = (type); \
		(m)->m_next = (struct mbuf *)NULL; \
		(m)->m_nextpkt = (struct mbuf *)NULL; \
		(m)->m_data = (m)->m_dat; \
		(m)->m_flags = 0; \
	} \
}

#define	MGETHDR(m, how, type) { \
	struct rte_mbuf *rm = (struct rte_mbuf *)rte_pktmbuf_alloc(SOCKET_POOL); \
	m = NULL; \
	if (rm) { \
		m = (struct mbuf *)(rm->userdata); \
		(m)->m_pktdat = rte_pktmbuf_mtod(rm, char *); \
		(m)->m_type = (type); \
		(m)->m_next = (struct mbuf *)NULL; \
		(m)->m_nextpkt = (struct mbuf *)NULL; \
		(m)->m_data = (m)->m_pktdat; \
		(m)->m_flags = M_PKTHDR; \
	} \
}

#define MFREE(m, nn) \
        { \
          (nn) = (m)->m_next; \
          rte_pktmbuf_free((struct rte_mbuf *)m); \
        }

/*
 * Copy mbuf pkthdr from from to to.
 * from must have M_PKTHDR set, and to must be empty.
 */
#define	M_COPY_PKTHDR(to, from) { \
	(to)->m_flags = (from)->m_flags & M_COPYFLAGS; \
	(to)->m_data = (to)->m_data; \
}

/*
 * Set the m_data pointer of a newly-allocated mbuf (m_get/MGET) to place
 * an object of the specified size at the end of the mbuf, longword aligned.
 */
#define	M_ALIGN(m, len) \
	{ (m)->m_data += (MLEN - (len)) &~ (sizeof(long) - 1); }
/*
 * As above, for mbufs allocated with m_gethdr/MGETHDR
 * or initialized by M_COPY_PKTHDR.
 */
#define	MH_ALIGN(m, len) \
	{ (m)->m_data += (MHLEN - (len)) &~ (sizeof(long) - 1); }

/*
 * Compute the amount of space available
 * before the current start of data in an mbuf.
 */
#define	M_LEADINGSPACE(m) \
	((m)->m_flags & M_EXT ? /* (m)->m_data - (m)->m_ext.ext_buf */ 0 : \
	    (m)->m_flags & M_PKTHDR ? (m)->m_data - (m)->m_pktdat : \
	    (m)->m_data - (m)->m_dat)

/*
 * Compute the amount of space available
 * after the end of data in an mbuf.
 */
#define	M_TRAILINGSPACE(m) \
	((m)->m_flags & M_EXT ? (m)->m_ext.ext_buf + (m)->m_ext.ext_size - \
	    ((m)->m_data + (m)->m_len) : \
	    &(m)->m_dat[MLEN] - ((m)->m_data + (m)->m_len))

/*
 * Arrange to prepend space of size plen to mbuf m.
 * If a new mbuf must be allocated, how specifies whether to wait.
 * If how is M_DONTWAIT and allocation fails, the original mbuf chain
 * is freed and m is set to NULL.
 */
#define	M_PREPEND(m, plen, how) { \
	if (M_LEADINGSPACE(m) >= (plen)) { \
		(m)->m_data -= (plen); \
		(m)->m_len += (plen); \
	} else \
		(m) = m_prepend((m), (plen), (how)); \
	if ((m) && (m)->m_flags & M_PKTHDR) \
		(m)->m_pkthdr.len += (plen); \
}

/* change mbuf to new type */
#define MCHTYPE(m, t) { \
	MBUFLOCK(mbstat.m_mtypes[(m)->m_type]--; mbstat.m_mtypes[t]++;) \
	(m)->m_type = t;\
}

/* length to m_copy to copy all */
#define	M_COPYALL	1000000000

/* compatiblity with 4.3 */
#define  m_copy(m, o, l)	m_copym((m), (o), (l), M_DONTWAIT)


#ifdef	KERNEL
int	max_linkhdr;			/* largest link-level header */
int	max_protohdr;			/* largest protocol header */
int	max_hdr;			/* largest link+protocol header */
int	max_datalen;			/* MHLEN - max_hdr */

void m_copydata(struct mbuf *m, int off, int len, caddr_t cp);
struct	mbuf *m_copym __P((struct mbuf *, int, int, int));
struct	mbuf *m_free __P((struct mbuf *));
struct	mbuf *m_get __P((int, int));
struct	mbuf *m_getclr __P((int, int));
struct	mbuf *m_gethdr __P((int, int));
struct	mbuf *m_prepend __P((struct mbuf *, int, int));
void	m_adj __P((struct mbuf *, int));
void	m_copyback __P((struct mbuf *, int, int, caddr_t));
void	m_freem __P((struct mbuf *));
#endif

#endif /* YATS_MBUF_COMPAT_H_ */
