/*
 * socket.h
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */

#ifndef YATS_SYS_SOCKET_H_
#define YATS_SYS_SOCKET_H_

/*
 * Definitions related to sockets: types, address families, options.
 */

/*
 * Types
 */
#define	SOCK_STREAM	1		/* stream socket */
#define	SOCK_DGRAM	2		/* datagram socket */
#define	SOCK_RAW	3		/* raw-protocol interface */
#define	SOCK_RDM	4		/* reliably-delivered message */
#define	SOCK_SEQPACKET	5		/* sequenced packet stream */

/*
 * Option flags per-socket.
 */
#define	SO_DEBUG	0x0001		/* turn on debugging info recording */
#define	SO_ACCEPTCONN	0x0002		/* socket has had listen() */
#define	SO_REUSEADDR	0x0004		/* allow local address reuse */
#define	SO_KEEPALIVE	0x0008		/* keep connections alive */
#define	SO_DONTROUTE	0x0010		/* just use interface addresses */
#define	SO_BROADCAST	0x0020		/* permit sending of broadcast msgs */
#define	SO_USELOOPBACK	0x0040		/* bypass hardware when possible */
#define	SO_LINGER	0x0080		/* linger on close if data present */
#define	SO_OOBINLINE	0x0100		/* leave received OOB data in line */
#define	SO_REUSEPORT	0x0200		/* allow local address & port reuse */

/*
 * Additional options, not kept in so_options.
 */
#define SO_SNDBUF	0x1001		/* send buffer size */
#define SO_RCVBUF	0x1002		/* receive buffer size */
#define SO_SNDLOWAT	0x1003		/* send low-water mark */
#define SO_RCVLOWAT	0x1004		/* receive low-water mark */
#define SO_SNDTIMEO	0x1005		/* send timeout */
#define SO_RCVTIMEO	0x1006		/* receive timeout */
#define	SO_ERROR	0x1007		/* get error status and clear */
#define	SO_TYPE		0x1008		/* get socket type */

/*
 * Structure used for manipulating linger option.
 */
struct	linger {
	int	l_onoff;		/* option on/off */
	int	l_linger;		/* linger time in seconds */
};

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	SOL_SOCKET	0xffff		/* options for socket level */

/*
 * Address families.
 */
#define	AF_UNSPEC	0		/* unspecified */
#define	AF_LOCAL	1		/* local to host (pipes, portals) */
#define	AF_UNIX		AF_LOCAL	/* backward compatibility */
#define	AF_INET		2		/* internetwork: UDP, TCP, etc. */
#define	AF_IMPLINK	3		/* arpanet imp addresses */
#define	AF_PUP		4		/* pup protocols: e.g. BSP */
#define	AF_CHAOS	5		/* mit CHAOS protocols */
#define	AF_NS		6		/* XEROX NS protocols */
#define	AF_ISO		7		/* ISO protocols */
#define	AF_OSI		AF_ISO
#define	AF_ECMA		8		/* european computer manufacturers */
#define	AF_DATAKIT	9		/* datakit protocols */
#define	AF_CCITT	10		/* CCITT protocols, X.25 etc */
#define	AF_SNA		11		/* IBM SNA */
#define AF_DECnet	12		/* DECnet */
#define AF_DLI		13		/* DEC Direct data link interface */
#define AF_LAT		14		/* LAT */
#define	AF_HYLINK	15		/* NSC Hyperchannel */
#define	AF_APPLETALK	16		/* Apple Talk */
#define	AF_ROUTE	17		/* Internal Routing Protocol */
#define	AF_LINK		18		/* Link layer interface */
#define	pseudo_AF_XTP	19		/* eXpress Transfer Protocol (no AF) */
#define	AF_COIP		20		/* connection-oriented IP, aka ST II */
#define	AF_CNT		21		/* Computer Network Technology */
#define pseudo_AF_RTIP	22		/* Help Identify RTIP packets */
#define	AF_IPX		23		/* Novell Internet Protocol */
#define	AF_SIP		24		/* Simple Internet Protocol */
#define pseudo_AF_PIP	25		/* Help Identify PIP packets */

#define	AF_MAX		26

/*
 * Structure used by kernel to store most
 * addresses.
 */
struct sockaddr {
	u_char	sa_len;			/* total length */
	u_char	sa_family;		/* address family */
	char	sa_data[14];		/* actually longer; address value */
};

/*
 * Structure used by kernel to pass protocol
 * information in raw sockets.
 */
struct sockproto {
	u_short	sp_family;		/* address family */
	u_short	sp_protocol;		/* protocol */
};

/*
 * Protocol families, same as address families for now.
 */
#define	PF_UNSPEC	AF_UNSPEC
#define	PF_LOCAL	AF_LOCAL
#define	PF_UNIX		PF_LOCAL	/* backward compatibility */
#define	PF_INET		AF_INET
#define	PF_IMPLINK	AF_IMPLINK
#define	PF_PUP		AF_PUP
#define	PF_CHAOS	AF_CHAOS
#define	PF_NS		AF_NS
#define	PF_ISO		AF_ISO
#define	PF_OSI		AF_ISO
#define	PF_ECMA		AF_ECMA
#define	PF_DATAKIT	AF_DATAKIT
#define	PF_CCITT	AF_CCITT
#define	PF_SNA		AF_SNA
#define PF_DECnet	AF_DECnet
#define PF_DLI		AF_DLI
#define PF_LAT		AF_LAT
#define	PF_HYLINK	AF_HYLINK
#define	PF_APPLETALK	AF_APPLETALK
#define	PF_ROUTE	AF_ROUTE
#define	PF_LINK		AF_LINK
#define	PF_XTP		pseudo_AF_XTP	/* really just proto family, no AF */
#define	PF_COIP		AF_COIP
#define	PF_CNT		AF_CNT
#define	PF_SIP		AF_SIP
#define	PF_IPX		AF_IPX		/* same format as AF_NS */
#define PF_RTIP		pseudo_AF_FTIP	/* same format as AF_INET */
#define PF_PIP		pseudo_AF_PIP

#define	PF_MAX		AF_MAX

/*
 * Maximum queue length specifiable by listen.
 */
#define	SOMAXCONN	5

/*
 * Message header for recvmsg and sendmsg calls.
 * Used value-result for recvmsg, value only for sendmsg.
 */
struct msghdr {
	caddr_t	msg_name;		/* optional address */
	u_int	msg_namelen;		/* size of address */
	struct	iovec *msg_iov;		/* scatter/gather array */
	u_int	msg_iovlen;		/* # elements in msg_iov */
	caddr_t	msg_control;		/* ancillary data, see below */
	u_int	msg_controllen;		/* ancillary data buffer len */
	int	msg_flags;		/* flags on received message */
};

#define	MSG_OOB		0x1		/* process out-of-band data */
#define	MSG_PEEK	0x2		/* peek at incoming message */
#define	MSG_DONTROUTE	0x4		/* send without using routing tables */
#define	MSG_EOR		0x8		/* data completes record */
#define	MSG_TRUNC	0x10		/* data discarded before delivery */
#define	MSG_CTRUNC	0x20		/* control data lost before delivery */
#define	MSG_WAITALL	0x40		/* wait for full request or error */
#define	MSG_DONTWAIT	0x80		/* this message should be nonblocking */
#define MSG_EOF         0x100           /* data completes connection */

/*
 * Header for ancillary data objects in msg_control buffer.
 * Used for additional information with/about a datagram
 * not expressible by flags.  The format is a sequence
 * of message elements headed by cmsghdr structures.
 */
struct cmsghdr {
	u_int	cmsg_len;		/* data byte count, including hdr */
	int	cmsg_level;		/* originating protocol */
	int	cmsg_type;		/* protocol-specific type */
/* followed by	u_char  cmsg_data[]; */
};

/* given pointer to struct cmsghdr, return pointer to data */
#define	CMSG_DATA(cmsg)		((u_char *)((cmsg) + 1))

/* "Socket"-level control message types: */
#define	SCM_RIGHTS	0x01		/* access rights (array of int) */

/*
* howto arguments for shutdown(2), specified by Posix.1g.
*/
#define SHUT_RD         0               /* shut down the reading side */
#define SHUT_WR         1               /* shut down the writing side */
#define SHUT_RDWR       2               /* shut down both sides */

#ifndef KERNEL

#include <sys/cdefs.h>

__BEGIN_DECLS
int     accept __P((int, struct sockaddr *, int *));
int     bind __P((int, const struct sockaddr *, int));
int     connect __P((int, const struct sockaddr *, int));
int     getpeername __P((int, struct sockaddr *, int *));
int     getsockname __P((int, struct sockaddr *, int *));
int     getsockopt __P((int, int, int, void *, int *));
int     listen __P((int, int));
ssize_t recv __P((int, void *, size_t, int));
ssize_t recvfrom __P((int, void *, size_t, int, struct sockaddr *, int *));
ssize_t recvmsg __P((int, struct msghdr *, int));
ssize_t send __P((int, const void *, size_t, int));
ssize_t sendto __P((int, const void *,
            size_t, int, const struct sockaddr *, int));
ssize_t sendmsg __P((int, const struct msghdr *, int));
int     setsockopt __P((int, int, int, const void *, int));
int     shutdown __P((int, int));
int     socket __P((int, int, int));
int     socketpair __P((int, int, int, int *));
__END_DECLS

#endif /* !KERNEL */

#endif /* YATS_SYS_SOCKET_H_ */
