/*
 * syscallargs.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_SYSCALLARGS_H_
#define BSD_SYS_SYSCALLARGS_H_

#define syscallarg(x)   union { x datum; register_t pad; }

struct recvmsg_args {
	syscallarg(int) s;
	syscallarg(struct msghdr *) msg;
	syscallarg(int) flags;
};

struct sendmsg_args {
	syscallarg(int) s;
	syscallarg(caddr_t) msg;
	syscallarg(int) flags;
};

struct recvfrom_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(size_t) len;
	syscallarg(int) flags;
	syscallarg(caddr_t) from;
	syscallarg(int *) fromlenaddr;
};

struct accept_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int *) anamelen;
};

struct getpeername_args {
	syscallarg(int) fdes;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct getsockname_args {
	syscallarg(int) fdes;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct socket_args {
        syscallarg(int) domain;
        syscallarg(int) type;
        syscallarg(int) protocol;
};

struct connect_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int) namelen;
};

struct bind_args {
        syscallarg(int) s;
        syscallarg(caddr_t) name;
        syscallarg(int) namelen;
};

struct setsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(caddr_t) val;
	syscallarg(int) valsize;
};

struct listen_args {
	syscallarg(int) s;
	syscallarg(int) backlog;
};

struct getsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(caddr_t) val;
	syscallarg(int *) avalsize;
};

struct sendto_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(size_t) len;
	syscallarg(int) flags;
	syscallarg(caddr_t) to;
	syscallarg(int) tolen;
};

struct shutdown_args {
	syscallarg(int) s;
	syscallarg(int) how;
};

struct socketpair_args {
	syscallarg(int) domain;
	syscallarg(int) type;
	syscallarg(int) protocol;
	syscallarg(int *) rsv;
};

#endif /* BSD_SYS_SYSCALLARGS_H_ */
