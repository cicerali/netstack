/*
 * file.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_FILE_H_
#define BSD_SYS_FILE_H_

#include "sys/fcntl.h"

#include <sys/queue.h>

struct proc;
struct uio;

/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 */
struct file {
		LIST_ENTRY(file) f_list;/* list of active files */
		short   f_flag;         /* see fcntl.h */
#define DTYPE_VNODE     1       /* file */
#define DTYPE_SOCKET    2       /* communications endpoint */
    	short   f_type;         /* descriptor type */
    	short	f_count;	/* reference count */
        struct  fileops {
                int     (*fo_read)      __P((struct file *fp, struct uio *uio,
                                            struct ucred *cred));
                int     (*fo_write)     __P((struct file *fp, struct uio *uio,
                                            struct ucred *cred));
                int     (*fo_ioctl)     __P((struct file *fp, u_long com,
                                            caddr_t data, struct proc *p));
                int     (*fo_select)    __P((struct file *fp, int which,
                                            struct proc *p));
                int     (*fo_close)     __P((struct file *fp, struct proc *p));
        } *f_ops;

        caddr_t f_data;         /* vnode or socket */
};

LIST_HEAD(filelist, file);
extern struct filelist filehead;	/* head of list of open files */
extern int maxfiles;			/* kernel limit on number of open files */
extern int nfiles;			/* actual number of open files */

#endif /* BSD_SYS_FILE_H_ */
