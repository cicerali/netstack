/*
 * filedesc.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_FILEDESC_H_
#define BSD_SYS_FILEDESC_H_

#define NDFILE		20
#define NDEXTENT	50		/* 250 bytes in 256-byte alloc. */

struct filedesc {
        struct  file **fd_ofiles;       /* file structures for open files */
        char	*fd_ofileflags;			/* per-process open file flags */
        int     fd_nfiles;              /* number of open files allocated */
    	u_short	fd_lastfile;			/* high-water mark of fd_ofiles */
    	u_short	fd_freefile;			/* approx. next free file */
};

/*
 * Basic allocation of descriptors:
 * one of the above, plus arrays for NDFILE descriptors.
 */
struct filedesc0 {
	struct	filedesc fd_fd;
	/*
	 * These arrays are used when the number of open files is
	 * <= NDFILE, and are then pointed to by the pointers above.
	 */
	struct	file *fd_dfiles[NDFILE];
	char	fd_dfileflags[NDFILE];
};

/*
 * Storage required per open file descriptor.
 */
#define OFILESIZE (sizeof(struct file *) + sizeof(char))

#ifdef KERNEL
/*
 * Kernel global variables and routines.
 */
struct proc;
int	fdalloc __P((struct proc *p, int want, int *result));
int	falloc __P((struct proc *p, struct file **resultfp, int *resultfd));
void ffree __P((struct file *fp));
#endif

#endif /* BSD_SYS_FILEDESC_H_ */
