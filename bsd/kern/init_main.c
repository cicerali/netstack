/*
 * init_main.c
 *
 *  Created on: Sep 10, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include "sys/filedesc.h"
#include "sys/proc.h"

void	ifinit __P((void));
void	domaininit __P((void));

/* Components of the first process -- never freed. */
struct	proc proc0;
struct	filedesc0 filedesc0;

int bsd_init() {
		struct proc *p;
		struct filedesc0 *fdp;


		p = &proc0;

		/* Create the file descriptor table. */
		fdp = &filedesc0;
		p->p_fd = &fdp->fd_fd;
		fdp->fd_fd.fd_ofiles = fdp->fd_dfiles;
		fdp->fd_fd.fd_ofileflags = fdp->fd_dfileflags;
		fdp->fd_fd.fd_nfiles = NDFILE;

		/* Initialize protocols. */
		// TODO first all dpdk port should be attached
		ifinit();
		domaininit();
}
