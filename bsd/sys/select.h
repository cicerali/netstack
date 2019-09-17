/*
 * select.h
 *
 *  Created on: Aug 16, 2019
 *      Author: cicerali
 */

#ifndef YATS_SELECT_H_
#define YATS_SELECT_H_

/*
 * Used to maintain information about processes that wish to be
 * notified when I/O becomes possible.
 */
struct selinfo {
	pid_t	si_pid;		/* process to be notified */
	short	si_flags;	/* see below */
};

#endif /* YATS_SELECT_H_ */
