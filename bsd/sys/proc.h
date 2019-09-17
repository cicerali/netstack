/*
 * proc.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_PROC_H_
#define BSD_SYS_PROC_H_

/*
 * Description of a process.
 */

struct  proc {
    struct  filedesc *p_fd;         /* Ptr to open files structure. */
};

#endif /* BSD_SYS_PROC_H_ */
