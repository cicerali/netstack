/*
 * fcntl.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_FCNTL_H_
#define BSD_SYS_FCNTL_H_

/*
 * Kernel encoding of open mode; separate read and write bits that are
 * independently testable: 1 greater than the above.
 *
 * XXX
 * FREAD and FWRITE are excluded from the #ifdef KERNEL so that TIOCFLUSH,
 * which was documented to use FREAD/FWRITE, continues to work.
 */
#ifndef _POSIX_SOURCE
#define FREAD           0x0001
#define FWRITE          0x0002
#endif


#endif /* BSD_SYS_FCNTL_H_ */
