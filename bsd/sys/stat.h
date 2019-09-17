/*
 * stat.h
 *
 *  Created on: Aug 27, 2019
 *      Author: cicerali
 */

#ifndef YATS_SYS_STAT_H_
#define YATS_SYS_STAT_H_

struct stat {
	mode_t    st_mode;              /* inode protection mode */
	u_int32_t st_blksize;		/* optimal blocksize for I/O */
};

#ifndef _POSIX_SOURCE
#define	S_IFSOCK 0140000		/* socket */
#endif

#endif /* YATS_SYS_STAT_H_ */
