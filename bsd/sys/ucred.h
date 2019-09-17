/*
 * ucred.h
 *
 *  Created on: Sep 9, 2019
 *      Author: cicerali
 */

#ifndef BSD_SYS_UCRED_H_
#define BSD_SYS_UCRED_H_

/*
 * Credentials.
 */
struct ucred {
        u_short cr_ref;                 /* reference count */
        uid_t   cr_uid;                 /* effective user id */
        short   cr_ngroups;             /* number of groups */
        gid_t   cr_groups[NGROUPS];     /* groups */
};


#endif /* BSD_SYS_UCRED_H_ */
