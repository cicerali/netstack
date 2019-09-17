/*
 * in_systm.h
 *
 *  Created on: Aug 19, 2019
 *      Author: cicerali
 */

#ifndef YATS_IN_SYSTM_H_
#define YATS_IN_SYSTM_H_

/*
 * Miscellaneous internetwork
 * definitions for kernel.
 */

/*
 * Network types.
 *
 * Internally the system keeps counters in the headers with the bytes
 * swapped so that VAX instructions will work on them.  It reverses
 * the bytes before transmission at each protocol level.  The n_ types
 * represent the types with the bytes in ``high-ender'' order.
 */
typedef u_int16_t n_short;		/* short as received from the net */
typedef u_int32_t n_long;			/* long as received from the net */

typedef	u_int32_t n_time;			/* ms since 00:00 GMT, byte rev */

#ifdef KERNEL
n_time	 iptime __P((void));
#endif

#endif /* YATS_IN_SYSTM_H_ */
