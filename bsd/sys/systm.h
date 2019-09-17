/*
 *  systm_compat.h
 *
 *  Created on: Aug 22, 2019
 *      Author: cicerali
 */

#ifndef YATS_COMPAT_SYSTM_COMPAT_H_
#define YATS_COMPAT__SYSTM_COMPAT_H_

#include <stdlib.h>
#include <time.h>
#include "rte_cycles.h"

void bcopy (const void *__src, void *__dest, size_t __n);
void bzero (void *__s, size_t __n);
int bcmp (const void *__s1, const void *__s2, size_t __n);
void	ovbcopy __P((const void *from, void *to, u_int len));

extern void *malloc (size_t __size);
void free (void *__ptr);

void insque(void *elem, void *prev);
void remque(void *elem);

static __inline int
imax(a, b)
        int a, b;
{
        return (a > b ? a : b);
}
static __inline int
imin(a, b)
        int a, b;
{
        return (a < b ? a : b);
}
static __inline long
lmax(a, b)
        long a, b;
{
        return (a > b ? a : b);
}
static __inline long
lmin(a, b)
        long a, b;
{
        return (a < b ? a : b);
}
static __inline u_int
max(a, b)
        u_int a, b;
{
        return (a > b ? a : b);
}
static __inline u_int
min(a, b)
        u_int a, b;
{
        return (a < b ? a : b);
}
static __inline u_long
ulmax(a, b)
        u_long a, b;
{
        return (a > b ? a : b);
}
static __inline u_long
ulmin(a, b)
        u_long a, b;
{
        return (a < b ? a : b);
}

int	copyin __P((void *udaddr, void *kaddr, u_int len));
int	copyout __P((void *kaddr, void *udaddr, u_int len));

#include <sys/time.h>
#define hz rte_get_timer_hz()
#define	tick (1000000 / hz)	/* usec per tick (1000000 / hz) */

void    timeout __P((void (*func)(void *), void *arg, int ticks));

#define tsleep(a, b, c, d) Tsleep(d)
static int	Tsleep(int timo)
{
rte_delay_ms(timo*1000);
return 0;
}

static inline void panic(const char *fmt, ...) {
	exit(EXIT_FAILURE);
}

#define SCARG(p,k)      ((p)->k.datum)  /* get arg from args pointer */

#endif /* YATS_COMPAT_SYSTM_COMPAT_H_ */
