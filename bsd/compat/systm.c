/*
 * systm.c
 *
 *  Created on: Sep 6, 2019
 *      Author: cicerali
 */

#include "sys/param.h"
#include <string.h>

int
copyin(const void *uaddr, void *kaddr, size_t len)
{
    memcpy(kaddr, uaddr, len);
    return (0);
}

int
copyout(const void *kaddr, void *uaddr, size_t len)
{
    memcpy(uaddr, kaddr, len);
    return (0);
}
