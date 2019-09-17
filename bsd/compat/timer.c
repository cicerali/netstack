/*
 * timer.c
 *
 *  Created on: Sep 1, 2019
 *      Author: cicerali
 */

#include "sys/param.h"

#include "rte_lcore.h"
#include "rte_timer.h"

#include "sys/systm.h"


/* Timeouts */
typedef void (timeout_t)(void *); /* actual timeout function type */
typedef timeout_t *timeout_func_t; /* a pointer to this type */

void timer_cb(struct rte_timer *tim, void *arg)
{
	((timeout_func_t)arg)(NULL);
}

void timeout(timeout_func_t ftn, void *arg, int ticks) {
	struct rte_timer timer;
	rte_timer_init(&timer);
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&timer, ticks, SINGLE, lcore_id, timer_cb, ftn);
}
