/*
 * Layer Two Tunnelling Protocol Daemon
 * Copyright (C) 1998 Adtran, Inc.
 * Copyright (C) 2002 Jeff McAdams
 *
 * Mark Spencer
 *
 * This software is distributed under the terms
 * of the GPL, which you should have received
 * along with this source.
 *
 * Authorization, Accounting, and Access control
 *
 */

#ifndef _IPV6AAA_H
#define _IPV6AAA_H
#include "md5.h"

#define ADDR_HASH_SIZE 256
#define MD_SIG_SIZE 16
#define MAX_VECTOR_SIZE 1024
#define VECTOR_SIZE 16

#define STATE_NONE 		 0
#define STATE_CHALLENGED 1
#define STATE_COMPLETE	 2

struct addr_ent6	//TODO: change it for IPv6
{
	uint8_t addr[16];
    struct addr_ent *next;
};


//RY: start
extern struct lns6 *get_lns6 (struct tunnel6 *);
extern unsigned int get_addr6 (struct iprange6 *);
extern void reserve_addr6 (unsigned int);
extern void unreserve_addr6 (unsigned int);
//RY: end

extern void init_addr ();
extern int handle_challenge6 (struct tunnel6 *, struct challenge *);
//extern void mk_challenge (unsigned char *, int);//RY: use original
#endif
