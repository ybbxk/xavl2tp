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
 * Misc stuff...
 */

#ifndef _IPV6MISC_H
#define _IPV6MISC_H

#include <syslog.h>
//RY: starts here
struct tunnel6;
struct buffer6
{
    int type;
    void *rstart;
    void *rend;
    void *start;
    int len;
    int maxlen;
#if 0
    unsigned int addr;	//RY: will not work for IPv6
    int port;
#else
    struct sockaddr_in6 peer;
#endif
    struct tunnel6 *tunnel;      /* Who owns this packet, if it's a control */
    int retries;                /* Again, if a control packet, how many retries? */
};
//RY: ends here

#define DEBUG c ? c->debug || t->debug : t->debug

#ifdef USE_SWAPS_INSTEAD
#define SWAPS(a) ((((a) & 0xFF) << 8 ) | (((a) >> 8) & 0xFF))
#ifdef htons
#undef htons
#endif
#ifdef ntohs
#undef htons
#endif
#define htons(a) SWAPS(a)
#define ntohs(a) SWAPS(a)
#endif

#define halt() printf("Halted.\n") ; for(;;)

extern char hostname[];
//extern void l2tp_log (int level, const char *fmt, ...);
extern struct buffer6 *new_buf6 (int);
//extern void udppush_handler (int);
extern int addfcs6 (struct buffer6 *buf);
//extern inline void swaps (void *, int);
extern void do_packet_dump6 (struct buffer6 *);
//extern void status (const char *fmt, ...);
//extern void status_handler (int signal);
//extern int getPtyMaster(char *, int);
//extern void do_control (void);
extern void recycle_buf6 (struct buffer6 *);
//extern void safe_copy (char *, char *, int);
//extern void opt_destroy (struct ppp_opts *);
//extern struct ppp_opts *add_opt (struct ppp_opts *, char *, ...);
#endif
