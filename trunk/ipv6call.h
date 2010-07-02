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
 * Handle a call as a separate thread (header file)
 */

#ifndef _IPV6CALL_H
#define _IPV6CALL_H


#include <sys/time.h>
#include "misc.h"
#include "common.h"
#include "ipsecmast.h" //RY:
//RY: starts here
//#define CALL_CACHE_SIZE 256 //RY: Defined in call.h

struct call6
{
/*	int rbit;		Set the "R" bit on the next packet? */
    int lbit;                   /* Should we send length field? */
/*	int throttle;	Throttle the connection? */
    int seq_reqd;               /* Sequencing required? */
    int tx_pkts;                /* Transmitted packets */
    int rx_pkts;                /* Received packets */
    int tx_bytes;               /* transmitted bytes */
    int rx_bytes;               /* received bytes */
    struct schedule_entry *zlb_xmit6;
    /* Scheduled ZLB transmission */
/*	struct schedule_entry *dethrottle; */
    /* Scheduled dethrottling (overrun) */
/*	int timeout;	Has our timeout expired? If so, we'll go ahead
					 and transmit, full window or not, and set the
					 R-bit on this packet.  */
    int prx;                    /* What was the last packet we sent
                                   as an Nr? Used to manage payload ZLB's */
    int state;                  /* Current state */
    int frame;                  /* Framing being used */
    struct call6 *next;          /* Next call, for linking */
    int debug;
    int msgtype;                /* What kind of message are we
                                   working with right now? */

    int ourcid;                 /* Our call number */
    int cid;                    /* Their call number */
    int qcid;                   /* Quitting CID */
    int bearer;                 /* Bearer type of call */
    unsigned int serno;         /* Call serial number */
    uint8_t addr[16];          /* Address reserved for this call */
    int txspeed;                /* Transmit speed */
    int rxspeed;                /* Receive speed */
    int ppd;                    /* Packet processing delay (of peer) */
    int physchan;               /* Physical channel ID */
    char dialed[MAXSTRLEN];     /* Number dialed for call */
    char dialing[MAXSTRLEN];    /* Original caller ID */
    char subaddy[MAXSTRLEN];    /* Sub address */

    int needclose;              /* Do we need to close this call? */
    int closing;                /* Are we actually in the process of closing? */
    /*
       needclose            closing         state
       =========            =======         =====
       0                       0            Running
       1                       0            Send Closing notice
       1                       1            Waiting for closing notice
       0                       1            Closing ZLB received, actulaly close
     */
    struct tunnel6 *container;   /* Tunnel we belong to */
    int fd;                     /* File descriptor for pty */
    struct termios *oldptyconf;
    int die;
    int nego;                   /* Show negotiation? */
    int pppd;                   /* PID of pppd */
    int result;                 /* Result code */
    int error;                  /* Error code */
    int fbit;                   /* Use sequence numbers? */
    int ourfbit;                /* Do we want sequence numbers? */
/*	int ourrws;		Our RWS for the call */
    int cnu;                    /* Do we need to send updated Ns, Nr values? */
    int pnu;                    /* ditto for payload packet */
    char errormsg[MAXSTRLEN];   /* Error message */
/*	int rws;		Receive window size, or -1 for none */
    struct timeval lastsent;    /* When did we last send something? */
    _u16 data_seq_num;          /* Sequence for next payload packet */
    _u16 data_rec_seq_num;      /* Sequence for next received payload packet */
    _u16 closeSs;               /* What number was in Ns when we started to
                                   close? */
    int pLr;                    /* Last packet received by peer */
    struct lns6 *lns;            /* LNS that owns us */
    struct lac6 *lac;            /* LAC that owns us */
    char dial_no[128];          /* jz: dialing number for outgoing call */
};
//RY: ends here

//extern void push_handler (int);	//RY: no need to duplicate
void toss6 (struct buffer6 *);

struct call6 *get_call6 (int tunnel,int call, struct in6_addr addr,
			      int port, IPsecSAref_t refme, IPsecSAref_t refhim);

struct call6 *get_tunnel6 (int,  int);
extern void destroy_call6 (struct call6 *);
extern struct call6 *new_call6 (struct tunnel6 *);
extern void set_error6 (struct call6 *, int, const char *, ...);
//void *call_thread_init (void *); //RY: no need to duplicate
void call_close6 (struct call6 *);

#endif
