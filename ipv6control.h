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
 * Control Packet Handling header
 *
 */

/* Declaration of FIFO used for maintaining
   a reliable control connection, as well
   as for queueing stuff for the individual
   threads */
#ifndef _IPV6CONTROL_H
#define _IPV6CONTROL_H
/* Control message types  for vendor-ID 0, placed in the VALUE
   field of AVP requests */

/* Control Connection Management */
#define SCCRQ 	1               /* Start-Control-Connection-Request */
#define SCCRP 	2               /* Start-Control-Connection-Reply */
#define SCCCN 	3               /* Start-Control-Connection-Connected */
#define StopCCN 4               /* Stop-Control-Connection-Notification */
/* 5 is reserved */
#define Hello	6               /* Hello */
/* Call Management */
#define OCRQ	7               /* Outgoing-Call-Request */
#define OCRP	8               /* Outgoing-Call-Reply */
#define OCCN	9               /* Outgoing-Call-Connected */
#define ICRQ	10              /* Incoming-Call-Request */
#define ICRP	11              /* Incoming-Call-Reply */
#define ICCN	12              /* Incoming-Call-Connected */
/* 13 is reserved */
#define CDN	14              /* Call-Disconnect-Notify */
/* Error Reporting */
#define WEN	15              /* WAN-Error-Notify */
/* PPP Sesssion Control */
#define SLI	16              /* Set-Link-Info */

#define MAX_MSG 16

#define TBIT 0x8000
#define LBIT 0x4000
#define RBIT 0x2000
#define FBIT 0x0800

extern int handle_packet6 (struct buffer6 *, struct tunnel6 *, struct call6 *);
extern struct buffer6 *new_outgoing6 (struct tunnel6 *);
extern void add_control_hdr6  (struct tunnel6 *t, struct call6 *c,
                             struct buffer6 *);
extern int control_finish6 (struct tunnel6 *t, struct call6 *c);
extern void control_zlb6 (struct buffer6 *, struct tunnel6 *, struct call6 *);
extern void recycle_outgoing6 (struct buffer6 *, struct sockaddr_in6);
extern void handle_special6 (struct buffer6 *, struct call6 *, _u16);
extern void hello6 (void *);
extern void send_zlb6 (void *);
extern void dethrottle6 (void *);

#endif
