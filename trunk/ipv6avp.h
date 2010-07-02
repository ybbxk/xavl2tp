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
 * Attribute Value Pair structures and
 * definitions
 */
#ifndef _IPV6AVP_H_
#define _IPV6AVP_H_

#include "common.h"

//struct avp_hdr
//{
//    _u16 length;
//    _u16 vendorid;
//    _u16 attr;
//} __attribute__((packed));

struct avp6
{
    int num;                    /* Number of AVP */
    int m;                      /* Set M? */
    int (*handler) (struct tunnel6 *, struct call6 *, void *, int);
    /* This should handle the AVP
       taking a tunnel6, call6, the data,
       and the length of the AVP as
       parameters.  Should return 0
       upon success */
    char *description;          /* A name, for debugging */
};

extern int handle_avps6 (struct buffer6 *buf, struct tunnel6 *t, struct call6 *c);

extern char *msgtypes[];

#define VENDOR_ID 0             /* We don't have any extensions
                                   so we shoouldn't have to
                                   worry about this */

extern void encrypt_avp6 (struct buffer6 *, _u16, struct tunnel6 *);
extern int decrypt_avp6 (char *, struct tunnel6 *);
extern int message_type_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int protocol_version_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int framing_caps_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int bearer_caps_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int firmware_rev_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int hostname_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int vendor_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int assigned_tunnel_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int receive_window_size_avp6 (struct tunnel6 *, struct call6 *, void *,
                                    int);
extern int result_code_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int assigned_call_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int call_serno_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int bearer_type_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int call_physchan_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int dialed_number_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int dialing_number_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int sub_address_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int frame_type_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int rx_speed_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int tx_speed_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int packet_delay_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int ignore_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int seq_reqd_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int challenge_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int chalresp_avp6 (struct tunnel6 *, struct call6 *, void *, int);
extern int rand_vector_avp6 (struct tunnel6 *, struct call6 *, void *, int);

extern int add_challenge_avp6 (struct buffer6 *, unsigned char *, int);
extern int add_avp_rws6 (struct buffer6 *, _u16);
extern int add_tunnelid_avp6 (struct buffer6 *, _u16);
extern int add_vendor_avp6 (struct buffer6 *);
extern int add_hostname_avp6 (struct buffer6 *, const char *);
extern int add_firmware_avp6 (struct buffer6 *);
extern int add_bearer_caps_avp6 (struct buffer6 *buf, _u16 caps);
extern int add_frame_caps_avp6 (struct buffer6 *buf, _u16 caps);
extern int add_protocol_avp6 (struct buffer6 *buf);
extern int add_message_type_avp6 (struct buffer6 *buf, _u16 type);
extern int add_result_code_avp6 (struct buffer6 *buf, _u16, _u16, char *, int);
extern int add_bearer_avp6 (struct buffer6 *, int);
extern int add_frame_avp6 (struct buffer6 *, int);
extern int add_rxspeed_avp6 (struct buffer6 *, int);
extern int add_txspeed_avp6 (struct buffer6 *, int);
extern int add_serno_avp6 (struct buffer6 *, unsigned int);
#ifdef TEST_HIDDEN
extern int add_callid_avp6 (struct buffer6 *, _u16, struct tunnel6 *);
#else
extern int add_callid_avp6 (struct buffer6 *, _u16);
#endif
extern int add_ppd_avp6 (struct buffer6 *, _u16);
extern int add_seqreqd_avp6 (struct buffer6 *);
extern int add_chalresp_avp6 (struct buffer6 *, unsigned char *, int);
extern int add_randvect_avp6 (struct buffer6 *, unsigned char *, int);
extern int add_minbps_avp6 (struct buffer6 *buf, int speed);      /* jz: needed for outgoing call */
extern int add_maxbps_avp6 (struct buffer6 *buf, int speed);      /* jz: needed for outgoing call */
extern int add_number_avp6 (struct buffer6 *buf, char *no);       /* jz: needed for outgoing call */

#endif
