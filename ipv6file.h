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
 * File format handling header file
 *
 */

#ifndef _IPV6FILE_H
#define _IPV6FILE_H

#define STRLEN 80               /* Length of a string */

struct iprange6
{
	uint8_t start[16];
	uint8_t end[16];
    int sense;
    struct iprange6 *next;
};

#define CONTEXT_GLOBAL 	1
#define CONTEXT_LNS	   	2
#define CONTEXT_LAC		3
#define CONTEXT_DEFAULT	256

#define SENSE_ALLOW -1
#define SENSE_DENY 0

#ifndef DEFAULT_AUTH_FILE
//#define DEFAULT_AUTH_FILE "/etc/xl2tpd/l2tp-secrets"
#define DEFAULT_AUTH_FILE "/etc/xl2tpd/ppp.secrets"
#endif
#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "/etc/xl2tpd/xl2tpd.conf"
#endif
//#define ALT_DEFAULT_AUTH_FILE "/etc/l2tpd/l2tp-secrets"
#define ALT_DEFAULT_AUTH_FILE "/etc/xl2tpd/ppp.secrets"
//#define ALT_DEFAULT_CONFIG_FILE "/etc/l2tp/l2tpd.conf"
#define ALT_DEFAULT_CONFIG_FILE "/etc/xl2tp/xl2tpd.conf"
//#define DEFAULT_PID_FILE "/var/run/xl2tpd.pid"
#define DEFAULT_PID_FILE "/var/run/eth0.1.pid"
//RY: starts here
/* Definition of an LNS for IPv6 */
struct lns6
{
    struct lns6 *next;
    int exclusive;              /* Only one tunnel per host? */
    int active;                 /* Is this actively in use? */
    uint8_t localaddr[16];     /* Local IP for PPP connections */ //IPv6 address
    int tun_rws;                /* Receive window size (tunnel) */
    int call_rws;               /* Call rws */
    int hbit;                   /* Permit hidden AVP's? */
    int lbit;                   /* Use the length field? */
    int challenge;              /* Challenge authenticate the peer? */
    int authpeer;               /* Authenticate our peer? */
    int authself;               /* Authenticate ourselves? */
    char authname[STRLEN];      /* Who we authenticate as */
    char peername[STRLEN];      /* Force peer name to this */
    char hostname[STRLEN];      /* Hostname to report */
    char entname[STRLEN];       /* Name of this entry */
    struct iprange6 *lacs;       /* Hosts permitted to connect */
    struct iprange6 *range;      /* Range of IP's we provide */
    int assign_ip;              /* Do we actually provide IP addresses? */
    int passwdauth;             /* Authenticate by passwd file? (or PAM) */
    int pap_require;            /* Require PAP auth for PPP */
    int chap_require;           /* Require CHAP auth for PPP */
    int pap_refuse;             /* Refuse PAP authentication for us */
    int chap_refuse;            /* Refuse CHAP authentication for us */
    int idle;                   /* Idle timeout in seconds */
    unsigned int pridns;        /* Primary DNS server */
    unsigned int secdns;        /* Secondary DNS server */
    unsigned int priwins;       /* Primary WINS server */
    unsigned int secwins;       /* Secondary WINS server */
    int proxyarp;               /* Use proxy-arp? */
    int proxyauth;              /* Allow proxy authentication? */
    int debug;                  /* Debug PPP? */
    char pppoptfile[STRLEN];    /* File containing PPP options */
    struct tunnel6 *t;           /* Tunnel of this, if it's ready */
};
//RY: ends here

//RY: starts here
/*Definition of LAC for IPv6*/
struct lac6
{
    struct lac6 *next;
    struct host *lns;           /* LNS's we can connect to */
    struct schedule_entry *rsched;
    int tun_rws;                /* Receive window size (tunnel) */
    int call_rws;               /* Call rws */
    int active;                 /* Is this connection in active use? */
    int hbit;                   /* Permit hidden AVP's? */
    int lbit;                   /* Use the length field? */
    int challenge;              /* Challenge authenticate the peer? */
    uint8_t localaddr[16];     /* Local IP address */
    uint8_t remoteaddr[16];    /* Force remote address to this */
    char authname[STRLEN];      /* Who we authenticate as */
    char password[STRLEN];      /* Password to authenticate with */
    char peername[STRLEN];      /* Force peer name to this */
    char hostname[STRLEN];      /* Hostname to report */
    char entname[STRLEN];       /* Name of this entry */
    int authpeer;               /* Authenticate our peer? */
    int authself;               /* Authenticate ourselves? */
    int pap_require;            /* Require PAP auth for PPP */
    int chap_require;           /* Require CHAP auth for PPP */
    int pap_refuse;             /* Refuse PAP authentication for us */
    int chap_refuse;            /* Refuse CHAP authentication for us */
    int idle;                   /* Idle timeout in seconds */
    int autodial;               /* Try to dial immediately? */
    int defaultroute;           /* Use as default route? */
    int redial;                 /* Redial if disconnected */
    int rmax;                   /* Maximum # of consecutive redials */
    int rtries;                 /* # of tries so far */
    int rtimeout;               /* Redial every this many # of seconds */
    char pppoptfile[STRLEN];    /* File containing PPP options */
    int debug;
    struct tunnel6 *t;           /* Our tunnel */
    struct call6 *c;             /* Our call */
};
//RY: ends here

extern struct global gconfig;   /* Global configuration options */

//RY: start
extern struct lns6 *lnslist6;     /* All LNS entries */
extern struct lac6 *laclist6;     /* All LAC entries */
extern struct lns6 *deflns6;      /* Default LNS config */
extern struct lac6 *deflac6;      /* Default LAC config */
//RY: end
extern int init_config6 ();      /* Read in the config file */

int set_ip6 (char *word, char *value, uint8_t *addr);
#endif
