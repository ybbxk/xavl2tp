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
 * File format handling
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "l2tp.h"

struct lns6 *lnslist6;
struct lac6 *laclist6;
struct lns6 *deflns6;
struct lac6 *deflac6;
//struct global gconfig;//TODO: use original global gconfig
char filerr[STRLEN];

int parse_config6 (FILE *);
struct keyword words6[];
//RY: start
//TODO: modified for INADDR_ANY: done

int init_config6 ()
{
    FILE *f;
    int returnedValue;
    gconfig.port = UDP_LISTEN_PORT;

    //TODO: need to change to in6addr_any as it is INADDR_ANY in ipv4
    // Default is to bind (listen) to all interfaces
    // Assigning zero to listenaddr6 (IN6ADDR_INIT_ANY)
  //  memset((void*) &gconfig.ipaddr.listenaddr6, 0, 16);
    gconfig.ipaddr.listenaddr6 = in6addr_any;
    gconfig.debug_avp = 0;
    gconfig.debug_network = 0;
    gconfig.packet_dump = 0;
    gconfig.debug_tunnel = 0;
    gconfig.debug_state = 0;
    lnslist6 = NULL;
    laclist6 = NULL;
    deflac6 = (struct lac6 *) malloc (sizeof (struct lac6));

    f = fopen (gconfig.configfile, "r");
    if (!f)
    {
        f = fopen (gconfig.altconfigfile, "r");
        if (f)
        {
	     l2tp_log (LOG_WARNING, "%s: Using old style config files %s and %s\n",
		__FUNCTION__, gconfig.altconfigfile, gconfig.altauthfile);
            strncpy (gconfig.authfile, gconfig.altauthfile,
            	sizeof (gconfig.authfile));
        }
        else
        {
            l2tp_log (LOG_CRIT, "%s: Unable to open config file %s or %s\n",
                 __FUNCTION__, gconfig.configfile, gconfig.altconfigfile);
            return -1;
        }

    }
    returnedValue = parse_config6 (f);
    fclose (f);
    return (returnedValue);
    filerr[0] = 0;
}


struct lns6 *new_lns6 ()
{
    struct lns6 *tmp;
    tmp = (struct lns6 *) malloc (sizeof (struct lns6));
    if (!tmp)
    {
        l2tp_log (LOG_CRIT, "%s: Unable to allocate memory for new lns6\n",
             __FUNCTION__);
        return NULL;
    }
    tmp->next = NULL;
    tmp->exclusive = 0;
    //tmp->localaddr = 0;
    memset((char*)tmp->localaddr,0,16);//RY:
    tmp->tun_rws = DEFAULT_RWS_SIZE;
    tmp->call_rws = DEFAULT_RWS_SIZE;
    tmp->hbit = 0;
    tmp->lbit = 0;
    tmp->authpeer = 0;
    tmp->authself = -1;
    tmp->authname[0] = 0;
    tmp->peername[0] = 0;
    tmp->hostname[0] = 0;
    tmp->entname[0] = 0;
    tmp->range = NULL;
    tmp->assign_ip = 1;                /* default to 'yes' */
    tmp->lacs = NULL;
    tmp->passwdauth = 0;
    tmp->pap_require = 0;
    tmp->pap_refuse = 0;
    tmp->chap_require = 0;
    tmp->chap_refuse = 0;
    tmp->idle = 0;
    tmp->pridns = 0;
    tmp->secdns = 0;
    tmp->priwins = 0;
    tmp->secwins = 0;
    tmp->proxyarp = 0;
    tmp->proxyauth = 0;
    tmp->challenge = 0;
    tmp->debug = 0;
    tmp->pppoptfile[0] = 0;
    tmp->t = NULL;
    return tmp;
}

struct lac6 *new_lac6 ()
{
    struct lac6 *tmp;
    tmp = (struct lac6 *) malloc (sizeof (struct lac6));
    if (!tmp)
    {
        l2tp_log (LOG_CRIT, "%s: Unable to allocate memory for lac entry!\n",
             __FUNCTION__);
        return NULL;
    }

    tmp->next = NULL;
    tmp->rsched = NULL;
    memset((char*)tmp->localaddr,0,16); //RY: since ipv6 is denoted in array
    //tmp->remoteaddr = 0;//RY: since, ipv6 is denoted in array
    memset((char*)tmp->remoteaddr, 0, 16);

    tmp->lns = 0;
    tmp->tun_rws = DEFAULT_RWS_SIZE;
    tmp->call_rws = DEFAULT_RWS_SIZE;
    tmp->hbit = 0;
    tmp->lbit = 0;
    tmp->authpeer = 0;
    tmp->authself = -1;
    tmp->authname[0] = 0;
    tmp->peername[0] = 0;
    tmp->hostname[0] = 0;
    tmp->entname[0] = 0;
    tmp->pap_require = 0;
    tmp->pap_refuse = 0;
    tmp->chap_require = 0;
    tmp->chap_refuse = 0;
    tmp->t = NULL;
    tmp->redial = 0;
    tmp->rtries = 0;
    tmp->rmax = 0;
    tmp->challenge = 0;
    tmp->autodial = 0;
    tmp->rtimeout = 30;
    tmp->active = 0;
    tmp->debug = 0;
    tmp->pppoptfile[0] = 0;
    tmp->defaultroute = 0;
    return tmp;
}

int set_rws6 (char *word, char *value, int context, void *item)
{
    if (atoi (value) < -1)
    {
        snprintf (filerr, sizeof (filerr),
                  "receive window size must be at least -1\n");
        return -1;
    }
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (word[0] == 'c')
            set_int (word, value, &(((struct lac6 *) item)->call_rws));
        if (word[0] == 't')
        {
            set_int (word, value, &(((struct lac6 *) item)->tun_rws));
            if (((struct lac6 *) item)->tun_rws < 1)
            {
                snprintf (filerr, sizeof (filerr),
                          "receive window size for tunnels must be at least 1\n");
                return -1;
            }
        }
        break;
    case CONTEXT_LNS:
        if (word[0] == 'c')
            set_int (word, value, &(((struct lns6 *) item)->call_rws));
        if (word[0] == 't')
        {
            set_int (word, value, &(((struct lns6 *) item)->tun_rws));
            if (((struct lns6 *) item)->tun_rws < 1)
            {
                snprintf (filerr, sizeof (filerr),
                          "receive window size for tunnels must be at least 1\n");
                return -1;
            }
        }
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

//RY: uses lac6, so redifned again.
int set_autodial6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->autodial)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_flow6 (char *word, char *value, int context, void *item)
{
    int v;
    set_boolean (word, value, &v);
    if (v < 0)
        return -1;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (v)
        {
            if (((struct lac6 *) item)->call_rws < 0)
                ((struct lac6 *) item)->call_rws = 0;
        }
        else
        {
            ((struct lac6 *) item)->call_rws = -1;
        }
        break;
    case CONTEXT_LNS:
        if (v)
        {
            if (((struct lns6 *) item)->call_rws < 0)
                ((struct lns6 *) item)->call_rws = 0;
        }
        else
        {
            ((struct lns6 *) item)->call_rws = -1;
        }
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_defaultroute6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->defaultroute)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_authname6 (char *word, char *value, int context, void *item)
{
    struct lac6 *l = (struct lac6 *) item;
    struct lns6 *n = (struct lns6 *) item;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_string (word, value, n->authname, sizeof (n->authname)))
            return -1;
        break;
    case CONTEXT_LAC:
        if (set_string (word, value, l->authname, sizeof (l->authname)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_hostname6 (char *word, char *value, int context, void *item)
{
    struct lac6 *l = (struct lac6 *) item;
    struct lns6 *n = (struct lns6 *) item;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_string (word, value, n->hostname, sizeof (n->hostname)))
            return -1;
        break;
    case CONTEXT_LAC:
        if (set_string (word, value, l->hostname, sizeof (l->hostname)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_passwdauth6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->passwdauth)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_hbit6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->hbit)))
            return -1;
        break;
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->hbit)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_challenge6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->challenge)))
            return -1;
        break;
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->challenge)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_lbit6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->lbit)))
            return -1;
        break;
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->lbit)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}


int set_debug6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->debug)))
            return -1;
        break;
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->debug)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_pppoptfile6 (char *word, char *value, int context, void *item)
{
    struct lac6 *l = (struct lac6 *) item;
    struct lns6 *n = (struct lns6 *) item;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_string (word, value, n->pppoptfile, sizeof (n->pppoptfile)))
            return -1;
        break;
    case CONTEXT_LAC:
        if (set_string (word, value, l->pppoptfile, sizeof (l->pppoptfile)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_papchap6 (char *word, char *value, int context, void *item)
{
    int result;
    char *c;
    struct lac6 *l = (struct lac6 *) item;
    struct lns6 *n = (struct lns6 *) item;
    if (set_boolean (word, value, &result))
        return -1;
    c = strchr (word, ' ');
    c++;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (c[0] == 'p')        /* PAP */
            if (word[2] == 'f')
                l->pap_refuse = result;
            else
                l->pap_require = result;
        else if (c[0] == 'a')   /* Authentication */
            if (word[2] == 'f')
                l->authself = result;
            else
                l->authpeer = result;
        else /* CHAP */ if (word[2] == 'f')
            l->chap_refuse = result;
        else
            l->chap_require = result;
        break;
    case CONTEXT_LNS:
        if (c[0] == 'p')        /* PAP */
            if (word[2] == 'f')
                n->pap_refuse = result;
            else
                n->pap_require = result;
        else if (c[0] == 'a')   /* Authentication */
            if (word[2] == 'f')
                n->authself = !result;
            else
                n->authpeer = result;
        else /* CHAP */ if (word[2] == 'f')
            n->chap_refuse = result;
        else
            n->chap_require = result;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_redial6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        if (set_boolean (word, value, &(((struct lac6 *) item)->redial)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_assignip6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->assign_ip)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}
//RY: start here
//TODO: need to check wrt to socket related stuff
struct iprange6 *set_range6 (char *word, char *value, struct iprange6 *in)
{
    char *c, *d = NULL, *e = NULL;
    struct iprange6 *ipr, *p;
	struct sockaddr_in6 *Temp;
	struct addrinfo myaddr, *hp;
	int count = 0;
    c = strchr (value, '-');
    if (c)
    {
        d = c + 1;
        *c = 0;
        while ((c >= value) && (*c < 33))
            *(c--) = 0;
        while (*d && (*d < 33))
            d++;
    }
    if (!strlen (value) || (c && !strlen (d)))
    {
        snprintf (filerr, sizeof (filerr),
                  "format is '%s <host or ip> - <host or ip>'\n", word);
        return NULL;
    }
    ipr = (struct iprange6 *) malloc (sizeof (struct iprange6));
    ipr->next = NULL;
	//RY: start
	memset(&myaddr, 0, sizeof(myaddr));
    myaddr.ai_family = PF_INET6;
    myaddr.ai_flags = AI_PASSIVE;
    getaddrinfo(value, NULL, &myaddr, &hp );
    //hp = gethostbyname (value);
	//RY: end
    if (!hp)
    {
        snprintf (filerr, sizeof (filerr), "Unknown host %s\n", value);
        free (ipr);
        return NULL;
    }

    Temp = (struct sockaddr_in6*)hp->ai_addr;//RY: typecasting into sockaddr_in6 type
    bcopy (&Temp->sin6_addr.s6_addr16[0], &ipr->start[0], sizeof(Temp->sin6_addr.s6_addr16[0]));// result is in addr

    //bcopy (hp->h_addr, &ipr->start, sizeof (unsigned int));
    if (c)
    {
		e = d;
		while(*e != '\0') {
			if (*e++ == '.')
				count++;
		}
		if (count != 3) {
			char ip_hi[16];

			strcpy(ip_hi, value);
			e = strrchr(ip_hi, '.')+1;
			// Copy the last field + null terminator
			strcpy(e, d);
			d = ip_hi;
		}
        //hp = gethostbyname (d);
		getaddrinfo(d, NULL, &myaddr, &hp ); //RY: myaddr has already been filled.
        if (!hp)
        {
            snprintf (filerr, sizeof (filerr), "Unknown host %s\n", d);
            free (ipr);
            return NULL;
        }
        //bcopy (hp->h_addr, &ipr->end, sizeof (unsigned int));
        Temp = (struct sockaddr_in6*)hp->ai_addr;	//RY: typecast to sockaddr_in6
        bcopy (&Temp->sin6_addr.s6_addr16[0], &ipr->end[0], sizeof(Temp->sin6_addr));// result in ipr_end
    }
    else
        //ipr->end = ipr->start;	//RY: as these are represented as array now.
		memcpy(ipr->end, ipr->start, sizeof(ipr->start));
    if (0 /*ntohl (ipr->start) > ntohl (ipr->end)*/)	//TODO: diable for testing
    {
        snprintf (filerr, sizeof (filerr), "start is greater than end!\n");
        free (ipr);
        return NULL;
    }
    if (word[0] == 'n')
        ipr->sense = SENSE_DENY;
    else
        ipr->sense = SENSE_ALLOW;
    p = in;
    if (p)
    {
        while (p->next)
            p = p->next;
        p->next = ipr;
        return in;
    }
    else
        return ipr;
}
//RY: end here
int set_iprange6 (char *word, char *value, int context, void *item)
{
    struct lns6 *lns6 = (struct lns6 *) item;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    lns6->range = set_range6 (word, value, lns6->range);
    if (!lns6->range)
        return -1;
#ifdef DEBUG_FILE
    l2tp_log (LOG_DEBUG, "range start = %x, end = %x, sense=%ud\n",
         ntohl (lns6->range->start), ntohl (lns6->range->end), lns6->range->sense);
#endif
    return 0;
}

int set_lac6 (char *word, char *value, int context, void *item)
{
    struct lns6 *lns6 = (struct lns6 *) item;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    lns6->lacs = set_range6 (word, value, lns6->lacs);
    if (!lns6->lacs)
        return -1;
#ifdef DEBUG_FILE
    l2tp_log (LOG_DEBUG, "lac start = %x, end = %x, sense=%ud\n",
         ntohl (lns6->lacs->start), ntohl (lns6->lacs->end), lns6->lacs->sense);
#endif
    return 0;
}

int set_exclusive6 (char *word, char *value, int context, void *item)
{
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LNS:
        if (set_boolean (word, value, &(((struct lns6 *) item)->exclusive)))
            return -1;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_localaddr6 (char *word, char *value, int context, void *item)
{
    struct lac6 *l;
    struct lns6 *n;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        l = (struct lac6 *) item;
        return set_ip6 (word, value, &(l->localaddr[0]));
    case CONTEXT_LNS:
        n = (struct lns6 *) item;
        return set_ip6 (word, value, &(n->localaddr[0]));
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_remoteaddr6 (char *word, char *value, int context, void *item)
{
    struct lac6 *l;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
        l = (struct lac6 *) item;
        return set_ip6 (word, value, (l->remoteaddr)); //TODO: check fr warning
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int set_lns6 (char *word, char *value, int context, void *item)
{
#if 0
    struct hostent *hp;
#endif
    struct lac6 *l;
    struct host *ipr, *pos;
    char *d;
    switch (context & ~CONTEXT_DEFAULT)
    {
    case CONTEXT_LAC:
#ifdef DEBUG_FILE
        l2tp_log (LOG_DEBUG, "set_lns6: setting LNS to '%s'\n", value);
#endif
        l = (struct lac6 *) item;
        d = strchr (value, ':');
        if (d)
        {
            d[0] = 0;
            d++;
        }
#if 0
		// why would you want to lookup hostnames at this time?
        hp = gethostbyname (value);
        if (!hp)
        {
            snprintf (filerr, sizeof (filerr), "no such host '%s'\n", value);
            return -1;
        }
#endif
        ipr = malloc (sizeof (struct host));
        ipr->next = NULL;
        pos = l->lns;
        if (!pos)
        {
            l->lns = ipr;
        }
        else
        {
            while (pos->next)
                pos = pos->next;
            pos->next = ipr;
        }
        strncpy (ipr->hostname, value, sizeof (ipr->hostname));
        if (d)
            ipr->port = atoi (d);
        else
            ipr->port = UDP_LISTEN_PORT;
        break;
    default:
        snprintf (filerr, sizeof (filerr), "'%s' not valid in this context\n",
                  word);
        return -1;
    }
    return 0;
}

int parse_config6 (FILE * f)
{
    /* Read in the configuration file handed to us */
    /* FIXME: I should check for incompatible options */
    int context = 0;
    char buf[STRLEN];
    char *s, *d, *t;
    int linenum = 0;
    int def = 0;
    struct keyword *kw;
    void *data = NULL;
    struct lns6 *tl;
    struct lac6 *tc;
    while (!feof (f))
    {
        fgets (buf, sizeof (buf), f);
        if (feof (f))
            break;
        linenum++;
        s = buf;
        /* Strip comments */
        while (*s && *s != ';')
            s++;
        *s = 0;
        s = buf;
        if (!strlen (buf))
            continue;
        while ((*s < 33) && *s)
            s++;                /* Skip over beginning white space */
        t = s + strlen (s);
        while ((t >= s) && (*t < 33))
            *(t--) = 0;         /* Ditch trailing white space */
        if (!strlen (s))
            continue;
        if (s[0] == '[')
        {
            /* We've got a context description */
            if (!(t = strchr (s, ']')))
            {
                l2tp_log (LOG_CRIT, "parse_config: line %d: No closing bracket\n",
                     linenum);
                return -1;
            }
            t[0] = 0;
            s++;
            if ((d = strchr (s, ' ')))
            {
                /* There's a parameter */
                d[0] = 0;
                d++;
            }
            if (d && !strcasecmp (d, "default"))
                def = CONTEXT_DEFAULT;
            else
                def = 0;
            if (!strcasecmp (s, "global"))
            {
                context = CONTEXT_GLOBAL;
#ifdef DEBUG_FILE
                l2tp_log (LOG_DEBUG,
                     "parse_config: global context descriptor %s\n",
                     d ? d : "");
#endif
                data = &gconfig;
            }
            else if (!strcasecmp (s, "lns6"))
            {
                context = CONTEXT_LNS;
                if (def)
                {
                    if (!deflns6)
                    {
                        deflns6 = new_lns6 ();
                        strncpy (deflns6->entname, "default",
                                 sizeof (deflns6->entname));
                    }
                    data = deflns6;
                    continue;
                }
                data = NULL;
                tl = lnslist6;
                if (d)
                {
                    while (tl)
                    {
                        if (!strcasecmp (d, tl->entname))
                            break;
                        tl = tl->next;
                    }
                    if (tl)
                        data = tl;
                }
                if (!data)
                {
                    data = new_lns6 ();
                    if (!data)
                        return -1;
                    ((struct lns6 *) data)->next = lnslist6;
                    lnslist6 = (struct lns6 *) data;
                }
                if (d)
                    strncpy (((struct lns6 *) data)->entname,
                             d, sizeof (((struct lns6 *) data)->entname));
#ifdef DEBUG_FILE
                l2tp_log (LOG_DEBUG, "parse_config: lns context descriptor %s\n",
                     d ? d : "");
#endif
            }
            else if (!strcasecmp (s, "lac6"))
            {
                context = CONTEXT_LAC;
                if (def)
                {
                    if (!deflac6)
                    {
                        deflac6 = new_lac6 ();
                        strncpy (deflac6->entname, "default",
                                 sizeof (deflac6->entname));
                    }
                    data = deflac6;
                    continue;
                }
                data = NULL;
                tc = laclist6;
                if (d)
                {
                    while (tc)
                    {
                        if (!strcasecmp (d, tc->entname))
                            break;
                        tc = tc->next;
                    }
                    if (tc)
                        data = tc;
                }
                if (!data)
                {
                    data = new_lac6 ();
                    if (!data)
                        return -1;
                    ((struct lac6 *) data)->next = laclist6;
                    laclist6 = (struct lac6 *) data;
                }
                if (d)
                    strncpy (((struct lac6 *) data)->entname,
                             d, sizeof (((struct lac6 *) data)->entname));
#ifdef DEBUG_FILE
                l2tp_log (LOG_DEBUG, "parse_config: lac context descriptor %s\n",
                     d ? d : "");
#endif
            }
            else
            {
                l2tp_log (LOG_WARNING,
                     "parse_config: line %d: unknown context '%s'\n", linenum,
                     s);
                return -1;
            }
        }
        else
        {
            if (!context)
            {
                l2tp_log (LOG_WARNING,
                     "parse_config: line %d: data '%s' occurs with no context\n",
                     linenum, s);
                return -1;
            }
            if (!(t = strchr (s, '=')))
            {
                l2tp_log (LOG_WARNING, "parse_config: line %d: no '=' in data\n",
                     linenum);
                return -1;
            }
            d = t;
            d--;
            t++;
            while ((d >= s) && (*d < 33))
                d--;
            d++;
            *d = 0;
            while (*t && (*t < 33))
                t++;
#ifdef DEBUG_FILE
            l2tp_log (LOG_DEBUG, "parse_config: field is %s, value is %s\n", s, t);
#endif
            /* Okay, bit twidling is done.  Let's handle this */
            for (kw = words6; kw->keyword; kw++)
            {
                if (!strcasecmp (s, kw->keyword))
                {
                    if (kw->handler (s, t, context | def, data))
                    {
                        l2tp_log (LOG_WARNING, "parse_config: line %d: %s", linenum,
                             filerr);
                        return -1;
                    }
                    break;
                }
            }
            if (!kw->keyword)
            {
                l2tp_log (LOG_CRIT, "parse_config: line %d: Unknown field '%s'\n",
                     linenum, s);
                return -1;
            }
        }
    }
    return 0;
}

struct keyword words6[] = {
    {"listen-addr", &set_listenaddr},
    {"port", &set_port},
    {"rand source", &set_rand_source},
    {"auth file", &set_authfile},
    {"exclusive", &set_exclusive6},
    {"autodial", &set_autodial6},
    {"redial", &set_redial6},
    {"redial timeout", &set_rtimeout},
    {"lns6", &set_lns6},
    {"max redials", &set_rmax},
    {"access control", &set_accesscontrol},
    {"force userspace", &set_userspace},
    {"ip range", &set_iprange6},
    {"no ip range", &set_iprange6},
    {"debug avp", &set_debugavp},
    {"debug network", &set_debugnetwork},
    {"debug packet", &set_debugpacket},
    {"debug tunnel", &set_debugtunnel},
    {"debug state", &set_debugstate},
    {"ipsec saref", &set_ipsec_saref},
    {"lac6", &set_lac6},
    {"no lac6", &set_lac6},
    {"assign ip", &set_assignip6},
    {"local ip", &set_localaddr6},
    {"remote ip", &set_remoteaddr6},
    {"defaultroute", &set_defaultroute6},
    {"length bit", &set_lbit6},
    {"hidden bit", &set_hbit6},
    {"require pap", &set_papchap6},
    {"require chap", &set_papchap6},
    {"require authentication", &set_papchap6},
    {"require auth", &set_papchap6},
    {"refuse pap", &set_papchap6},
    {"refuse chap", &set_papchap6},
    {"refuse authentication", &set_papchap6},
    {"refuse auth", &set_papchap6},
    {"unix authentication", &set_passwdauth6},
    {"unix auth", &set_passwdauth6},
    {"name", &set_authname6},
    {"hostname", &set_hostname6},
    {"ppp debug", &set_debug6},
    {"pppoptfile", &set_pppoptfile6},
    {"call rws", &set_rws6},
    {"tunnel rws", &set_rws6},
    {"flow bit", &set_flow6},
    {"challenge", &set_challenge6},
    {NULL, NULL}
};


//RY:removed gethostbyname() with getaddrinfo() Done..
int set_ip6 (char *word, char *value, uint8_t *addr)
{
    //struct hostent *hp;
    struct addrinfo myaddr, *hp;
//    struct in6_addr addr;
    struct sockaddr_in6* Temp ;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.ai_family = PF_INET6;
    myaddr.ai_flags = AI_PASSIVE;
    getaddrinfo(value, NULL, &myaddr, &hp );
//    hp = gethostbyname (value);
    if (!hp)
    {
        snprintf (filerr, sizeof (filerr), "%s: host '%s' not found\n",
                  __FUNCTION__, value);
        return -1;
    }
 //   bcopy (hp->h_addr, addr, sizeof (unsigned int));

    Temp = (struct sockaddr_in6*)hp->ai_addr;//RY: typecasting into sockaddr_in6 type
    bcopy ( &Temp->sin6_addr.s6_addr16, addr, sizeof(hp->ai_addr));

    return 0;
}
