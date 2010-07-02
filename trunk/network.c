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
 * Network routines for UDP handling
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include "l2tp.h"
#include "ipsecmast.h"
//RY: start
#define	RY:
extern char IPv6;
extern char xxx;
//RY: end
char hostname[256];

void network_thread_IPv4(void);
struct sockaddr_in6 server6, from6;						//RY:
int server_socket6;           /*Server IPv6 socket*/    //RY:
struct sockaddr_in server, from;        /* Server and transmitter structures */
int server_socket;              /* Server socket */

#ifdef USE_KERNEL
int kernel_support;             /* Kernel Support there or not? */
#endif
//RY: start here

int init_ipv6()
{
	long arg;
	unsigned int length = sizeof (server6);
	//RY:start
	char ipaddrStr[INET6_ADDRSTRLEN];
	//RY:end
	gethostname (hostname, sizeof (hostname));
    server6.sin6_family = AF_INET6;//RY: do i need this?

	//   server6.sin6_addr  = in6addr_any; //gconfig.listenaddr; //TODO: check for ipv6 addr???
/*
    inet_pton(AF_INET6, "2001::12/64", &server6.sin6_addr);
    inet_ntop(AF_INET6, server6.sin6_addr.s6_addr, ipaddrStr, sizeof(ipaddrStr));
*/

//    memcpy(&server6.sin6_addr.s6_addr, &gconfig.ipaddr.listenaddr6,
//						sizeof(gconfig.ipaddr.listenaddr6));
    memcpy(&server6.sin6_addr, &gconfig.ipaddr.listenaddr6,
						sizeof(gconfig.ipaddr.listenaddr6));

    printf("RY, addr:%s\n",IPADDY6(gconfig.ipaddr.listenaddr6));

    server6.sin6_port = htons (gconfig.port);

    printf("RY, port:%d\n",  (gconfig.port));
    if ((server_socket6 = socket (AF_INET6, SOCK_DGRAM, 0)) < 0)
        {
            printf( "%s: Unable to allocate IPv6 socket. Terminating.\n",
                 __FUNCTION__);
            return -EINVAL;
        };

    if (bind (server_socket6, (struct sockaddr *) &server6, sizeof (server6)))
    {
        close (server_socket6);
        printf( "%s: Unable to bind socket: %s. Terminating.\n",
             __FUNCTION__, strerror(errno), errno);
        return -EINVAL;
    };
    if (getsockname (server_socket6, (struct sockaddr *) &server6, &length))
    {
        printf( "%s: Unable to read socket name.Terminating.\n",
             __FUNCTION__);
        return -EINVAL;
    }

	  //For L2TP/IPsec with KLIPSng, set the socket to receive IPsec REFINFO
     //values.

    arg=1;
	//RY: start, changed for IPV6 option
	if(setsockopt(server_socket6, SOL_IP, IP_IPSEC_REFINFO,
    /*if(setsockopt(server_socket6, SOL_IP, IP_IPSEC_REFINFO,*/
	//RY: end
		  &arg, sizeof(arg)) != 0) {
	    l2tp_log(LOG_CRIT, "setsockopt recvref: %s\n", strerror(errno));

	    gconfig.ipsecsaref=0;
    }

#ifdef USE_KERNEL
    if (gconfig.forceuserspace)
    {
        printf( "Not looking for kernel support.\n");
        kernel_support = 0;
    }
    else
    {
        int kernel_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
        if (kernel_fd < 0)
        {
            printf( "L2TP kernel support not detected.\n");
            kernel_support = 0;
        }
        else
        {
            close(kernel_fd);
            printf( "Using l2tp kernel support.\n");
            kernel_support = -1;
        }
    }
#else
    printf( "This binary does not support kernel L2TP.\n");
#endif
    arg = fcntl (server_socket6, F_GETFL);
    arg |= O_NONBLOCK;
    fcntl (server_socket6, F_SETFL, arg);
    gconfig.port = ntohs (server6.sin6_port);
    return 0;
}


//RY: end here
//TODO: need to refine the code.
int init_network (void)
{
    long arg;
    unsigned int length = sizeof (server);
    gethostname (hostname, sizeof (hostname));
    //TODO:Read from a file, RY:
    if(xxx == IPv6)
    {
    	init_ipv6();
    	return 0;
    }

//TODO: need to put it in separate function?
// If it is IPv4 socket, then
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = gconfig.ipaddr.listenaddr;
    server.sin_port = htons (gconfig.port);
    printf("RY:1\n");
    if ((server_socket = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
    {    printf("RY:2\n");
    	printf( "%s: Unable to allocate IPv4 socket. Terminating.\n",
    			__FUNCTION__);
		return -EINVAL;
    };

    if (bind (server_socket, (struct sockaddr *) &server, sizeof (server)))
    {
        close (server_socket);
        printf( "%s: Unable to bind socket: %s. Terminating.\n",
             __FUNCTION__, strerror(errno), errno);
        return -EINVAL;
    }
    if (getsockname (server_socket, (struct sockaddr *) &server, &length))
    {
        printf( "%s: Unable to read socket name.Terminating.\n",
             __FUNCTION__);
        return -EINVAL;
    }
    /*
     * For L2TP/IPsec with KLIPSng, set the socket to receive IPsec REFINFO
     * values.
     */
    arg=1;
    if(setsockopt(server_socket, SOL_IP, IP_IPSEC_REFINFO,
		  &arg, sizeof(arg)) != 0) {
	    l2tp_log(LOG_CRIT, "setsockopt recvref: %s\n", strerror(errno));

	    gconfig.ipsecsaref=0;
    }

#ifdef USE_KERNEL
    if (gconfig.forceuserspace)
    {
        printf( "Not looking for kernel support.\n");
        kernel_support = 0;
    }
    else
    {
        int kernel_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
        if (kernel_fd < 0)
        {
            printf( "L2TP kernel support not detected.\n");
            kernel_support = 0;
        }
        else
        {
            close(kernel_fd);
            printf( "Using l2tp kernel support.\n");
            kernel_support = -1;
        }
    }
#else
    printf( "This binary does not support kernel L2TP.\n");
#endif
    arg = fcntl (server_socket, F_GETFL);
    arg |= O_NONBLOCK;
    fcntl (server_socket, F_SETFL, arg);
    gconfig.port = ntohs (server.sin_port);
    return 0;
}

inline void extract (void *buf, int *tunnel, int *call)
{
    /*
     * Extract the tunnel and call #'s, and fix the order of the
     * version
     */

    struct payload_hdr *p = (struct payload_hdr *) buf;
    if (PLBIT (p->ver))
    {
        *tunnel = p->tid;
        *call = p->cid;
    }
    else
    {
        *tunnel = p->length;
        *call = p->tid;
    }
}

inline void fix_hdr (void *buf)
{
    /*
     * Fix the byte order of the header
     */

    struct payload_hdr *p = (struct payload_hdr *) buf;
    _u16 ver = ntohs (p->ver);
    if (CTBIT (p->ver))
    {
        /*
         * Control headers are always
         * exactly 12 bytes big.
         */
        swaps (buf, 12);
    }
    else
    {
        int len = 6;
        if (PSBIT (ver))
            len += 4;
        if (PLBIT (ver))
            len += 2;
        if (PFBIT (ver))
            len += 4;
        swaps (buf, len);
    }
}

void dethrottle (void *call)
{
/*	struct call *c = (struct call *)call; */
/*	if (c->throttle) {
#ifdef DEBUG_FLOW
		log(LOG_DEBUG, "%s: dethrottling call %d, and setting R-bit\n",__FUNCTION__,c->ourcid);
#endif 		c->rbit = RBIT;
		c->throttle = 0;
	} else {
		log(LOG_DEBUG, "%s:  call %d already dethrottled?\n",__FUNCTION__,c->ourcid);
	} */
}
//RY: starts here
void control_xmit_ipv6 (void *b)
{
    struct buffer6 *buf = (struct buffer6 *) b;
    struct tunnel6 *t;
    struct timeval tv;
    int ns;

    if (!buf)
    {
        l2tp_log (LOG_WARNING, "%s: called on NULL buffer!\n", __FUNCTION__);
        return;
    }

    t = buf->tunnel;
#ifdef DEBUG_CONTROL_XMIT
    if(t) {
	    l2tp_log (LOG_DEBUG,
		      "trying to send control packet to %d\n",
		      t->ourtid);
    }
#endif

    buf->retries++;
    ns = ntohs (((struct control_hdr *) (buf->start))->Ns);
    if (t)
    {
        if (ns < t->cLr)
        {
#ifdef DEBUG_CONTROL_XMIT
            l2tp_log (LOG_DEBUG, "%s: Tossing packet %d\n", __FUNCTION__, ns);
#endif
            /* Okay, it's been received.  Let's toss it now */
            toss6 (buf);
            return;
        }
    }
    if (buf->retries > DEFAULT_MAX_RETRIES)
    {
        /*
           * Too many retries.  Either kill the tunnel, or
           * if there is no tunnel, just stop retransmitting.
         */
        if (t)
        {
            if (t->self->needclose)
            {
                l2tp_log (LOG_DEBUG,
                     "Unable to deliver closing message for tunnel %d. Destroying anyway.\n",
                     t->ourtid);
                t->self->needclose = 0;
                t->self->closing = -1;
            }
            else
            {
                l2tp_log (LOG_NOTICE,
                     "Maximum retries exceeded for tunnel %d.  Closing.\n",
                     t->ourtid);
                strcpy (t->self->errormsg, "Timeout");
                t->self->needclose = -1;
            }
        }
	free(buf->rstart);
	free(buf);
    }
    else
    {
        /*
           * FIXME:  How about adaptive timeouts?
         */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        schedule (tv, control_xmit_ipv6, buf);
#ifdef DEBUG_CONTROL_XMIT
        l2tp_log (LOG_DEBUG, "%s: Scheduling and transmitting packet %d\n",
             __FUNCTION__, ns);
#endif
        udp_xmit6 (buf, t);
    }
}
//RY: ends here

void control_xmit (void *b)
{
    struct buffer *buf = (struct buffer *) b;
    struct tunnel *t;
    struct timeval tv;
    int ns;
//RY: start here
 /*   if(xxx == IPv6)
	{
		control_xmit_ipv6(b);
		return;
	}
*/
//RY: ends here
    if (!buf)
    {
        l2tp_log (LOG_WARNING, "%s: called on NULL buffer!\n", __FUNCTION__);
        return;
    }

    t = buf->tunnel;
#ifdef DEBUG_CONTROL_XMIT
    if(t) {
	    l2tp_log (LOG_DEBUG,
		      "trying to send control packet to %d\n",
		      t->ourtid);
    }
#endif

    buf->retries++;
    ns = ntohs (((struct control_hdr *) (buf->start))->Ns);
    if (t)
    {
        if (ns < t->cLr)
        {
#ifdef DEBUG_CONTROL_XMIT
            l2tp_log (LOG_DEBUG, "%s: Tossing packet %d\n", __FUNCTION__, ns);
#endif
            /* Okay, it's been received.  Let's toss it now */
            toss (buf);
            return;
        }
    }
    if (buf->retries > DEFAULT_MAX_RETRIES)
    {
        /*
           * Too many retries.  Either kill the tunnel, or
           * if there is no tunnel, just stop retransmitting.
         */
        if (t)
        {
            if (t->self->needclose)
            {
                l2tp_log (LOG_DEBUG,
                     "Unable to deliver closing message for tunnel %d. Destroying anyway.\n",
                     t->ourtid);
                t->self->needclose = 0;
                t->self->closing = -1;
            }
            else
            {
                l2tp_log (LOG_NOTICE,
                     "Maximum retries exceeded for tunnel %d.  Closing.\n",
                     t->ourtid);
                strcpy (t->self->errormsg, "Timeout");
                t->self->needclose = -1;
            }
        }
	free(buf->rstart);
	free(buf);
    }
    else
    {
        /*
           * FIXME:  How about adaptive timeouts?
         */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        schedule (tv, control_xmit, buf);
#ifdef DEBUG_CONTROL_XMIT
        l2tp_log (LOG_DEBUG, "%s: Scheduling and transmitting packet %d\n",
             __FUNCTION__, ns);
#endif
        udp_xmit (buf, t);
    }
}
//RY: start here
void udp_xmit6 (struct buffer6 *buf, struct tunnel6 *t)
{
	struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(sizeof (unsigned int))];
    unsigned int *refp;
    struct msghdr msgh;
    int err;
    struct iovec iov;
//RY: start, for testing
    struct sockaddr_in6 clientaddr;
    struct iovec iov1[1];
    char a[10];
//RY: end
    /*
     * OKAY, now send a packet with the right SAref values.
     */
    memset(&msgh, 0, sizeof(struct msghdr));

    msgh.msg_control = cbuf;
    msgh.msg_controllen = 0;
//TODO: need to take decision on IPSEC
    if(gconfig.ipsecsaref && t->refhim != IPSEC_SAREF_NULL) {
	msgh.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_IP;
	//RY: start
	//cmsg->cmsg_type  = IP_IPSEC_REFINFO;
	cmsg->cmsg_type  = IPV6_DSTOPTS;	//RY: updated for IPV6 com.
	//RY: end
	cmsg->cmsg_len   = CMSG_LEN(sizeof(unsigned int));

	if(gconfig.debug_network) {
		l2tp_log(LOG_DEBUG,"sending with saref=%d\n", t->refhim);
	}
	refp = (unsigned int *)CMSG_DATA(cmsg);
	*refp = t->refhim;

	msgh.msg_controllen = cmsg->cmsg_len;
    }

    iov.iov_base = buf->start;
    iov.iov_len  = buf->len;

    /* return packet from whence it came */
    //RY: start
    inet_pton(AF_INET6, "2003::1", &buf->peer.sin6_addr);
    buf->peer.sin6_family = AF_INET6;
    buf->peer.sin6_port = htons(1701);
    //RY: end
    msgh.msg_name    = &buf->peer;
    msgh.msg_namelen = sizeof(buf->peer);

    msgh.msg_iov  = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_flags = 0;

#if 0
    //RY: start
    inet_pton(AF_INET6, "2005::1", &buf->peer.sin6_addr);

    printf("dest addr:%s\n", IPADDY6(buf->peer.sin6_addr));
    buf->peer.sin6_family = AF_INET6;
    buf->peer.sin6_port = htons(23156);

    msgh.msg_name = &buf->peer;

    iov.iov_base = a;
    iov.iov_len = sizeof(a);
    msgh.msg_iov->iov_base = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = NULL;
    msgh.msg_controllen = 0;
    msgh.msg_flags = 0;

//#ifdef RY:
//    memset(&clientaddr, 0, sizeof(clientaddr));
//    	inet_pton(AF_INET6,"2005::1", &clientaddr.sin6_addr);
//    	clientaddr.sin6_port = htons(1701);
//    	clientaddr.sin6_family = AF_INET6;
//    memset(a, 'a', sizeof(a));
//        for(;;)
//          sendto(server_socket6, a, sizeof(a), 0,
//  							&clientaddr, sizeof(clientaddr));
 //   for(;;)
#endif
    //for(;;)
    if((err = sendmsg(server_socket6, &msgh, 0)) < 0)
	{
    	//RY: start
    	printf("udp_xmit6 failed with err=%d:%s\n",err,strerror(errno));
		//RY: end
		l2tp_log(LOG_ERR, "udp_xmit6 failed with err=%d:%s\n",
    			err,strerror(errno));
    }//RY: start
    else
    {
    	printf("sent:bytes = %d\n", err);
    //sleep(1)
    }
    //RY: end
}

//RY: end here
void udp_xmit (struct buffer *buf, struct tunnel *t)
{
    struct cmsghdr *cmsg;
    char cbuf[CMSG_SPACE(sizeof (unsigned int))];
    unsigned int *refp;
    struct msghdr msgh;
    int err;
    struct iovec iov;

    /*
     * OKAY, now send a packet with the right SAref values.
     */
    memset(&msgh, 0, sizeof(struct msghdr));

    msgh.msg_control = cbuf;
    msgh.msg_controllen = 0;

    if(gconfig.ipsecsaref && t->refhim != IPSEC_SAREF_NULL) {
	msgh.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type  = IP_IPSEC_REFINFO;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(unsigned int));

	if(gconfig.debug_network) {
		l2tp_log(LOG_DEBUG,"sending with saref=%d\n", t->refhim);
	}
	refp = (unsigned int *)CMSG_DATA(cmsg);
	*refp = t->refhim;

	msgh.msg_controllen = cmsg->cmsg_len;
    }

    iov.iov_base = buf->start;
    iov.iov_len  = buf->len;

    /* return packet from whence it came */
    msgh.msg_name    = &buf->peer;
    msgh.msg_namelen = sizeof(buf->peer);

    msgh.msg_iov  = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_flags = 0;

    /* Receive one packet. */
    //for(;;)
    if((err = sendmsg(server_socket, &msgh, 0)) < 0)
		{
    		l2tp_log(LOG_ERR, "udp_xmit failed with err=%d:%s\n",
    				err,strerror(errno));
    	}
    //RY: start
        else
        {
        	printf("sent:bytes = %d\n", err);
        //sleep(1)
        }
        //RY: end
}

int build_fdset (fd_set *readfds)
{
	struct tunnel *tun;
	struct call *call;
	int max = 0;

	tun = tunnels.head;
	FD_ZERO (readfds);

	while (tun)
	{
		call = tun->call_head;
		while (call)
		{
			if (call->needclose ^ call->closing)
			{
				call_close (call);
				call = tun->call_head;
				if (!call)
					break;
				continue;
			}
			if (call->fd > -1)
			{
				if (!call->needclose && !call->closing)
				{
					if (call->fd > max)
						max = call->fd;
					FD_SET (call->fd, readfds);
				}
			}
			call = call->next;
		}
		/* Now that call fds have been collected, and checked for
		 * closing, check if the tunnel needs to be closed too
		 */
		if (tun->self->needclose ^ tun->self->closing)
		{
			if (gconfig.debug_tunnel)
				l2tp_log (LOG_DEBUG, "%s: closing down tunnel %d\n",
						__FUNCTION__, tun->ourtid);
			call_close (tun->self);
			/* Reset the while loop
			 * and check for NULL */
			tun = tunnels.head;
			if (!tun)
				break;
			continue;
		}
		tun = tun->next;
	}

	FD_SET (server_socket, readfds);
	if (server_socket > max)
		max = server_socket;
	FD_SET (control_fd, readfds);
	if (control_fd > max)
		max = control_fd;
	return max;
}

int build_fdset_ipv6 (fd_set *readfds)
{
	struct tunnel6 *tun;
	struct call6 *call;
	int max = 0;

	tun = tunnels6.head;
	FD_ZERO (readfds);

	while (tun)
	{
		call = tun->call_head;
		while (call)
		{
			if (call->needclose ^ call->closing)
			{
				call_close6 (call);
				call = tun->call_head;
				if (!call)
					break;
				continue;
			}
			if (call->fd > -1)
			{
				if (!call->needclose && !call->closing)
				{
					if (call->fd > max)
						max = call->fd;
					FD_SET (call->fd, readfds);
				}
			}
			call = call->next;
		}
		/* Now that call fds have been collected, and checked for
		 * closing, check if the tunnel needs to be closed too
		 */
		if (tun->self->needclose ^ tun->self->closing)
		{
			if (gconfig.debug_tunnel)
				l2tp_log (LOG_DEBUG, "%s: closing down tunnel %d\n",
						__FUNCTION__, tun->ourtid);
			call_close6 (tun->self);
			/* Reset the while loop
			 * and check for NULL */
			tun = tunnels6.head;
			if (!tun)
				break;
			continue;
		}
		tun = tun->next;
	}

	FD_SET (server_socket6, readfds);
	if (server_socket6 > max)
		max = server_socket6;
	FD_SET (control_fd, readfds);
	if (control_fd > max)
		max = control_fd;
	return max;
}

//RY: start here
void network_thread_IPv6()
{
	/*
     * We loop forever waiting on either data from the ppp drivers or from
     * our network socket.  Control handling is no longer done here.
     */
    struct sockaddr_in6 from, to;
    unsigned int fromlen, tolen;
    int tunnel, call;           /* Tunnel and call */
    int recvsize;               /* Length of data received */
    struct buffer6 *buf;         /* Payload buffer */
    struct call6 *c, *sc;        /* Call to send this off to */
    struct tunnel6 *st;          /* Tunnel */
    fd_set readfds;             /* Descriptors to watch for reading */
    int max;                    /* Highest fd */
    struct timeval tv;          /* Timeout for select */
    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
    unsigned int refme, refhim;

    /* This one buffer can be recycled for everything except control packets */
    buf = new_buf6 (MAX_RECV_SIZE);

    tunnel = 0;
    call = 0;

    for (;;)
    {
        max = build_fdset_ipv6 (&readfds);
        tv.tv_sec = 1;//RY:commented for testing
        //tv.tv_sec = 0;//RY: made 0 for testing, anyways not being used in select().
        tv.tv_usec = 0;
        schedule_unlock ();

		// RY: start
#if 0
		buf->peer = from;
		buf->len = sizeof(from);
		buf->start = NULL;
        udp_xmit6 (buf, st);
        udp_xmit6 (buf, st);
        udp_xmit6 (buf, st);

#endif
        //RY: end
        select (max + 1, &readfds, NULL, NULL, NULL);
        schedule_lock ();
        if (FD_ISSET (control_fd, &readfds))
        {
            do_control6 ();
        }
        //TODO: Mistake prone line.RY:
        if (FD_ISSET (server_socket6, &readfds))
        {
            /*
             * Okay, now we're ready for reading and processing new data.
             */
            recycle_buf6 (buf);

            /* Reserve space for expanding payload packet headers */
            buf->start += PAYLOAD_BUF;
            buf->len -= PAYLOAD_BUF;

            memset(&from, 0, sizeof(from));
            memset(&to,   0, sizeof(to));

            fromlen = sizeof(from);
            tolen   = sizeof(to);

            memset(&msgh, 0, sizeof(struct msghdr));
            iov.iov_base = buf->start;
            iov.iov_len  = buf->len;
            msgh.msg_control = cbuf;
            msgh.msg_controllen = sizeof(cbuf);
            msgh.msg_name = &from;
            msgh.msg_namelen = fromlen;
            msgh.msg_iov  = &iov;
            msgh.msg_iovlen = 1;
            msgh.msg_flags = 0;
//RY: start here
	    /* Receive one packet. */
            recvsize = recvmsg(server_socket6, &msgh, 0);

//RY: ends here
            if (recvsize < MIN_PAYLOAD_HDR_LEN)
            {
                if (recvsize < 0)
                {
                    if (errno != EAGAIN)
                        l2tp_log (LOG_WARNING,
                             "%s: recvfrom returned error %d (%s)\n",
                             __FUNCTION__, errno, strerror (errno));
                }
                else
                {
                    l2tp_log (LOG_WARNING, "%s: received too small a packet\n",
                         __FUNCTION__);
                }
                continue;
            }

	    refme=refhim=0;

	    /* extract IPsec info out */
	    if(gconfig.ipsecsaref) {
		    struct cmsghdr *cmsg;
		    /* Process auxiliary received data in msgh */
		    for (cmsg = CMSG_FIRSTHDR(&msgh);
			 cmsg != NULL;
			 cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
			    if (cmsg->cmsg_level == IPPROTO_IPV6
				&& cmsg->cmsg_type == IP_IPSEC_REFINFO) {	//RY: can be changed to
				    unsigned int *refp;

				    refp = (unsigned int *)CMSG_DATA(cmsg);
				    refme =refp[0];
				    refhim=refp[1];
			    }
		    }
	    }

	    /*
	     * some logic could be added here to verify that we only
	     * get L2TP packets inside of IPsec, or to provide different
	     * classes of service to packets not inside of IPsec.
	     */
	    buf->len = recvsize;
	    fix_hdr (buf->start);
	    extract (buf->start, &tunnel, &call);

	    if (gconfig.debug_network)
	    {
	    	//RY: start
	    	//TODO: un-comment later..
	    	l2tp_log(LOG_DEBUG, "RY: packet received");
//		l2tp_log(LOG_DEBUG, "%s: recv packet from %s, size = %d, "
//			 "tunnel = %d, call = %d ref=%u refhim=%u\n",
//			 __FUNCTION__, inet_ntop(from.sin6_addr),
//			 recvsize, tunnel, call, refme, refhim);
	    	//RY: end
	    }

	    if (gconfig.packet_dump)
	    {
	    	do_packet_dump6 (buf);
	    }
	    if (!
		(c = get_call6 (tunnel, call, from.sin6_addr,
			       from.sin6_port, refme, refhim)))
	    {
			if ((c =
				get_tunnel6 (tunnel, from.sin6_port)))
			{
		    /*
		     * It is theoretically possible that we could be sent
		     * a control message (say a StopCCN) on a call that we
		     * have already closed or some such nonsense.  To
		     * prevent this from closing the tunnel, if we get a
		     * call on a valid tunnel, but not with a valid CID,
		     * we'll just send a ZLB to ack receiving the packet.
		     */
				if (gconfig.debug_tunnel)
				l2tp_log (LOG_DEBUG,
				  "%s: no such call %d on tunnel %d.  Sending special ZLB\n",
				  __FUNCTION__);
				handle_special6 (buf, c, call);

				/* get a new buffer */
				buf = new_buf6 (MAX_RECV_SIZE);
			}
			else
				l2tp_log (LOG_DEBUG,
			      "%s: unable to find call or tunnel to handle packet.  call = %d, tunnel = %d Dumping.\n",
			      __FUNCTION__, call, tunnel);

		}
	    else
	    {
	    	buf->peer = from;
			/* Handle the packet */
			c->container->chal_us.vector = NULL;
			if (handle_packet6 (buf, c->container, c))
			{
				if (gconfig.debug_tunnel)
				l2tp_log (LOG_DEBUG, "%s: bad packet\n", __FUNCTION__);
			}
			if (c->cnu)
			{
				/* Send Zero Byte Packet */
				control_zlb6 (buf, c->container, c);
				c->cnu = 0;
			}
	    }
	}

	/*
	 * finished obvious sources, look for data from PPP connections.
	 */
	st = tunnels6.head;
        while (st)
        {
            sc = st->call_head;
            while (sc)
            {
                if ((sc->fd >= 0) && FD_ISSET (sc->fd, &readfds))
                {
                    /* Got some payload to send */
                    int result;
                    recycle_payload6 (buf, sc->container->peer);
/*
#ifdef DEBUG_FLOW_MORE
                    l2tp_log (LOG_DEBUG, "%s: rws = %d, pSs = %d, pLr = %d\n",
                         __FUNCTION__, sc->rws, sc->pSs, sc->pLr);
#endif
		    if ((sc->rws>0) && (sc->pSs > sc->pLr + sc->rws) && !sc->rbit) {
#ifdef DEBUG_FLOW
						log(LOG_DEBUG, "%s: throttling payload (call = %d, tunnel = %d, Lr = %d, Ss = %d, rws = %d)!\n",__FUNCTION__,
								 sc->cid, sc->container->tid, sc->pLr, sc->pSs, sc->rws);
#endif
						sc->throttle = -1;
						We unthrottle in handle_packet if we get a payload packet,
						valid or ZLB, but we also schedule a dethrottle in which
						case the R-bit will be set
						FIXME: Rate Adaptive timeout?
						tv.tv_sec = 2;
						tv.tv_usec = 0;
						sc->dethrottle = schedule(tv, dethrottle, sc);
					} else */
/*					while ((result=read_packet(buf,sc->fd,sc->frame & SYNC_FRAMING))>0) { */
                    while ((result =
                            read_packet6 (buf, sc->fd, SYNC_FRAMING)) > 0)
                    {
                        add_payload_hdr6 (sc->container, sc, buf);
                        if (gconfig.packet_dump)
                        {
                            do_packet_dump6 (buf);
                        }

                        sc->prx = sc->data_rec_seq_num;
                        if (sc->zlb_xmit6)
                        {
                            deschedule (sc->zlb_xmit6);
                            sc->zlb_xmit6 = NULL;
                        }
                        sc->tx_bytes += buf->len;
                        sc->tx_pkts++;
                        udp_xmit6 (buf, st);
                        recycle_payload6 (buf, sc->container->peer);
                    }
                    if (result != 0)
                    {
                        l2tp_log (LOG_WARNING,
                             "%s: tossing read packet, error = %s (%d).  Closing call.\n",
                             __FUNCTION__, strerror (-result), -result);
                        strcpy (sc->errormsg, strerror (-result));
                        sc->needclose = -1;
                    }
                }
                sc = sc->next;
            }
            st = st->next;
        }
    }
}
//RY: ends here

void network_thread_IPv4()
{
	/*
     * We loop forever waiting on either data from the ppp drivers or from
     * our network socket.  Control handling is no longer done here.
     */
    struct sockaddr_in from, to;
    unsigned int fromlen, tolen;
    int tunnel, call;           /* Tunnel and call */
    int recvsize;               /* Length of data received */
    struct buffer *buf;         /* Payload buffer */
    struct call *c, *sc;        /* Call to send this off to */
    struct tunnel *st;          /* Tunnel */
    fd_set readfds;             /* Descriptors to watch for reading */
    int max;                    /* Highest fd */
    struct timeval tv;          /* Timeout for select */
    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
    unsigned int refme, refhim;

    /* This one buffer can be recycled for everything except control packets */
    buf = new_buf (MAX_RECV_SIZE);

    tunnel = 0;
    call = 0;

    for (;;)
    {
        max = build_fdset (&readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        schedule_unlock ();
        select (max + 1, &readfds, NULL, NULL, NULL);
        schedule_lock ();
        if (FD_ISSET (control_fd, &readfds))
        {
            do_control ();
        }
        //TODO: Mistake prone line.RY:
        if (FD_ISSET (server_socket, &readfds))
        {
            /*
             * Okay, now we're ready for reading and processing new data.
             */
            recycle_buf (buf);

            /* Reserve space for expanding payload packet headers */
            buf->start += PAYLOAD_BUF;
            buf->len -= PAYLOAD_BUF;

	    memset(&from, 0, sizeof(from));
	    memset(&to,   0, sizeof(to));

	    fromlen = sizeof(from);
	    tolen   = sizeof(to);

	    memset(&msgh, 0, sizeof(struct msghdr));
	    iov.iov_base = buf->start;
	    iov.iov_len  = buf->len;
	    msgh.msg_control = cbuf;
	    msgh.msg_controllen = sizeof(cbuf);
	    msgh.msg_name = &from;
	    msgh.msg_namelen = fromlen;
	    msgh.msg_iov  = &iov;
	    msgh.msg_iovlen = 1;
	    msgh.msg_flags = 0;
//RY: start here
	    /* Receive one packet. */
	    recvsize = recvmsg(server_socket, &msgh, 0);
//RY: ends here
	    if (recvsize < MIN_PAYLOAD_HDR_LEN)
            {
                if (recvsize < 0)
                {
                    if (errno != EAGAIN)
                        l2tp_log (LOG_WARNING,
                             "%s: recvfrom returned error %d (%s)\n",
                             __FUNCTION__, errno, strerror (errno));
                }
                else
                {
                    l2tp_log (LOG_WARNING, "%s: received too small a packet\n",
                         __FUNCTION__);
                }
		continue;
            }


	    refme=refhim=0;

	    /* extract IPsec info out */
	    if(gconfig.ipsecsaref) {
		    struct cmsghdr *cmsg;
		    /* Process auxiliary received data in msgh */
		    for (cmsg = CMSG_FIRSTHDR(&msgh);
			 cmsg != NULL;
			 cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
			    if (cmsg->cmsg_level == IPPROTO_IPV6
			    		//RY: start, //TODO: make amendments for IPv6
			    	&& cmsg->cmsg_type == 	IPV6_DSTOPTS)
			    		/*&& cmsg->cmsg_type == IP_IPSEC_REFINFO)*/
			    	//RY: end
			    	{
				    unsigned int *refp;

				    refp = (unsigned int *)CMSG_DATA(cmsg);
				    refme =refp[0];
				    refhim=refp[1];
			    }
		    }
	    }

	    /*
	     * some logic could be added here to verify that we only
	     * get L2TP packets inside of IPsec, or to provide different
	     * classes of service to packets not inside of IPsec.
	     */
	    buf->len = recvsize;
	    fix_hdr (buf->start);
	    extract (buf->start, &tunnel, &call);

	    if (gconfig.debug_network)
	    {
		l2tp_log(LOG_DEBUG, "%s: recv packet from %s, size = %d, "
			 "tunnel = %d, call = %d ref=%u refhim=%u\n",
			 __FUNCTION__, inet_ntoa (from.sin_addr),
			 recvsize, tunnel, call, refme, refhim);
	    }

	    if (gconfig.packet_dump)
	    {
	    	do_packet_dump (buf);
	    }
	    if (!
		(c = get_call (tunnel, call, from.sin_addr.s_addr,
			       from.sin_port, refme, refhim)))
	    {
		if ((c =
		     get_tunnel (tunnel, from.sin_addr.s_addr,
				 from.sin_port)))
		{
		    /*
		     * It is theoretically possible that we could be sent
		     * a control message (say a StopCCN) on a call that we
		     * have already closed or some such nonsense.  To
		     * prevent this from closing the tunnel, if we get a
		     * call on a valid tunnel, but not with a valid CID,
		     * we'll just send a ZLB to ack receiving the packet.
		     */
		    if (gconfig.debug_tunnel)
			l2tp_log (LOG_DEBUG,
				  "%s: no such call %d on tunnel %d.  Sending special ZLB\n",
				  __FUNCTION__);
		    handle_special (buf, c, call);

		    /* get a new buffer */
		    buf = new_buf (MAX_RECV_SIZE);
		}
		else
		    l2tp_log (LOG_DEBUG,
			      "%s: unable to find call or tunnel to handle packet.  call = %d, tunnel = %d Dumping.\n",
			      __FUNCTION__, call, tunnel);

	    }
	    else
	    {
		buf->peer = from;
		/* Handle the packet */
		c->container->chal_us.vector = NULL;
		if (handle_packet (buf, c->container, c))
		{
		    if (gconfig.debug_tunnel)
			l2tp_log (LOG_DEBUG, "%s: bad packet\n", __FUNCTION__);
		};
		if (c->cnu)
		{
		    /* Send Zero Byte Packet */
		    control_zlb (buf, c->container, c);
		    c->cnu = 0;
		}
	    };
	}

	/*
	 * finished obvious sources, look for data from PPP connections.
	 */
	st = tunnels.head;
        while (st)
        {
            sc = st->call_head;
            while (sc)
            {
                if ((sc->fd >= 0) && FD_ISSET (sc->fd, &readfds))
                {
                    /* Got some payload to send */
                    int result;
                    recycle_payload (buf, sc->container->peer);
/*
#ifdef DEBUG_FLOW_MORE
                    l2tp_log (LOG_DEBUG, "%s: rws = %d, pSs = %d, pLr = %d\n",
                         __FUNCTION__, sc->rws, sc->pSs, sc->pLr);
#endif
		    if ((sc->rws>0) && (sc->pSs > sc->pLr + sc->rws) && !sc->rbit) {
#ifdef DEBUG_FLOW
						log(LOG_DEBUG, "%s: throttling payload (call = %d, tunnel = %d, Lr = %d, Ss = %d, rws = %d)!\n",__FUNCTION__,
								 sc->cid, sc->container->tid, sc->pLr, sc->pSs, sc->rws);
#endif
						sc->throttle = -1;
						We unthrottle in handle_packet if we get a payload packet,
						valid or ZLB, but we also schedule a dethrottle in which
						case the R-bit will be set
						FIXME: Rate Adaptive timeout?
						tv.tv_sec = 2;
						tv.tv_usec = 0;
						sc->dethrottle = schedule(tv, dethrottle, sc);
					} else */
/*					while ((result=read_packet(buf,sc->fd,sc->frame & SYNC_FRAMING))>0) { */
                    while ((result =
                            read_packet (buf, sc->fd, SYNC_FRAMING)) > 0)
                    {
                        add_payload_hdr (sc->container, sc, buf);
                        if (gconfig.packet_dump)
                        {
                            do_packet_dump (buf);
                        }

                        sc->prx = sc->data_rec_seq_num;
                        if (sc->zlb_xmit)
                        {
                            deschedule (sc->zlb_xmit);
                            sc->zlb_xmit = NULL;
                        }
                        sc->tx_bytes += buf->len;
                        sc->tx_pkts++;
                        udp_xmit (buf, st);
                        recycle_payload (buf, sc->container->peer);
                    }
                    if (result != 0)
                    {
                        l2tp_log (LOG_WARNING,
                             "%s: tossing read packet, error = %s (%d).  Closing call.\n",
                             __FUNCTION__, strerror (-result), -result);
                        strcpy (sc->errormsg, strerror (-result));
                        sc->needclose = -1;
                    }
                }
                sc = sc->next;
            }
            st = st->next;
        }
    }
}
void network_thread ()
{
//RY: start here
    if(xxx == IPv6)
    	network_thread_IPv6();
    else
    	network_thread_IPv4();
//RY: ends here
}
