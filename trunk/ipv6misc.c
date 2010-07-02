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
 * Miscellaneous but important functions
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#if defined(SOLARIS)
# include <varargs.h>
#endif
#include <netinet/in.h>
#include "l2tp.h"

void set_error6 (struct call6 *c, int error, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    c->error = error;
    c->result = RESULT_ERROR;
    c->needclose = -1;
    vsnprintf (c->errormsg, sizeof (c->errormsg), fmt, args);
    if (c->errormsg[strlen (c->errormsg) - 1] == '\n')
        c->errormsg[strlen (c->errormsg) - 1] = 0;
    va_end (args);
}

struct buffer6 *new_buf6 (int size)
{
    struct buffer6 *b = malloc (sizeof (struct buffer6));

    if (!b || !size || size < 0)
        return NULL;
    b->rstart = malloc (size);
    if (!b->rstart)
    {
        free (b);
        return NULL;
    }
    b->start = b->rstart;
    b->rend = b->rstart + size - 1;
    b->len = size;
    b->maxlen = size;
    return b;
}

inline void recycle_buf6 (struct buffer6 *b)
{
    b->start = b->rstart;
    b->len = b->maxlen;
}

void do_packet_dump6 (struct buffer6 *buf)
{
    int x;
    unsigned char *c = buf->start;
    printf ("packet dump: \nHEX: { ");
    for (x = 0; x < buf->len; x++)
    {
        printf ("%.2X ", *c);
        c++;
    };
    printf ("}\nASCII: { ");
    c = buf->start;
    for (x = 0; x < buf->len; x++)
    {
        if (*c > 31 && *c < 127)
        {
            putchar (*c);
        }
        else
        {
            putchar (' ');
        }
        c++;
    }
    printf ("}\n");
}

inline void toss6 (struct buffer6 *buf)
{
    /*
     * Toss a frame and free up the buffer that contained it
     */

    free (buf->rstart);
    free (buf);
}


