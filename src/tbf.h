/* This file is part of vmod-tbf
   Copyright (C) 2013-2016 Sergey Poznyakoff
  
   Vmod-tbf is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
  
   Vmod-tbf is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with vmod-tbf.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <vcl.h>
#include <vrt.h>
#include "vcc_if.h"
#include "vsha256.h"
#include "pthread.h"

#include "bin/varnishd/cache/cache.h"
#define MOD_CTX const struct vrt_ctx *
#define WSPTR(s) ((s)->ws)

#ifndef USEC_PER_SEC
# define USEC_PER_SEC  1000000L
#endif

#define DEBUG 1

struct dump_header {
	uint32_t version;
	uint32_t debug;
	uint32_t size;
	uint32_t count;
	uint32_t root;
};
#define DUMP_VERSION 0

enum { CHILD_LEFT, CHILD_RIGHT };

#define FL_CHILD_LEFT  0x1
#define FL_CHILD_RIGHT 0x2

enum { NST_INCOMPLETE, NST_INIT };

struct node {
	uint8_t key[SHA256_LEN];
#ifdef DEBUG
	char *keystr;
#endif
	struct node *parent;
	struct node *child[2];
	struct node *prev, *next;
	pthread_cond_t notbusy;
	int busy:1;
	int status;
	uint32_t ord;
	uint64_t timestamp;  /* microseconds since epoch */
	size_t tokens;       /* tokens available */
};

struct tree
{
	/* Root node of the tree */
	struct node *root;
	/* All nodes are linked in a LRU fashion, head pointing to
	   the most recently used, and tail to the last recently used
	   ones. */
	struct node *head, *tail;	
	pthread_mutex_t mutex;
	size_t refcnt;
};

enum node_lookup_result { NODE_FOUND, NODE_NEW };

