/* This file is part of vmod-tbf
   Copyright (C) 2013 Sergey Poznyakoff
  
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
#include <db.h>
#include "vrt.h"
#include "vcc_if.h"
#include "bin/varnishd/cache.h"

#ifdef VMODDEBUG
# include <stdarg.h>
static void
debugprt(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_DAEMON|LOG_DEBUG, fmt, ap);
	va_end(ap);
}
#define debug(c) debugprt c
#else
# define debug(c)
#endif

#ifndef USEC_PER_SEC
# define USEC_PER_SEC  1000000L
#endif

static char *dbname;
static DB *db;
static uint64_t autosync_max;
static uint64_t autosync_count;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#define DBFILEMODE 0640

static void
tbf_set_db_name(const char *file_name)
{
	if (dbname)
		free(dbname);
	dbname = strdup(file_name);
	if (!dbname)
		abort();
}

struct mode_kw {
	char *mkw_str;
	int mkw_len;
	int mkw_tok;
};

enum {
	MKW_TRUNCATE,
	MKW_MODE,
	MKW_SYNC
};

static struct mode_kw mode_kw_tab[] = {
#define S(s) #s, sizeof(#s)-1
	{ S(truncate), MKW_TRUNCATE },
	{ S(trunc), MKW_TRUNCATE },
	{ S(mode=), MKW_MODE },
	{ S(sync=), MKW_SYNC },
	{ NULL }
#undef S
};

static void
tbf_open_internal(const char *mode)
{
	int rc;
	int flags = DB_CREATE|DB_THREAD;
	int filemode = DBFILEMODE;
	uint64_t n;
	char *p;
	
	if (!dbname)
		tbf_set_db_name(LOCALSTATEDIR "/tbf.db");
	debug(("opening database %s", dbname));
	
	rc = db_create(&db, NULL, 0);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot create db struct");
		return;
	}

	while (*mode) {
		struct mode_kw *mkw;
		
		for (mkw = mode_kw_tab; mkw->mkw_str; mkw++) {
			if (strncmp(mode, mkw->mkw_str, mkw->mkw_len) == 0)
				break;
		}

		if (!mkw->mkw_str) {
			syslog(LOG_DAEMON|LOG_ERR, "invalid keyword %s", mode);
			break;
		}

		mode += mkw->mkw_len;
		
		switch (mkw->mkw_tok) {
		case MKW_TRUNCATE:
			flags |= DB_TRUNCATE;
			break;

		case MKW_MODE:
			errno = 0;
			n = strtoul(mode, &p, 8);
			if (errno || (n & ~0777) || !(*p == 0 || *p == ';')) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "invalid file mode near %s", p);
				mode += strlen(mode);
			} else {
				filemode = n;
				mode = p;
			}
			break;

		case MKW_SYNC:
			errno = 0;
			n = strtoul(mode, &p, 10);
			if (errno || !(*p == 0 || *p == ';')) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "invalid count near %s", p);
				mode += strlen(mode);
			} else {
				autosync_max = n;
				autosync_count = 0;
			}
			break;
		}

		if (*mode == 0)
			break;
		else if (*mode == ';')
			mode++;
		else {
			syslog(LOG_DAEMON|LOG_ERR,
			       "expected ';' near %s", mode);
			break;
		}
	}
	
	rc = db->open(db, NULL, dbname, NULL, DB_HASH, flags, filemode);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot open %s: %s",
		       dbname, db_strerror (rc));
		db->close(db, 0);
		db = NULL;
	}
}

static DB *
tbf_open(const char *mode)
{
	pthread_mutex_lock(&mutex);
	if (!db)
		tbf_open_internal(mode ? mode : "w");
	pthread_mutex_unlock(&mutex);
	return db;
}

int
tbf_init(struct vmod_priv *priv, const struct VCL_conf *vclconf)
{
}

void
vmod_open(struct sess *sp, const char *file_name, const char *mode)
{
	if (db) {
		syslog(LOG_DAEMON|LOG_ERR, "tbf.config called twice");
		return;
	}
	tbf_set_db_name(file_name);
	tbf_open(mode);
}

void
vmod_close(struct sess *sp)
{
	if (db) {
		debug(("closing database %s", dbname));
		db->close(db, 0);
		db = NULL;
	}
}

void
vmod_sync(struct sess *sp)
{
	if (db) {
		debug(("synchronizing database"));
		db->sync(db, 0);
	}
}

/* Algorithm:
   
   * A token is added to the bucket at a constant rate of 1 token per INTERVAL
     microseconds.

   * A bucket can hold at most BURST_SIZE tokens.  If a token arrives when the
     bucket is full, that token is discarded.

   * When COST items of data arrive, COST tokens are removed
     from the bucket and the data are accepted.

   * If fewer than COST tokens are available, no tokens are removed from
     the bucket and the data are not accepted.

   This keeps the data traffic at a constant rate INTERVAL with bursts of
   up to BURST_SIZE data items.  Such bursts occur when no data was being
   arrived for BURST_SIZE*INTERVAL or more microseconds.
*/

struct tbf_bucket {
	uint64_t timestamp;  /* microseconds since epoch */
	size_t tokens;       /* tokens available */
};

unsigned
vmod_rate(struct sess *sp, const char *key, int cost, double t, int burst_size)
{
	DB *db;
	DBT keydat, content;
	struct timeval tv;
	uint64_t now;
	uint64_t elapsed;
	uint64_t tokens;
	struct tbf_bucket *bkt, init_bkt;
	int rc, res;
	unsigned long interval = t * USEC_PER_SEC;
	
	debug(("entering rate(%s,%d,%g,%d)", key, cost, t, burst_size));
		
	if (interval == 0 || burst_size == 0)
		return false;

	if (!cost) {
		/* cost free, so don't waste time on database access */
		return true;
	}
	if (cost > burst_size) {
		/* impossibly expensive, so don't waste time on
		   database access */
		return false;
	}

	db = tbf_open(NULL);

	memset(&keydat, 0, sizeof keydat);
	keydat.data = (void*) key;
	keydat.size = strlen(key);

	gettimeofday(&tv, NULL);
	now = (uint64_t) tv.tv_sec * USEC_PER_SEC + (uint64_t)tv.tv_usec;

	memset(&content, 0, sizeof content);
	content.flags = DB_DBT_MALLOC;
	rc = db->get(db, NULL, &keydat, &content, 0);
	switch (rc) {
	case 0:
		bkt = (struct tbf_bucket *) content.data;
		/* calculate elapsed time and number of new tokens since
		   last add */;
		elapsed = now - bkt->timestamp;
		tokens = elapsed / interval; /* partial tokens ignored */
		/* timestamp set to time of most recent token */
		bkt->timestamp += tokens * interval; 
		
		/* add existing tokens to 64bit counter to prevent overflow
		   in range check */
		tokens += bkt->tokens;
		if (tokens >= burst_size)
			bkt->tokens = burst_size;
		else
			bkt->tokens = (size_t)tokens;
		
		debug(("found, elapsed time: %"PRIu64" us, "
		       "new tokens: %"PRIu64", total: %lu ",
		       elapsed, tokens, (unsigned long) bkt->tokens));
		break;

	case DB_NOTFOUND:
		/* Initialize the structure */
		init_bkt.timestamp = now;
		init_bkt.tokens = burst_size;
		bkt = &init_bkt;
		break;

	default:
		syslog(LOG_DAEMON|LOG_ERR, "cannot fetch data %s: %s",
		       key, db_strerror(rc));
		return false;
	}

	if (cost <= bkt->tokens) {
		res = 1;
		bkt->tokens -= cost;
		debug(("tbf_rate matched %s", key));
	} else {
		res = 0;
		debug(("tbf_rate overlimit on %s", key));
	}

	/* Update the db */
	content.data = (void*) bkt;
	content.size = sizeof(*bkt);

	rc = db->put (db, NULL, &keydat, &content, 0);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "error updating key %s: %s",
		       key, db_strerror(rc));
	}

	if (bkt != &init_bkt)
		free(bkt);

	if (autosync_max && ++autosync_count >= autosync_max) {
		debug(("synchronizing database"));
		db->sync(db, 0);
		autosync_count = 0;
	}
	
	return res;
}
