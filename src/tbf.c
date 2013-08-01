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
#include <sys/stat.h>
#include <db.h>
#include "vrt.h"
#include "vcc_if.h"
#include "bin/varnishd/cache.h"

static int debug_level;

static void
debugprt(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_DAEMON|LOG_DEBUG, fmt, ap);
	va_end(ap);
}
#define debug(n,c) do { if (debug_level>=(n)) debugprt c; } while (0)

#ifndef USEC_PER_SEC
# define USEC_PER_SEC  1000000L
#endif

#define DEFDBNAME "tbf.bdb"
#define DEFOPENPARAMS "truncate"
#define DBFILEMODE 0640

static char *dbdir;
static char *dbname;
static DB_ENV *dbenv;
static DB *db;
static uint64_t autosync_max;
static uint64_t autosync_count;
static int tbf_disabled;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


/* The keylock structure serializes accesses to each db record, ensuring
   that no other thread could modify the data between calls to get and
   put */
   
struct keylock {
	char *key;                   /* Key string */
	unsigned refcnt;             /* Reference count */
	pthread_mutex_t mutex;        
	VTAILQ_ENTRY(keylock) list;
};

/* Keylock_head keeps a list of active (i.e. used by at least one thread)
   keylocks.  Keylock_avail keeps a list of available threads, to avoid
   unnecessary memory allocations/frees. */
static VTAILQ_HEAD(, keylock) keylock_head, keylock_avail;

/* Find and return a keylock corresponding to the given key.  If not found,
   create it, either by getting an unused entry from keylock_avail or by
   allocating a new one. */
static struct keylock *
keylock_find(const char *key)
{
	struct keylock *kp;
	
	VTAILQ_FOREACH(kp, &keylock_head, list) {
		if (strcmp(kp->key, key) == 0) {
			kp->refcnt++;
			return kp;
		}
	}

	if (VTAILQ_FIRST(&keylock_avail)) {
		kp = VTAILQ_FIRST(&keylock_avail);
		VTAILQ_REMOVE(&keylock_avail, kp, list);
	} else {
		kp = malloc(sizeof(*kp));
		AN(kp);
		pthread_mutex_init(&kp->mutex, NULL);
	}
	kp->key = strdup(key);
	AN(kp->key);
	kp->refcnt = 1;
	VTAILQ_INSERT_TAIL(&keylock_head, kp, list);
	return kp;
}

/* Thread-safe version of the above. */
static struct keylock *
keylock_find_safe(const char *key)
{
	struct keylock *kp;
	pthread_mutex_lock(&mutex);
	kp = keylock_find(key);
	pthread_mutex_unlock(&mutex);
	return kp;
}

/* Remove keylock from keylock_head and attach it to keylock_avail for
   eventual future use. */
static void
keylock_remove_safe(struct keylock *kp)
{
	pthread_mutex_lock(&mutex);
	free(kp->key);
	kp->key = NULL;
	VTAILQ_REMOVE(&keylock_head, kp, list);
	VTAILQ_INSERT_TAIL(&keylock_avail, kp, list);
	pthread_mutex_unlock(&mutex);
}

static void
tbf_set_db_dir(const char *dir)
{
	if (dbdir)
		free(dbdir);
	dbdir = strdup(dir);
	AN(dbdir);
}

struct param_kw {
	char *pkw_str;
	int pkw_len;
	int pkw_tok;
};

enum {
	PKW_TRUNCATE,
	PKW_MODE,
	PKW_SYNC,
	PKW_DEBUG,
	PKW_DBNAME
};

static struct param_kw param_kw_tab[] = {
#define S(s) #s, sizeof(#s)-1
	{ S(truncate), PKW_TRUNCATE },
	{ S(trunc), PKW_TRUNCATE },
	{ S(mode=), PKW_MODE },
	{ S(sync=), PKW_SYNC },
	{ S(debug=), PKW_DEBUG },
	{ S(dbname=), PKW_DBNAME },
	{ NULL }
#undef S
};

static void
tbf_open(const char *params)
{
	int rc;
	int filemode = DBFILEMODE;
	uint64_t n;
	char *p;
	struct stat st;
	int truncate = 0;
	
	if (!dbdir) {
		dbdir = strdup(LOCALSTATEDIR "/vmod-tbf");
		AN(dbdir);
	}
	if (!dbname) {
		dbname = strdup(DEFDBNAME);
		AN(dbname);
	}
	
	while (*params) {
		struct param_kw *pkw;
		
		for (pkw = param_kw_tab; pkw->pkw_str; pkw++) {
			if (strncmp(params, pkw->pkw_str, pkw->pkw_len) == 0)
				break;
		}

		if (!pkw->pkw_str) {
			syslog(LOG_DAEMON|LOG_ERR, "invalid keyword %s", params);
			break;
		}

		params += pkw->pkw_len;
		
		switch (pkw->pkw_tok) {
		case PKW_TRUNCATE:
			truncate = 1;
			break;

		case PKW_MODE:
			errno = 0;
			n = strtoul(params, &p, 8);
			if (errno || (n & ~0777) || !(*p == 0 || *p == ';')) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "invalid file mode near %s", p);
				params += strlen(params);
			} else {
				filemode = n;
				params = p;
			}
			break;

		case PKW_SYNC:
			errno = 0;
			n = strtoul(params, &p, 10);
			if (errno || !(*p == 0 || *p == ';')) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "invalid count near %s", p);
				params += strlen(params);
			} else {
				autosync_max = n;
				autosync_count = 0;
				params = p;
			}
			break;

		case  PKW_DEBUG:
			errno = 0;
			n = strtoul(params, &p, 10);
			if (errno || !(*p == 0 || *p == ';')) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "invalid debug level near %s", p);
				params += strlen(params);
			} else {
				debug_level = n;
				params = p;
			}
			break;

		case PKW_DBNAME:
			if (dbname)
				free(dbname);
			n = strcspn(params, ";");
			dbname = malloc(n + 1);
			AN(dbname);
			memcpy(dbname, params, n);
			dbname[n] = 0;
			params += n;
			break;
		}

		if (*params == 0)
			break;
		else if (*params == ';')
			params++;
		else {
			syslog(LOG_DAEMON|LOG_ERR,
			       "expected ';' near %s", params);
			break;
		}
	}
	
	debug(1, ("opening database %s/%s", dbdir, dbname));

	if (rc = db_env_create(&dbenv, 0)) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot create db environment: %s",
		       db_strerror(rc));
		return;
	}

	if (stat(dbdir, &st)) {
		if (errno == ENOENT) {
			if (mkdir(dbdir,
				  filemode | 0100 |
				  ((filemode & 0060) ? 0010 : 0) |
				  ((filemode & 0006) ? 0001 : 0))) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "cannot create db environment directory %s: %m",
				       dbdir);
			}
		} else {
			syslog(LOG_DAEMON|LOG_ERR,
			       "cannot stat db environment directory %s: %m",
			       dbdir);
			return;
		}
	} else if (!S_ISDIR(st.st_mode)) {
		syslog(LOG_DAEMON|LOG_ERR, "%s is not a directory",
		       dbdir);
		return;
	}
	
	rc = dbenv->open(dbenv, dbdir,
			 DB_THREAD | DB_CREATE | DB_INIT_MPOOL | DB_INIT_CDB,
			 0);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot open db environment %s: %s",
		       dbdir, db_strerror(rc));
		tbf_disabled = 1;
		return;
	}
	
	rc = db_create(&db, dbenv, 0);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot create db struct");
		return;
	}

	rc = db->open(db, NULL, dbname, NULL, DB_HASH,
		      DB_THREAD | DB_CREATE, filemode);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "cannot open database %s: %s",
		       dbname, db_strerror (rc));
		db->close(db, 0);
		db = NULL;
		dbenv->close(dbenv, 0);
		dbenv = NULL;
		tbf_disabled = 1;
	}

	if (truncate) {
		rc = db->truncate(db, NULL, NULL, 0);
		if (rc)
			syslog(LOG_DAEMON|LOG_WARNING,
			       "failed to truncate database %s: %s",
			       dbname, db_strerror(rc));
	}	
}

static DB *
tbf_open_safe(const char *params)
{
	if (tbf_disabled)
		return NULL;
	pthread_mutex_lock(&mutex);
	if (!db)
		tbf_open(params ? params : DEFOPENPARAMS);
	pthread_mutex_unlock(&mutex);
	return db;
}

int
tbf_init(struct vmod_priv *priv, const struct VCL_conf *vclconf)
{
	VTAILQ_INIT(&keylock_head);
	VTAILQ_INIT(&keylock_avail);
}

void
vmod_open(struct sess *sp, const char *dir, const char *params)
{
	if (db) {
		syslog(LOG_DAEMON|LOG_ERR, "tbf.open called twice");
		return;
	}
	tbf_set_db_dir(dir);
	tbf_open_safe(params);
}

void
vmod_close(struct sess *sp)
{
	pthread_mutex_lock(&mutex);
	if (db) {
		debug(1, ("closing database %s", dbname));
		db->close(db, 0);
		db = NULL;
		dbenv->close(dbenv, 0);
		dbenv = NULL;
		tbf_disabled = 0;
	}
	pthread_mutex_unlock(&mutex);
}

void
vmod_sync(struct sess *sp)
{
	if (db) {
		debug(1, ("synchronizing database"));
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

int
tbf_proc(struct sess *sp, DB *db, const char *key, int cost,
	 unsigned long interval, int burst_size)
{
	DBT keydat, content;
	struct timeval tv;
	uint64_t now;
	uint64_t elapsed;
	uint64_t tokens;
	struct tbf_bucket *bkt, init_bkt;
	int rc, res;

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
		
		debug(2, ("found, elapsed time: %"PRIu64" us, "
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
		debug(2, ("tbf_rate matched %s, tokens left %lu", key,
			  (unsigned long)bkt->tokens));
	} else {
		res = 0;
		debug(1, ("tbf_rate overlimit on %s", key));
	}

	/* Update the db */
	content.data = (void*) bkt;
	content.size = sizeof(*bkt);

	rc = db->put(db, NULL, &keydat, &content, 0);
	if (rc) {
		syslog(LOG_DAEMON|LOG_ERR, "error updating key %s: %s",
		       key, db_strerror(rc));
	}

	if (bkt != &init_bkt)
		free(bkt);

	if (autosync_max && ++autosync_count >= autosync_max) {
		debug(1, ("synchronizing database"));
		db->sync(db, 0);
		autosync_count = 0;
	}
	
	return res;
}

unsigned
vmod_rate(struct sess *sp, const char *key, int cost, double t, int burst_size)
{
	unsigned long interval = t * USEC_PER_SEC;
	int rc;
	
	debug(2, ("entering rate(%s,%d,%g,%d)", key, cost, t, burst_size));
		
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

	db = tbf_open_safe(NULL);
	if (db) {
		struct keylock *kp;

		kp = keylock_find_safe(key);
		debug(2, ("found key %s, ref %u", key, kp->refcnt));
		AZ(pthread_mutex_lock(&kp->mutex));
		rc = tbf_proc(sp, db, key, cost, interval, burst_size);
		if (--kp->refcnt == 0)
			keylock_remove_safe(kp);
		AZ(pthread_mutex_unlock(&kp->mutex));
	} else
		rc = false;
       
	return rc;
}

#define ISWS(c) ((c)==' '||(c)=='\t')

unsigned
vmod_check(struct sess *sp, const char *key, const char *spec)
{
	double t, v, n;
	char *p;
#define SKIPWS(init) for (init; *spec && ISWS(*spec); spec++)
	int burst;
	
	errno = 0;
	v = strtod(spec, &p);
	if (errno || v < 0) {
		syslog(LOG_DAEMON|LOG_ERR, "bad rate: %s", spec);
		return false;
	}
	SKIPWS(spec = p);
	if (strncmp(spec, "req", 3)) {
		syslog(LOG_DAEMON|LOG_ERR,
		       "bad rate: expected \"req\", but found \"%s\"", spec);
		return false;
	}
	SKIPWS(spec += 3);
	if (*spec != '/') {
		syslog(LOG_DAEMON|LOG_ERR,
		       "bad rate: expected \"/\", but found \"%c\"", *spec);
		return false;
	}
	SKIPWS(++spec);
	if (*spec >= '0' && *spec <= '9') {
		errno = 0;
		n = strtod(spec, &p);
		if (errno || n < 0) {
			syslog(LOG_DAEMON|LOG_ERR, "bad interval: %s", spec);
			return false;
		}
		spec = p;
	} else
		n = 1;
	SKIPWS();

	switch (*spec) {
	case 0:
	case 's':
		break;
	case 'd':
		n *= 24;
	case 'h':
		n *= 60;
	case 'm':
		n *= 60;
		break;
	default:
		syslog(LOG_DAEMON|LOG_ERR, "invalid interval specifier: %s",
		       spec);
		return false;
	}

	SKIPWS(++spec);

	if (*spec)
		syslog(LOG_DAEMON|LOG_WARNING, "garbage after rate spec: %s",
		       spec);

	return vmod_rate(sp, key, 1, n/v, v/n+1);
}
