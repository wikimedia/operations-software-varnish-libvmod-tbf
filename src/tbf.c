/* This file is part of vmod-tbf
   Copyright (C) 2013-2014 Sergey Poznyakoff
  
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
#include "tbf.h"
#include "vsha256.h"

#ifndef USEC_PER_SEC
# define USEC_PER_SEC  1000000L
#endif

#define DEBUG 1
static unsigned gc_interval = 3600;
static int debug_level = 0;

static void
debugprt(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_DAEMON|LOG_DEBUG, fmt, ap);
	va_end(ap);
}
#define debug(n,c) do { if (debug_level>=(n)) debugprt c; } while (0)

enum { CHILD_LEFT, CHILD_RIGHT };

struct node {
	uint8_t key[SHA256_LEN];
#ifdef DEBUG
	char *keystr;
#endif
	struct node *parent;
	struct node *child[2];
	struct node *prev, *next;
	pthread_cond_t notbusy;
	int busy;
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
};

/* Linked list management */

/* Link NODE after REF in TREE.  If REF is NULL, link at head */
static void
lru_link_node(struct tree *tree, struct node *node, struct node *ref)
{
	if (!ref) {
		node->prev = NULL;
		node->next = tree->head;
		if (tree->head)
			tree->head->prev = node;
		else
			tree->tail = node;
		tree->head = node;
	} else {
		struct node *x;

		node->prev = ref;
		if ((x = ref->next))
			x->prev = node;
		else
			tree->tail = node;
		ref->next = node;
	}
}

static void
lru_unlink_node(struct tree *tree, struct node *node)
{
	struct node *x;

	debug(1,("UNLINK %p %p\n", node, node->prev, node->next));

	if ((x = node->prev))
		x->next = node->next;
	else
		tree->head = node->next;
	if ((x = node->next))
		x->prev = node->prev;
	else
		tree->tail = node->prev;
	node->prev = node->next = NULL;
}

static int
keycmp(uint8_t *a, uint8_t *b)
{
	return memcmp(a, b, SHA256_LEN);
}

static void
keycpy(uint8_t *a, uint8_t *b)
{
	memcpy(a, b, SHA256_LEN);
}

static void
key_create(char const *input, uint8_t key[])
{
	struct SHA256Context ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, strlen (input));
	SHA256_Final(key, &ctx);
}

static void
node_lock(struct tree *tree, struct node *node)
{
	if (node->busy) {
		pthread_cond_wait(&node->notbusy, &tree->mutex);
		node->busy = 1;
	}
}

static void
node_unlock(struct node *node)
{
	node->busy = 0;
	pthread_cond_broadcast(&node->notbusy);
}

enum node_lookup_result {
	NODE_FOUND,
	NODE_NEW
};

static int
tree_lookup_node(struct tree *tree, uint8_t key[], struct node **ret)
{
	int res;
	struct node *node, *parent = NULL;
	struct node **nodeptr;
	
 	pthread_mutex_lock(&tree->mutex);

	nodeptr = &tree->root;
	while ((node = *nodeptr) != NULL) {
		res = keycmp(key, node->key);
		if (res == 0)
			break;
		parent = node;
		nodeptr = &node->child[res > 0];
	}

	if (node) {
		node_lock(tree, node);
		lru_unlink_node(tree, node);
		res = NODE_FOUND;
	} else {
		node = calloc(1, sizeof(*node));
		AN(node);
		node->parent = parent;
		keycpy(node->key, key);
		pthread_cond_init(&node->notbusy, NULL);
		node->busy = 1;
		*nodeptr = node;
		debug(2, ("%x: allocated new node %p", pthread_self(), node));
		res = NODE_NEW;
	}
	lru_link_node(tree, node, NULL);
	*ret = node;
 	pthread_mutex_unlock(&tree->mutex);
//	debug(0, ("head: %p, root: %p", tree->head, tree->root));
	return res;
}

static void
node_free(struct node *node)
{
#ifdef DEBUG
	free(node->keystr);
#endif
	pthread_cond_destroy(&node->notbusy);
	free(node);
}

static void
tree_delete_node_unlocked(struct tree *tree, struct node *node)
{
	struct node *parent = node->parent;
	struct node **slot;

	if (!parent)
		slot = &tree->root;
	else if (node == parent->child[CHILD_LEFT])
		slot = &parent->child[CHILD_LEFT];
	else
		slot = &parent->child[CHILD_RIGHT];
	
	if (!node->child[CHILD_LEFT]) {
		/* No left subtree: link the right subtree to the parent slot */
		*slot = node->child[CHILD_RIGHT];
		if (node->child[CHILD_RIGHT])
			node->child[CHILD_RIGHT]->parent = parent;
	} else if (!node->child[CHILD_RIGHT]) {
		/* No right subtree: link the left subtree to the parent slot */
		*slot = node->child[CHILD_LEFT];
		if (node->child[CHILD_LEFT])
			node->child[CHILD_LEFT]->parent = parent;
	} else {
		/* Node has both subtrees. Find the largest value in the
		   right subtree */
		struct node *p;
		for (p = node->child[CHILD_LEFT]; p->child[CHILD_RIGHT];
		     p = p->child[CHILD_RIGHT])
			;

		p->child[CHILD_RIGHT] = node->child[CHILD_RIGHT];
		p->child[CHILD_RIGHT]->parent = p;

		*slot = node->child[CHILD_LEFT];
		node->child[CHILD_LEFT]->parent = parent;
	}
	lru_unlink_node(tree, node);
}

/* Dispose of tree nodes that were last accessed TIMEOUT seconds ago or
   earlier */
void
tree_gc(struct tree *tree, time_t timeout)
{
	struct node *p;
	uint64_t t;

	pthread_mutex_lock(&tree->mutex);
	t = (uint64_t) (time(NULL) - timeout) * USEC_PER_SEC;
	debug(1,("gc till %"PRIu64, t));
	while ((p = tree->tail) && p->timestamp < t) {
#ifdef DEBUG
		debug(1,("deleting %s", tree->tail->keystr));
		debug(1,("%p %p %p\n", tree->head, tree->tail, tree->tail->prev));
#endif
		node_lock(tree, p);
		tree_delete_node_unlocked(tree, p);
		node_unlock(p);
		node_free(p);
		debug(1,("%p %p\n", tree->head, tree->tail));
	}
	pthread_mutex_unlock(&tree->mutex);
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

int
tbf_proc(struct tree *tree, const char *keystr, int cost,
	 unsigned long interval, int burst_size)
{
	uint8_t key[SHA256_LEN];
	struct node *node = NULL;
	struct timeval tv;
	uint64_t now;
	uint64_t elapsed;
	uint64_t tokens;
	int res;

	key_create(keystr, key);

	gettimeofday(&tv, NULL);
	now = (uint64_t) tv.tv_sec * USEC_PER_SEC + (uint64_t)tv.tv_usec;

	switch (tree_lookup_node(tree, key, &node)) {
	case NODE_FOUND:
		/* calculate elapsed time and number of new tokens since
		   last add */;
		elapsed = now - node->timestamp;
		tokens = elapsed / interval; /* partial tokens ignored */
		/* timestamp set to time of most recent token */
		node->timestamp += tokens * interval; 
		
		/* add existing tokens to 64bit counter to prevent overflow
		   in range check */
		tokens += node->tokens;
		if (tokens >= burst_size)
			node->tokens = burst_size;
		else
			node->tokens = (size_t)tokens;
		
		debug(2, ("%x: found, elapsed time: %"PRIu64" us, "
			  "new tokens: %"PRIu64", total: %lu ",
			  pthread_self(),
			  elapsed, tokens, (unsigned long) node->tokens));
		break;

	case NODE_NEW:
		/* Initialize the structure */
#ifdef DEBUG
		node->keystr = strdup(keystr);
#endif
		node->timestamp = now;
		node->tokens = burst_size;
	}

	if (cost <= node->tokens) {
		res = 1;
		node->tokens -= cost;
		debug(2, ("%x: tbf_rate matched %s, tokens left %lu",
			  pthread_self(), keystr,
			  (unsigned long) node->tokens));
	} else {
		res = 0;
		debug(1, ("%x: tbf_rate overlimit on %s",
			  pthread_self(), keystr));
	}
	node_unlock(node);
	debug(1, ("tbf_proc: return"));
	return res;
}

struct tree *
tree_create(void)
{
	struct tree *tree = calloc(1, sizeof(*tree));
	AN(tree);
	pthread_mutex_init(&tree->mutex, NULL);
	return tree;
}

void
tree_free(void *data)
{
	struct tree *tree = data;
	struct node *p;

 	pthread_mutex_lock(&tree->mutex);
	while ((p = tree->tail)) {
		node_lock(tree, p);
		lru_unlink_node(tree, p);
		node_unlock(p);
		node_free(p);
	}
	pthread_mutex_unlock(&tree->mutex);
	pthread_mutex_destroy(&tree->mutex);
	free(tree);
}

int
tbf_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	switch (e) {
	case VCL_EVENT_LOAD:
		priv->priv = tree_create();
		priv->free = tree_free;
		break;

	case VCL_EVENT_DISCARD:
		break;

	default:
		/* ignore */
		break;
	}
	return 0;
}

struct tree *
get_tree(struct vmod_priv *priv)
{
	return priv->priv;
}

VCL_VOID
vmod_debug(VRT_CTX, VCL_INT newval)
{
	debug_level = newval;
}

VCL_VOID
vmod_set_gc_interval(VRT_CTX, VCL_REAL interval)
{
	gc_interval = interval;
}

VCL_VOID
vmod_gc(VRT_CTX, struct vmod_priv *priv, VCL_REAL interval)
{
	tree_gc(get_tree(priv), interval);
}

VCL_BOOL
vmod_rate(VRT_CTX, struct vmod_priv *priv,
	  VCL_STRING key, VCL_INT cost, VCL_REAL t,
	  VCL_INT burst_size)
{
	struct tree *tree = get_tree(priv);
	unsigned long interval = t * USEC_PER_SEC;
	
	debug(2, ("%x: entering rate(%s,%d,%g,%d)",
		  pthread_self(), key, cost, t, burst_size));
		
	if (interval == 0 || burst_size == 0)
		return false;

	tree_gc(tree, gc_interval);

	if (!cost) {
		/* cost free, so don't waste time on tree lookup */
		return true;
	}
	if (cost > burst_size) {
		/* impossibly expensive, so don't waste time on
		   tree lookup */
		return false;
	}

	return tbf_proc(tree, key, cost, interval, burst_size);
}

#define ISWS(c) ((c)==' '||(c)=='\t')

VCL_BOOL
vmod_check(VRT_CTX, struct vmod_priv *priv,
	   VCL_STRING key, VCL_STRING spec)
{
	double v, n;
	char *p;
#define SKIPWS(init) for (init; *spec && ISWS(*spec); spec++)
	
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

	return vmod_rate(ctx, priv, key, 1, n/v, v/n+1);
}

static char xdig[] = "0123456789abcdef";
	
static void
key_to_str(uint8_t key[], char *buf)
{
	size_t i;

	for (i = 0; i < SHA256_LEN; i++) {
		*buf++ = xdig[key[i] >> 4];
		*buf++ = xdig[key[i] & 0xf];
	}
	*buf = 0;
}

static void
node_to_keystr(struct node *node, char *buf)
{
	if (node)
		key_to_str(node->key, buf);
	else
		*buf = 0;
}

VCL_VOID
vmod_dump(VRT_CTX, struct vmod_priv *priv, VCL_STRING file)
{
	struct tree *tree = get_tree(priv);
	struct node *node;
	char keybuf[3][2*SHA256_LEN+1];
	FILE *fp;
	int err = 0;
	
	fp = fopen(file, "w");
	if (!fp) {
		syslog(LOG_DAEMON|LOG_ERR,
		       "tbf.dump: can't open file %s for output: %m", file);
		return;
	}
 	pthread_mutex_lock(&tree->mutex);
	if (tree->root) {
		node_to_keystr(tree->root, keybuf[0]);
		fprintf(fp, "%s\n", keybuf[0]);
	}
	for (node = tree->head; node; node = node->next) {
		node_to_keystr(node, keybuf[0]);
		node_to_keystr(node->child[CHILD_LEFT], keybuf[1]);
		node_to_keystr(node->child[CHILD_RIGHT], keybuf[2]);
#ifdef DEBUG
		fprintf(fp, "# %s\n", node->keystr);
#endif
		fprintf(fp, "%s:%s:%s:%"PRIu64":%lu\n",
			keybuf[0], keybuf[1], keybuf[2],
			node->timestamp, (unsigned long)node->tokens);
		if (ferror(fp)) {
			syslog(LOG_DAEMON|LOG_ERR,
			       "tbf.dump: error writing to %s: %m", file);
			err = 1;
			break;
		}
	}
 	pthread_mutex_unlock(&tree->mutex);
	fclose(fp);
	if (err)
		unlink(file);
}
