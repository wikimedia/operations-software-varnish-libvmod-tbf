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
#include "tbf.h"

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
		//debug(0, ("LINK %p %p %p", node, ref, ref->next));
		node->prev = ref;
		node->next = ref->next;
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

static struct node *
node_alloc(uint8_t key[], struct node *parent)
{
	static struct node *node;
	
	node = calloc(1, sizeof(*node));
	AN(node);
	node->parent = parent;
	keycpy(node->key, key);
	pthread_cond_init(&node->notbusy, NULL);
	node->busy = 1;
	node->status = NST_INCOMPLETE;
//	debug(2, ("%x: allocated new node %p", pthread_self(), node));
	return node;
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
	if (node->busy) {
		node->busy = 0;
		pthread_cond_broadcast(&node->notbusy);
	}
}

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
		node = node_alloc(key, parent);
		*nodeptr = node;
		res = NODE_NEW;
	}
	lru_link_node(tree, node, NULL);
	*ret = node;
 	pthread_mutex_unlock(&tree->mutex);
//	debug(2, ("head: %p, root: %p", tree->head, tree->root));
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
	size_t count = 0;
	
	pthread_mutex_lock(&tree->mutex);
	t = (uint64_t) (time(NULL) - timeout) * USEC_PER_SEC;
	debug(1,("gc till %"PRIu64, t));
	while ((p = tree->tail) && p->timestamp < t) {
#ifdef DEBUG
		debug(1,("deleting %s", tree->tail->keystr));
#endif
		node_lock(tree, p);
		tree_delete_node_unlocked(tree, p);
		node_unlock(p);
		node_free(p);
		++count;
	}
	debug(1,("gc removed %lu nodes", count));
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

static int
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
		
		debug(2, ("found, elapsed time: %"PRIu64" us, "
			  "new tokens: %"PRIu64", total: %lu",
			  elapsed, tokens, (unsigned long) node->tokens));
		break;

	case NODE_NEW:
		/* Initialize the structure */
		node->status = NST_INIT;
#ifdef DEBUG
		node->keystr = strdup(keystr);
#endif
		node->timestamp = now;
		node->tokens = burst_size;
	}

	if (cost <= node->tokens) {
		res = 1;
		node->tokens -= cost;
		debug(2, ("tbf_rate matched %s, tokens left %lu",
			  keystr,
			  (unsigned long) node->tokens));
	} else {
		res = 0;
		debug(1, ("tbf_rate overlimit on %s", keystr));
	}
	node_unlock(node);
	debug(1, ("tbf_proc: return"));
	return res;
}

static void tree_ref(struct tree *tree);

static struct tree *
tree_create(void)
{
	struct tree *tree = calloc(1, sizeof(*tree));
	AN(tree);
	pthread_mutex_init(&tree->mutex, NULL);
	tree_ref(tree);
	return tree;
}

static void
tree_ref(struct tree *tree)
{
	pthread_mutex_lock(&tree->mutex);
	tree->refcnt++;
	pthread_mutex_unlock(&tree->mutex);
}

static void
tree_destroy(struct tree **tree_ptr)
{
	struct tree *tree = *tree_ptr;
	struct node *p;

 	pthread_mutex_lock(&tree->mutex);
	*tree_ptr = NULL;
	
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

static void
tree_unref(struct tree **ptree)
{
	struct tree *tree = *ptree;
	
	pthread_mutex_lock(&tree->mutex);
	AN(tree->refcnt);
	if (--tree->refcnt == 0)
		*ptree = NULL;
	pthread_mutex_unlock(&tree->mutex);
	if (tree->refcnt == 0)
		tree_destroy(&tree);
}

static struct node *
node_postorder_first(struct node *node)
{
	uint32_t n = node->ord;
	
	while (1) {
		if (node->child[CHILD_LEFT])
			node = node->child[CHILD_LEFT];
		else if (node->child[CHILD_RIGHT])
			node = node->child[CHILD_RIGHT];
		else
			break;
		node->ord = ++n;
	}
	return node;
}

static struct node *
node_postorder_next(struct node *node)
{
	AN(node->parent);
	if (node == node->parent->child[CHILD_RIGHT])
		return node->parent;
	if (node == node->parent->child[CHILD_LEFT]) {
		if (node->parent->child[CHILD_RIGHT]) {
			node->parent->child[CHILD_RIGHT]->ord = node->parent->ord + 1;
			return node_postorder_first(node->parent->child[CHILD_RIGHT]);
		} else
			return node->parent;
	}
	/* should not happen */
	abort();
}

static void
tree_traverse_postorder(struct tree *tree,
			void (*visit)(struct node *, void *data),
			void *data)
{
	struct node *node;
	pthread_mutex_lock(&tree->mutex);
	tree->root->ord = 1;
	node = node_postorder_first(tree->root);
	visit(node, data);
	while (node != tree->root) {
		node = node_postorder_next(node);
		visit(node, data);
	}
 	pthread_mutex_unlock(&tree->mutex);
}
#if 0
static void
node_traverse_postorder(struct node *node,
			void (*visit)(struct node *, void *data),
			void *data)
{
	if (!node) return;
	node_traverse_postorder(node->child[CHILD_LEFT], visit, data);
	node_traverse_postorder(node->child[CHILD_RIGHT], visit, data);
	visit(node, data);
}

static void
tree_traverse_postorder(struct tree *tree,
			void (*visit)(struct node *, void *data),
			void *data)
{
	node_traverse_postorder(tree->root, visit, data);
}
#endif

struct tree_stats
{
	uint32_t len_sum;
	uint32_t num_nodes;
	uint32_t num_leaves;
	uint32_t shortest_path;
	uint32_t longest_path;
	double avg_path;
};

static void
node_compute_stats(struct node *node, void *data)
{
	struct tree_stats *st = data;
	st->num_nodes++;
	if (!node->child[CHILD_LEFT] && !node->child[CHILD_RIGHT]) {
		st->num_leaves++;
		st->len_sum += node->ord;
		if (node->ord > st->longest_path)
			st->longest_path = node->ord;
		if (node->ord < st->shortest_path)
			st->shortest_path = node->ord;
	}
}

void
tree_compute_stats(struct tree *tree, struct tree_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->shortest_path = tree->root != NULL ? (uint32_t)-1 : 0;
	tree_traverse_postorder(tree, node_compute_stats, st);
	if (st->num_leaves)
		st->avg_path = (double) st->len_sum / st->num_leaves;
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

static void
node_dump_ord(struct node *node, FILE *fp)
{
	uint32_t *p;
		  
	if (node) 
		p = &node->ord;
	else {
		uint32_t t = 0;
		p = &t;
	} 
	fwrite(p, sizeof(*p), 1, fp);
}

#define ELSIZE(m) sizeof(((struct node*)0)->m)
#define RECSIZE (3*ELSIZE(key) + ELSIZE(timestamp) + ELSIZE(tokens))
		 
static void
node_dump(struct node *node, FILE *fp)
{
	uint32_t len = 1;
	uint32_t flags = 0;
	
#ifdef DEBUG
	len += (strlen(node->keystr) + RECSIZE) / RECSIZE;
#endif
	fwrite(&len, sizeof(len), 1, fp);
	if (node->child[CHILD_LEFT])
		flags |= FL_CHILD_LEFT;
	if (node->child[CHILD_RIGHT])
		flags |= FL_CHILD_RIGHT;
	fwrite(&flags, sizeof(flags), 1, fp);
	
	fwrite(&node->key, sizeof(node->key), 1, fp);
	node_dump_ord(node->child[CHILD_LEFT], fp);
	node_dump_ord(node->child[CHILD_RIGHT], fp);
	fwrite(&node->timestamp, sizeof(node->timestamp), 1, fp);
	fwrite(&node->tokens, sizeof(node->tokens), 1, fp);
#ifdef DEBUG
	fwrite(node->keystr, strlen(node->keystr), 1, fp);
	len = RECSIZE - (strlen(node->keystr) + RECSIZE) % RECSIZE;
	if (len) {
		char c = 0;
		fseek(fp, len-1, SEEK_CUR);
		fputc(c, fp);
	}
#endif
}

static void
tree_dump_unlocked(struct tree *tree, char const *file)
{
	struct node *node;
	char keybuf[3][2*SHA256_LEN+1];
	FILE *fp;
	int err = 0;
	struct dump_header header;

	fp = fopen(file, "w");
	if (!fp) {
		syslog(LOG_DAEMON|LOG_ERR,
		       "tbf.dump: can't open file %s for output: %m", file);
		return;
	}

	header.version = DUMP_VERSION;
#ifdef DEBUG
	header.debug = 1;
#else	
	header.debug = 0;
#endif
	header.size = RECSIZE;
	header.count = 0;
	
	/* Count nodes */
	for (node = tree->head; node; node = node->next)
		node->ord = header.count++;
	if (tree->root)
		header.root = tree->root->ord;
	fwrite(&header, sizeof(header), 1, fp);
	for (node = tree->head; node; node = node->next) {
		node_dump(node, fp);
		if (ferror(fp)) {
			syslog(LOG_DAEMON|LOG_ERR,
			       "tbf.dump: error writing to %s: %m", file);
			err = 1;
			break;
		}
	}
	fclose(fp);
	if (err)
		unlink(file);
}

static void
tree_dump(struct tree *tree, char const *file)
{
	if (tree) {
		pthread_mutex_lock(&tree->mutex);
		tree_dump_unlocked(tree, file);
		pthread_mutex_unlock(&tree->mutex);
	}
}

static int
readrec(FILE *fp, void *buf, size_t size)
{
	switch (fread(buf, size, 1, fp)) {
	case 1:
		break;
	case -1:
		syslog(LOG_DAEMON|LOG_ERR, "tbf.%s: read error: %s",
		       __FUNCTION__, strerror(errno));
		return -1;
	default:
		syslog(LOG_DAEMON|LOG_ERR, "tbf.%s: unexpected EOF",
		       __FUNCTION__);
		return -1;
	}
	return 0;
}

#define READREC(f,r) readrec(f, &(r), sizeof(r))

struct node *
new_node(struct node **nodes, struct dump_header *hdr,
	 uint32_t ord, struct node *parent)
{
	struct node *child;
	
	if (ord >= hdr->count)
		return NULL;
	
	if (nodes[ord]) {
		child = nodes[ord];
		child->parent = parent;
	} else {
		static uint8_t null_key[SHA256_LEN];
		
		child = node_alloc(null_key, parent);
		nodes[ord] = child;
	}
	return child;
}

int
tree_load_nodes(struct tree *tree, struct dump_header *hdr,
		struct node **nodes, FILE *fp)
{
	size_t i;
	uint32_t root_idx;
	uint32_t ord[2];
	size_t incomplete = 0;
	
	for (i = 0; i < hdr->count; i++) {
		struct node node, *np;
		uint32_t len;
		uint32_t flags;
		
		debug(0,("Load record %lu/%lu %lu", i, hdr->count, incomplete));

		if (READREC(fp, len))
			return -1;
		if (READREC(fp, flags))
			return -1;
		if (READREC(fp, node.key))
			return -1;
		if (READREC(fp, ord[CHILD_LEFT]))
			return -1;
		if (READREC(fp, ord[CHILD_RIGHT]))
			return -1;
		if (READREC(fp, node.timestamp))
			return -1;
		if (READREC(fp, node.tokens))
			return -1;

		if (--len) {
#ifdef DEBUG
			char *p, *recbuf = malloc(len * hdr->size);
			AN(recbuf);
			p = recbuf;
			while (len--) {
				if (readrec(fp, p, hdr->size)) {
					free(recbuf);
					return -1;
				}
				p += hdr->size;
			}
			node.keystr = recbuf;
#else
			fseek(fp, len * hdr->size, SEEK_SET);
#endif
		}

		if (nodes[i]) {
			np = nodes[i];
			if (np->status == NST_INIT) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "tbf.%s: duplicate node",
				       __FUNCTION__);
#if DEBUG
				free(node.keystr);
#endif
				return -1;
			} else {
				--incomplete;
				keycpy(np->key, node.key);
			}
		} else {
			np = node_alloc(node.key, NULL);
			np->status = NST_INIT;
			node_unlock(np);
			nodes[i] = np;
		}
		np->timestamp = node.timestamp;
		np->tokens = node.tokens;
#if DEBUG
		np->keystr = node.keystr;
		debug(0, ("loaded %p: %s %1x (%lu,%lu): time: %"PRIu64" us, tokens: %lu",
			  np,
			  np->keystr,
			  flags,
			  ord[CHILD_LEFT],
			  ord[CHILD_RIGHT],
			  np->timestamp, np->tokens));
#endif
		if (flags & FL_CHILD_LEFT) {
			np->child[CHILD_LEFT] =
				new_node(nodes, hdr, ord[CHILD_LEFT], np);
			if (!np->child[CHILD_LEFT]) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "tbf.%s: invalid left pointer",
				       __FUNCTION__);
				return -1;
			}
			if (np->child[CHILD_LEFT]->status == NST_INCOMPLETE) {
				++incomplete;
			}
		}

		if (flags & FL_CHILD_RIGHT) {
			np->child[CHILD_RIGHT] =
				new_node(nodes, hdr, ord[CHILD_RIGHT], np);
			if (!np->child[CHILD_RIGHT]) {
				syslog(LOG_DAEMON|LOG_ERR,
				       "tbf.%s: invalid left pointer",
				       __FUNCTION__);
				return -1;
			}
			if (np->child[CHILD_RIGHT]->status == NST_INCOMPLETE) {
				++incomplete;
			}
		}
		lru_link_node(tree, np, tree->tail);
	}
	
	if (incomplete) {
		syslog(LOG_DAEMON|LOG_ERR, "tbf.%s: %lu incomplete nodes left",
		       __FUNCTION__, incomplete);
		return 1;
	}
	tree->root = nodes[hdr->root];
//	debug(0,("Loaded nodes"));
	return 0;
}

struct tree *
tree_load(char const *filename)
{
	FILE *fp;
	struct tree *tree;
	int rc;
	struct dump_header header;
	
	fp = fopen(filename, "r");
	if (!fp) {
		syslog(LOG_DAEMON|LOG_ERR, "can't open file %s: %s",
		       filename, strerror(errno));
		return NULL;
	}

	if (READREC(fp, header))
		rc = -1;
	else {
		struct node **nodes;

		debug(0,("elements: %"PRIu32", size: %"PRIu32", root: %"PRIu32,
			 header.count, header.size, header.root));
		tree = tree_create();
		nodes = calloc(header.count, sizeof(*nodes));
		rc = tree_load_nodes(tree, &header, nodes, fp);
		fclose(fp);
		if (rc) {
			size_t i;
			for (i = 0; i < header.count; i++) {
				if (nodes[i])
					node_free(nodes[i]);
			}
			tree->root = tree->head = tree->tail = NULL;
			tree_destroy(&tree);
		}
		free(nodes);
	}
	return tree;
}


pthread_mutex_t access_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tree *tbf_tree;
static char *tbf_dump_file_name;

static struct tree *
tbf_get_tree(void)
{
	struct tree *t;
	pthread_mutex_lock(&access_mutex);
	tree_ref(tbf_tree);
	t = tbf_tree;
	pthread_mutex_unlock(&access_mutex);
	return t;
}

static void
tbf_release_tree(struct tree **t)
{
	tree_unref(t);
}
	

static void
tbf_exit()
{
	if (tbf_dump_file_name) {
		struct tree *t = tbf_get_tree();
		tree_dump(t, tbf_dump_file_name);
		tbf_release_tree(&t);
	}
}

int
tbf_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	switch (e) {
	case VCL_EVENT_LOAD:
		tbf_tree = tree_create();
		atexit(tbf_exit);
		break;

	case VCL_EVENT_DISCARD:
		break;

	default:
		/* ignore */
		break;
	}
	return 0;
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
vmod_gc(VRT_CTX, VCL_REAL interval)
{
	tree_gc(tbf_tree, interval);
}

VCL_BOOL
vmod_rate(VRT_CTX, 
	  VCL_STRING key, VCL_INT cost, VCL_REAL t,
	  VCL_INT burst_size)
{
	VCL_BOOL res;
	struct tree *tree = tbf_get_tree();
	unsigned long interval = t * USEC_PER_SEC;
	
	debug(2, ("entering rate(%s,%d,%g,%d)",
		  key, cost, t, burst_size));
		
	tree_gc(tree, gc_interval);

	if (interval == 0 || burst_size == 0)
		res = false;
	else if (!cost)
		/* cost free, so don't waste time on tree lookup */
		res = true;
	else if (cost > burst_size)
		/* impossibly expensive, so don't waste time on
		   tree lookup */
		res = false;
	else 
		res = tbf_proc(tree, key, cost, interval, burst_size);
	tbf_release_tree(&tree);
	return res;
}

#define ISWS(c) ((c)==' '||(c)=='\t')

VCL_BOOL
vmod_check(VRT_CTX, VCL_STRING key, VCL_STRING spec)
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

	return vmod_rate(ctx, key, 1, n/v, v/n+1);
}

VCL_VOID
vmod_dump(VRT_CTX, VCL_STRING file)
{
	struct tree *t = tbf_get_tree();
	tree_dump(t, file);
	tbf_release_tree(&t);
}

VCL_VOID
vmod_dump_at_exit(VRT_CTX, VCL_STRING file)
{
 	pthread_mutex_lock(&access_mutex);
	free(tbf_dump_file_name);
	tbf_dump_file_name = strdup(file);
	AN(tbf_dump_file_name);
 	pthread_mutex_unlock(&access_mutex);
}

VCL_VOID
vmod_load(VRT_CTX, VCL_STRING file)
{
	struct tree *new_tree = tree_load(file);
	if (new_tree) {
		pthread_mutex_lock(&access_mutex);
		tree_unref(&tbf_tree);
		tbf_tree = new_tree;
		pthread_mutex_unlock(&access_mutex);
	}
}

struct traverse_closure
{
	int prio;
	uint32_t num;
};

static void
log_node(struct node *node, void *data)
{
	struct traverse_closure *tc = data;
	char kbuf[2*SHA256_LEN+1];
	key_to_str(node->key, kbuf);
#ifdef DEBUG
	syslog(tc->prio, "%d: %p(%p,%p): %lu %s: %s", tc->num, node,
	       node->child[CHILD_LEFT], node->child[CHILD_RIGHT], node->ord,
	       kbuf,
	       node->keystr);
#else
	syslog(tc->prio, "%d: %p(%p,%p): %lu %s", tc->num, node,
	       node->child[CHILD_LEFT], node->child[CHILD_RIGHT], node->ord,
	       kbuf);
#endif
}
	

VCL_VOID
vmod_log_tree(VRT_CTX, VCL_INT prio)
{
	struct traverse_closure tc;
	struct tree *tree = tbf_get_tree();
	if (!tree)
		return;
	tc.num = 0;
	tc.prio = prio;
	tree_traverse_postorder(tree, log_node, &tc);
	tbf_release_tree(&tree);
}

VCL_VOID
vmod_log_stats(VRT_CTX, VCL_INT prio)
{
	struct tree_stats st;
	struct tree *tree = tbf_get_tree();
	tree_compute_stats(tree, &st);
	tbf_release_tree(&tree);
	syslog(prio, "Number of nodes: %lu", st.num_nodes);
	syslog(prio, "Number of leaves: %lu", st.num_leaves);
	syslog(prio, "Shortest path: %lu", st.shortest_path);
	syslog(prio, "Longest path: %lu", st.longest_path);	
	syslog(prio, "Avg path: %f", st.avg_path);
}
