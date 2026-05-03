/*
 * src/res.c — c-ares-backed asynchronous DNS resolver.
 *
 * The original 2245-line hand-rolled resolver (Darren Reed, 1992) lives in
 * the repository's history. This file replaces it with a thin shim around
 * c-ares (1.16+). c-ares-specific code is confined to this translation unit;
 * the rest of the daemon talks to gethost_byname / gethost_byaddr /
 * del_queries / flush_cache / expire_cache / add_local_domain unchanged.
 *
 * Lifetime discipline (see GitHub issue #2 design comment for the long form):
 *
 *   c-ares 1.34 has no per-query cancellation API. ares_cancel() cancels
 *   every pending query channel-wide, which is too coarse: a freed aClient
 *   would take down unrelated in-flight lookups. So del_queries() does NOT
 *   free or unlink — it tombstones the matching ResRQs by setting
 *   r->cancelled = 1, and waits for the c-ares callback to fire eventually.
 *   The callback unlinks first, then snapshots cancelled (also true if
 *   status is ARES_ECANCELLED or ARES_EDESTRUCTION), then processes if not
 *   cancelled, then always frees the ResRQ. The unlink-first step matters
 *   because forward-confirmed-reverse-DNS verification can fail and trigger
 *   the caller to drop the client, which calls del_queries(cptr) reentrantly;
 *   tombstoning a ResRQ that has already unlinked itself from the pending
 *   list is harmless.
 *
 *   Two distinct stale-pointer hazards exist, handled by two distinct
 *   mechanisms:
 *
 *     - Pending query references a freed aClient/aConfItem
 *         → tombstone in ResRQ.cancelled
 *     - Cached struct hostent referenced by cptr->hostp survives the cache
 *       entry being evicted
 *         → rem_cache walks local[] and nulls dangling cptr->hostp
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "res.h"
#include "numeric.h"
#include "h.h"

#include <ares.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include "inet.h"

extern int  errno, h_errno;
extern int  highest_fd;

/* Local poll-event flags. s_bsd.c keeps a similar set but they're file-static
 * there; the platforms we build on (Debian Trixie) all have POLLIN/POLLOUT,
 * so the abbreviated form is enough here. */
#if !defined(POLLREADFLAGS)
# if defined(POLLIN) && defined(POLLRDNORM)
#  define POLLREADFLAGS  (POLLIN | POLLRDNORM)
# elif defined(POLLIN)
#  define POLLREADFLAGS  POLLIN
# endif
#endif
#if !defined(POLLWRITEFLAGS)
# if defined(POLLOUT) && defined(POLLWRNORM)
#  define POLLWRITEFLAGS (POLLOUT | POLLWRNORM)
# elif defined(POLLOUT)
#  define POLLWRITEFLAGS POLLOUT
# endif
#endif

#define ARES_CACSIZE         307
#define DNS_CACHE_MIN_TTL    300        /* project floor — RFC-low TTLs lifted */
#define DNS_QUERY_TIMEOUT_MS 5000
#define DNS_QUERY_TRIES      4

/*
 * In-flight DNS request.
 *
 * cinfo is a memcpy of the caller's Link, so the caller's Link going out of
 * scope doesn't matter. cinfo.value.{cptr,aconf} is a raw pointer into a pool
 * that may be freed at any time — `cancelled` is the only safe gate before
 * dereferencing it.
 */
typedef struct reslist
{
    Link            cinfo;
    int             type;       /* RESRQ_FORWARD or RESRQ_REVERSE */
    int             phase;      /* 0 = primary, 1 = forward-verify leg */
    int             has_rev;    /* phase 1 + intersect with rev_addr */
    int             cancelled;  /* tombstone — set by del_queries / shutdown */
    char           *name;       /* query name (forward) — allocated */
    struct IN_ADDR  rev_addr;   /* original IP for reverse / FCrDNS verify */
    struct reslist *prev, *next;
} ResRQ;

#define RESRQ_FORWARD 1
#define RESRQ_REVERSE 2

typedef struct cachetable
{
    aCache *num_list;
    aCache *name_list;
} CacheTable;

/* File-local globals */
static ares_channel_t *resolver_channel = NULL;
static int  resolver_initialized = 0;
static int  library_initialized  = 0;

/*
 * Sock-state callback table. c-ares 1.16 caps the simultaneously-active
 * socket count at ARES_GETSOCK_MAXNUM (16), so a fixed array indexed by slot
 * is enough — no need for a growable structure.
 */
struct cares_fd_entry
{
    ares_socket_t fd;
    int           want_read;
    int           want_write;
};
static struct cares_fd_entry cares_fds[ARES_GETSOCK_MAXNUM];

/*
 * Cached search domain. captured from the c-ares channel after init/reinit
 * via ares_save_options(); used by add_local_domain() to qualify unqualified
 * names before lookup.
 */
static char saved_search_domain[256];

/* Cache state */
static int        incache = 0;
static CacheTable hashtable[ARES_CACSIZE];
static aCache    *cachetop = NULL;

/* Pending request list */
static ResRQ *pending_first = NULL;
static ResRQ *pending_last  = NULL;

/* STATS counters */
static struct cacheinfo
{
    int ca_adds;
    int ca_dels;
    int ca_expires;
    int ca_lookups;
    int ca_na_hits;
    int ca_nu_hits;
    int ca_updates;
} cainfo;

static struct resinfo
{
    int re_errors;
    int re_nu_look;
    int re_na_look;
    int re_replies;
    int re_requests;
    int re_resends;     /* unused under c-ares (it does its own retries) */
    int re_sent;
    int re_timeouts;
    int re_shortttl;
    int re_unkrep;      /* unused under c-ares */
} reinfo;

/* Forward declarations */
static void    pending_link(ResRQ *);
static void    pending_unlink(ResRQ *);
static ResRQ  *make_request(Link *);
static void    free_resrq(ResRQ *);

static void    on_sock_state(void *data, ares_socket_t fd, int read_ok, int write_ok);
static void    on_addrinfo_cb(void *arg, int status, int timeouts,
                              struct ares_addrinfo *result);
static void    on_nameinfo_cb(void *arg, int status, int timeouts,
                              char *node, char *service);

static void    process_forward_result(ResRQ *r, struct ares_addrinfo *result);
static void    spawn_forward_verify(ResRQ *r_old, const char *name);

static void    deliver_success(ResRQ *r, aCache *cp);
static void    deliver_failure(ResRQ *r);

static aCache *cache_make(const char *name, struct IN_ADDR *addrs, int n_addrs,
                          char **aliases, int n_aliases, time_t min_ttl);
static aCache *cache_add(aCache *);
static aCache *find_cache_name(char *name);
static aCache *find_cache_number(const struct IN_ADDR *addr);
static void    rem_cache(aCache *);
static void    update_list(aCache *cachep);
static int     hash_number(const u_char *);
static int     hash_name(const char *);

static void    capture_search_domain(void);
static void    issue_forward(ResRQ *r, const char *name);


/* --------------------------------------------------------------------------
 * Pending list (doubly-linked, FIFO order)
 * -------------------------------------------------------------------------- */

static void pending_link(ResRQ *r)
{
    r->prev = pending_last;
    r->next = NULL;
    if (pending_last)
        pending_last->next = r;
    else
        pending_first = r;
    pending_last = r;
}

static void pending_unlink(ResRQ *r)
{
    if (r->prev)
        r->prev->next = r->next;
    else
        pending_first = r->next;
    if (r->next)
        r->next->prev = r->prev;
    else
        pending_last = r->prev;
    r->prev = r->next = NULL;
}

static ResRQ *make_request(Link *lp)
{
    ResRQ *r = (ResRQ *) MyMalloc(sizeof(ResRQ));
    memset((char *) r, 0, sizeof(ResRQ));
    if (lp)
        memcpy((char *) &r->cinfo, (char *) lp, sizeof(Link));
    else
        r->cinfo.flags = ASYNC_NONE;
    pending_link(r);
    reinfo.re_requests++;
    return r;
}

static void free_resrq(ResRQ *r)
{
    if (!r)
        return;
    if (r->name)
        MyFree(r->name);
    MyFree((char *) r);
}


/* --------------------------------------------------------------------------
 * I/O loop integration
 * -------------------------------------------------------------------------- */

static void on_sock_state(void *data, ares_socket_t fd, int read_ok, int write_ok)
{
    int i, slot;

    (void) data;

    if (!read_ok && !write_ok)
    {
        /* fd closing — drop from table */
        for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
        {
            if (cares_fds[i].fd == fd)
            {
                cares_fds[i].fd         = ARES_SOCKET_BAD;
                cares_fds[i].want_read  = 0;
                cares_fds[i].want_write = 0;
                return;
            }
        }
        return;
    }

    /* update existing slot */
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
    {
        if (cares_fds[i].fd == fd)
        {
            cares_fds[i].want_read  = read_ok;
            cares_fds[i].want_write = write_ok;
            return;
        }
    }

    /* allocate fresh slot */
    slot = -1;
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
    {
        if (cares_fds[i].fd == ARES_SOCKET_BAD)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
    {
        /* table full — should not happen since c-ares caps active sockets at
         * ARES_GETSOCK_MAXNUM. If it does, the leak is bounded: c-ares will
         * stop calling us until a slot frees. */
        sendto_realops_lev(DEBUG_LEV,
                           "resolver: cares_fds[] full, dropping fd %d", (int) fd);
        return;
    }
    cares_fds[slot].fd         = fd;
    cares_fds[slot].want_read  = read_ok;
    cares_fds[slot].want_write = write_ok;
}

int resolver_collect_pfds(struct pollfd *out)
{
    int i, n = 0;

    if (!resolver_initialized)
        return 0;

    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
    {
        if (cares_fds[i].fd == ARES_SOCKET_BAD)
            continue;
        out[n].fd      = cares_fds[i].fd;
        out[n].events  = 0;
        out[n].revents = 0;
        if (cares_fds[i].want_read)
            out[n].events |= POLLREADFLAGS;
        if (cares_fds[i].want_write)
            out[n].events |= POLLWRITEFLAGS;
        n++;
    }
    return n;
}

void resolver_process(int fd, int read_ok, int write_ok)
{
    if (!resolver_initialized)
        return;
    ares_process_fd(resolver_channel,
                    read_ok  ? (ares_socket_t) fd : ARES_SOCKET_BAD,
                    write_ok ? (ares_socket_t) fd : ARES_SOCKET_BAD);
}

time_t resolver_next_timeout(time_t now)
{
    struct timeval tv, *p;

    if (!resolver_initialized)
        return now + AR_TTL;

    p = ares_timeout(resolver_channel, NULL, &tv);
    if (!p)
        return now + AR_TTL;

    return now + (time_t) p->tv_sec + ((p->tv_usec > 0) ? 1 : 0);
}


/* --------------------------------------------------------------------------
 * Search domain (replaces _res.defdname)
 * -------------------------------------------------------------------------- */

static void capture_search_domain(void)
{
    struct ares_options opts;
    int mask = 0;

    saved_search_domain[0] = '\0';
    memset((char *) &opts, 0, sizeof(opts));

    if (ares_save_options(resolver_channel, &opts, &mask) == ARES_SUCCESS)
    {
        if ((mask & ARES_OPT_DOMAINS) && opts.ndomains > 0 && opts.domains[0])
        {
            strncpy(saved_search_domain, opts.domains[0],
                    sizeof(saved_search_domain) - 1);
            saved_search_domain[sizeof(saved_search_domain) - 1] = '\0';
        }
    }
    ares_destroy_options(&opts);
}

void add_local_domain(char *hname, int size)
{
    int hlen, dlen;

    if (strchr(hname, '.'))
        return;
    if (saved_search_domain[0] == '\0')
        return;

    hlen = (int) strlen(hname);
    dlen = (int) strlen(saved_search_domain);
    if (size <= 0 || dlen + 1 >= size - hlen)
        return;

    (void) strncat(hname, ".", size - 1);
    (void) strncat(hname, saved_search_domain, size - 2);
}


/* --------------------------------------------------------------------------
 * del_queries — tombstone-only
 *
 * Walks the pending list and marks every request whose cinfo.value.cp == cp
 * as cancelled. The callback path will eventually fire and unlink + free.
 * -------------------------------------------------------------------------- */

void del_queries(char *cp)
{
    ResRQ *r;
    for (r = pending_first; r; r = r->next)
    {
        if (r->cinfo.value.cp == cp)
            r->cancelled = 1;
    }
}


/* --------------------------------------------------------------------------
 * Cache layout
 *
 * Cache entries own libc-shaped struct hostent memory:
 *   h_name        — char * (allocated)
 *   h_aliases     — NULL-terminated char ** (allocated; entries allocated)
 *   h_addr_list   — NULL-terminated char ** (allocated; first entry points
 *                   at a single MyMalloc'd block of n * sizeof(IN_ADDR))
 * -------------------------------------------------------------------------- */

static int hash_number(const u_char *ip)
{
    u_int hashv = 0;
    int i;

#ifndef INET6
    for (i = 0; i < 4; i++)
        hashv += hashv + ip[i];
#else
    for (i = 0; i < 16; i++)
        hashv += hashv + ip[i];
#endif
    return (int) (hashv % ARES_CACSIZE);
}

static int hash_name(const char *name)
{
    u_int hashv = 0;
    for (; *name && *name != '.'; name++)
        hashv += (u_char) *name;
    return (int) (hashv % ARES_CACSIZE);
}

static aCache *cache_add(aCache *ocp)
{
    int hashv;

    /* prepend to LRU list */
    ocp->list_next = cachetop;
    cachetop = ocp;

    if (!ocp->he.h_name || !ocp->he.h_addr_list || !ocp->he.h_addr_list[0])
        return NULL;

    hashv = hash_name(ocp->he.h_name);
    ocp->hname_next = hashtable[hashv].name_list;
    hashtable[hashv].name_list = ocp;

    hashv = hash_number((u_char *) ocp->he.h_addr_list[0]);
    ocp->hnum_next = hashtable[hashv].num_list;
    hashtable[hashv].num_list = ocp;

    cainfo.ca_adds++;

    /* LRU eviction */
    if (++incache > IRC_MAXCACHED)
    {
        aCache *cp;
        for (cp = cachetop; cp->list_next; cp = cp->list_next)
            ;
        rem_cache(cp);
    }
    return ocp;
}

static aCache *cache_make(const char *name, struct IN_ADDR *addrs, int n_addrs,
                          char **aliases, int n_aliases, time_t min_ttl)
{
    aCache *cp;
    char   *block;
    int     i;

    if (!name || n_addrs <= 0)
        return NULL;

    cp = (aCache *) MyMalloc(sizeof(aCache));
    memset((char *) cp, 0, sizeof(aCache));
    cp->he.h_addrtype = AFINET;
    cp->he.h_length   = sizeof(struct IN_ADDR);

    cp->he.h_name = (char *) MyMalloc(strlen(name) + 1);
    strcpy(cp->he.h_name, name);

    if (n_aliases < 0)
        n_aliases = 0;
    cp->he.h_aliases = (char **) MyMalloc((n_aliases + 1) * sizeof(char *));
    for (i = 0; i < n_aliases; i++)
    {
        cp->he.h_aliases[i] = (char *) MyMalloc(strlen(aliases[i]) + 1);
        strcpy(cp->he.h_aliases[i], aliases[i]);
    }
    cp->he.h_aliases[n_aliases] = NULL;

    cp->he.h_addr_list = (char **) MyMalloc((n_addrs + 1) * sizeof(char *));
    block = (char *) MyMalloc(n_addrs * sizeof(struct IN_ADDR));
    for (i = 0; i < n_addrs; i++)
    {
        cp->he.h_addr_list[i] = block + i * sizeof(struct IN_ADDR);
        memcpy(cp->he.h_addr_list[i], (char *) &addrs[i], sizeof(struct IN_ADDR));
    }
    cp->he.h_addr_list[n_addrs] = NULL;

    if (min_ttl < DNS_CACHE_MIN_TTL)
    {
        reinfo.re_shortttl++;
        cp->ttl = DNS_CACHE_MIN_TTL;
    }
    else
        cp->ttl = min_ttl;
    cp->expireat = timeofday + cp->ttl;

    return cache_add(cp);
}

/* Move cache entry to front of LRU list (called on hit). */
static void update_list(aCache *cachep)
{
    aCache **cpp;

    cainfo.ca_updates++;

    for (cpp = &cachetop; *cpp; cpp = &((*cpp)->list_next))
    {
        if (*cpp == cachep)
        {
            *cpp = cachep->list_next;
            cachep->list_next = cachetop;
            cachetop = cachep;
            return;
        }
    }
}

static aCache *find_cache_name(char *name)
{
    aCache *cp;
    int     hashv, i;

    if (!name)
        return NULL;
    hashv = hash_name(name);

    for (cp = hashtable[hashv].name_list; cp; cp = cp->hname_next)
    {
        if (cp->he.h_name && mycmp(cp->he.h_name, name) == 0)
        {
            cainfo.ca_na_hits++;
            update_list(cp);
            return cp;
        }
        if (cp->he.h_aliases)
        {
            for (i = 0; cp->he.h_aliases[i]; i++)
            {
                if (mycmp(cp->he.h_aliases[i], name) == 0)
                {
                    cainfo.ca_na_hits++;
                    update_list(cp);
                    return cp;
                }
            }
        }
    }
    return NULL;
}

static aCache *find_cache_number(const struct IN_ADDR *addr)
{
    aCache *cp;
    int     hashv, i;

    if (!addr)
        return NULL;
    hashv = hash_number((const u_char *) addr);

    for (cp = hashtable[hashv].num_list; cp; cp = cp->hnum_next)
    {
        if (!cp->he.h_addr_list)
            continue;
        for (i = 0; cp->he.h_addr_list[i]; i++)
        {
            const struct IN_ADDR *cand =
                (const struct IN_ADDR *) cp->he.h_addr_list[i];
#ifndef INET6
            if (cand->S_ADDR == addr->S_ADDR)
#else
            if (memcmp(cand->S_ADDR, addr->S_ADDR, sizeof(struct IN_ADDR)) == 0)
#endif
            {
                cainfo.ca_nu_hits++;
                update_list(cp);
                return cp;
            }
        }
    }
    return NULL;
}

static void rem_cache(aCache *ocp)
{
    aCache **cp;
    struct hostent *hp = &ocp->he;
    int     hashv, fd;
    aClient *cptr;

    /*
     * Cleanup any references to this struct hostent from local clients —
     * cptr->hostp points into the cache, so the cache entry going away has
     * to null out the dangling pointer. (Preserved verbatim from the
     * pre-c-ares implementation; this is the second of the two stale-pointer
     * hazards documented at the top of this file.)
     */
    for (fd = highest_fd; fd >= 0; fd--)
    {
        if ((cptr = local[fd]) && cptr->hostp == hp)
            cptr->hostp = NULL;
    }

    /* unlink from LRU */
    for (cp = &cachetop; *cp; cp = &((*cp)->list_next))
    {
        if (*cp == ocp)
        {
            *cp = ocp->list_next;
            break;
        }
    }

    /* unlink from name hash */
    if (hp->h_name)
    {
        hashv = hash_name(hp->h_name);
        for (cp = &hashtable[hashv].name_list; *cp; cp = &((*cp)->hname_next))
        {
            if (*cp == ocp)
            {
                *cp = ocp->hname_next;
                break;
            }
        }
    }

    /* unlink from number hash */
    if (hp->h_addr_list && hp->h_addr_list[0])
    {
        hashv = hash_number((u_char *) hp->h_addr_list[0]);
        for (cp = &hashtable[hashv].num_list; *cp; cp = &((*cp)->hnum_next))
        {
            if (*cp == ocp)
            {
                *cp = ocp->hnum_next;
                break;
            }
        }
    }

    /* free strings */
    if (hp->h_name)
        MyFree(hp->h_name);
    if (hp->h_aliases)
    {
        int i;
        for (i = 0; hp->h_aliases[i]; i++)
            MyFree(hp->h_aliases[i]);
        MyFree((char *) hp->h_aliases);
    }
    if (hp->h_addr_list)
    {
        if (hp->h_addr_list[0])
            MyFree((char *) hp->h_addr_list[0]);  /* single block */
        MyFree((char *) hp->h_addr_list);
    }

    MyFree((char *) ocp);
    incache--;
    cainfo.ca_dels++;
}

time_t expire_cache(time_t now)
{
    aCache *cp, *cp2;
    time_t  next = 0;
    time_t  mmax = now + AR_TTL;

    for (cp = cachetop; cp; cp = cp2)
    {
        cp2 = cp->list_next;
        if (now >= cp->expireat)
        {
            cainfo.ca_expires++;
            rem_cache(cp);
        }
        else if (!next || next > cp->expireat)
            next = cp->expireat;
    }
    return (next > now) ? (next < mmax ? next : mmax) : mmax;
}

void flush_cache(void)
{
    aCache *cp;
    while ((cp = cachetop))
        rem_cache(cp);
}


/* --------------------------------------------------------------------------
 * Delivery to caller via the Link cinfo
 * -------------------------------------------------------------------------- */

static void deliver_success(ResRQ *r, aCache *cp)
{
    aClient   *cptr;
    aConfItem *aconf;
    struct hostent *hp = (struct hostent *) &cp->he;

    /*
     * Tombstone any sibling pending requests for the same target so the
     * caller's Link can be freed without surprises. The current ResRQ has
     * already been pending_unlink'd by the caller, so this walk skips it.
     */
    del_queries(r->cinfo.value.cp);

    switch (r->cinfo.flags)
    {
    case ASYNC_CLIENT:
        cptr = r->cinfo.value.cptr;
        if (cptr)
        {
            ClearDNS(cptr);
            cptr->hostp = hp;
            if (!DoingAuth(cptr))
                SetAccess(cptr);
        }
        break;

    case ASYNC_CONNECT:
        aconf = r->cinfo.value.aconf;
        if (aconf)
        {
            memcpy((char *) &aconf->ipnum, hp->h_addr, sizeof(struct IN_ADDR));
            (void) connect_server(aconf, NULL, hp);
        }
        break;

    case ASYNC_CONF:
        aconf = r->cinfo.value.aconf;
        if (aconf)
            memcpy((char *) &aconf->ipnum, hp->h_addr, sizeof(struct IN_ADDR));
        break;

    default:
        break;
    }
}

static void deliver_failure(ResRQ *r)
{
    aClient   *cptr;
    aConfItem *aconf;

    reinfo.re_errors++;

    switch (r->cinfo.flags)
    {
    case ASYNC_CLIENT:
        cptr = r->cinfo.value.cptr;
        if (cptr)
        {
            ClearDNS(cptr);
            cptr->hostp = NULL;
            if (!DoingAuth(cptr))
                SetAccess(cptr);
        }
        break;

    case ASYNC_CONNECT:
        aconf = r->cinfo.value.aconf;
        sendto_ops("Connect to %s failed: host lookup",
                   aconf ? aconf->host : "unknown");
        break;

    case ASYNC_CONF:
        /* No further action — server config will retry next cycle. */
        break;

    default:
        break;
    }
}


/* --------------------------------------------------------------------------
 * c-ares callbacks
 * -------------------------------------------------------------------------- */

static void on_addrinfo_cb(void *arg, int status, int timeouts,
                           struct ares_addrinfo *result)
{
    ResRQ *r = (ResRQ *) arg;
    int    cancelled;

    (void) timeouts;

    /* 1. unlink first — re-entrancy safety: any deliver path that triggers
     *    del_queries(cptr) reentrantly will tombstone other ResRQs but will
     *    not see this one. */
    pending_unlink(r);

    cancelled = r->cancelled
             || status == ARES_ECANCELLED
             || status == ARES_EDESTRUCTION;

    reinfo.re_replies++;

    if (!cancelled)
    {
        if (status != ARES_SUCCESS || !result)
            deliver_failure(r);
        else
            process_forward_result(r, result);
    }

    if (result)
        ares_freeaddrinfo(result);
    free_resrq(r);
}

static void on_nameinfo_cb(void *arg, int status, int timeouts,
                           char *node, char *service)
{
    ResRQ *r = (ResRQ *) arg;
    int    cancelled;

    (void) timeouts;
    (void) service;

    pending_unlink(r);

    cancelled = r->cancelled
             || status == ARES_ECANCELLED
             || status == ARES_EDESTRUCTION;

    reinfo.re_replies++;

    if (cancelled)
    {
        free_resrq(r);
        return;
    }

    if (status != ARES_SUCCESS || !node || !*node)
    {
        deliver_failure(r);
        free_resrq(r);
        return;
    }

    /*
     * Forward-confirmed-reverse-DNS: spawn a fresh ResRQ for the canonical
     * name's forward A/AAAA lookup. The verify ResRQ inherits cinfo + the
     * original IP for the cross-check.
     */
    spawn_forward_verify(r, node);
    free_resrq(r);
}

static void process_forward_result(ResRQ *r, struct ares_addrinfo *result)
{
    struct ares_addrinfo_node  *n;
    struct ares_addrinfo_cname *cn;
    struct IN_ADDR              addrs[IRC_MAXADDRS];
    char                       *aliases[IRC_MAXALIASES];
    int                         n_addrs   = 0;
    int                         n_aliases = 0;
    time_t                      min_ttl   = (time_t) AR_TTL;
    const char                 *canon;
    aCache                     *cp;
    int                         i, found;

    /*
     * Cache key: prefer the original query name (what we asked for, the
     * canonical-cname for the FCrDNS case). Fall back to whatever c-ares
     * gives us in result->name.
     */
    canon = r->name ? r->name : result->name;
    if (!canon || !*canon)
    {
        deliver_failure(r);
        return;
    }

    /* Walk address records (skipping families we don't support). */
    for (n = result->nodes; n; n = n->ai_next)
    {
        if (n_addrs >= IRC_MAXADDRS)
            break;

        if (n->ai_family == AF_INET && n->ai_addrlen >= sizeof(struct sockaddr_in))
        {
            const struct sockaddr_in *sin4 = (const struct sockaddr_in *) n->ai_addr;
#ifndef INET6
            addrs[n_addrs].S_ADDR = sin4->sin_addr.s_addr;
#else
            u_char *out = (u_char *) addrs[n_addrs].S_ADDR;
            memset(out, 0, 10);
            out[10] = out[11] = 0xff;
            memcpy(out + 12, &sin4->sin_addr, 4);
#endif
        }
#ifdef INET6
        else if (n->ai_family == AF_INET6 && n->ai_addrlen >= sizeof(struct sockaddr_in6))
        {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) n->ai_addr;
            memcpy(addrs[n_addrs].S_ADDR, &sin6->sin6_addr, sizeof(struct IN_ADDR));
        }
#endif
        else
            continue;

        if (n->ai_ttl > 0 && (time_t) n->ai_ttl < min_ttl)
            min_ttl = (time_t) n->ai_ttl;

        n_addrs++;
    }

    /* Walk CNAME chain into aliases. canon is captured as char * (the
     * resolver's allocated query name or c-ares's writable result->name) so
     * we can hand it to mycmp without a const cast. */
    for (cn = result->cnames; cn && n_aliases < IRC_MAXALIASES; cn = cn->next)
    {
        if (cn->name && mycmp(cn->name, (char *) canon) != 0)
        {
            aliases[n_aliases++] = cn->name;
            if (n_aliases >= IRC_MAXALIASES)
                break;
        }
        if (cn->alias && mycmp(cn->alias, (char *) canon) != 0)
        {
            aliases[n_aliases++] = cn->alias;
        }
        if (cn->ttl > 0 && (time_t) cn->ttl < min_ttl)
            min_ttl = (time_t) cn->ttl;
    }

    if (n_addrs == 0)
    {
        deliver_failure(r);
        return;
    }

    /*
     * FCrDNS verification: if this is a forward-verify leg, require the
     * original IP to appear in the forward result. If it does, trim the
     * cached address list to just that IP (matches the pre-c-ares behavior:
     * "Those not in the reverse query must be zeroed out" — and our reverse
     * query had a single IP).
     */
    if (r->has_rev)
    {
        found = 0;
        for (i = 0; i < n_addrs; i++)
        {
#ifndef INET6
            if (addrs[i].S_ADDR == r->rev_addr.S_ADDR)
#else
            if (memcmp(addrs[i].S_ADDR, r->rev_addr.S_ADDR, sizeof(struct IN_ADDR)) == 0)
#endif
            {
                found = 1;
                break;
            }
        }
        if (!found)
        {
            sendto_ops_lev(DEBUG_LEV,
                           "FCrDNS mismatch for %s — forward IPs do not "
                           "include the reverse-resolved IP", canon);
            deliver_failure(r);
            return;
        }
        memcpy((char *) &addrs[0], (char *) &r->rev_addr, sizeof(struct IN_ADDR));
        n_addrs = 1;
    }

    cp = cache_make(canon, addrs, n_addrs, aliases, n_aliases, min_ttl);
    if (!cp)
    {
        deliver_failure(r);
        return;
    }
    deliver_success(r, cp);
}

static void issue_forward(ResRQ *r, const char *name)
{
    struct ares_addrinfo_hints hints;

    memset((char *) &hints, 0, sizeof(hints));
#ifndef INET6
    hints.ai_family = AF_INET;
    hints.ai_flags  = 0;
#else
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags  = ARES_AI_V4MAPPED | ARES_AI_ADDRCONFIG;
#endif

    reinfo.re_sent++;
    ares_getaddrinfo(resolver_channel, name, NULL, &hints, on_addrinfo_cb, r);
}

static void spawn_forward_verify(ResRQ *r_old, const char *name)
{
    ResRQ *rv = make_request(&r_old->cinfo);
    rv->type    = RESRQ_FORWARD;
    rv->phase   = 1;
    rv->has_rev = 1;
    memcpy((char *) &rv->rev_addr, (char *) &r_old->rev_addr, sizeof(struct IN_ADDR));
    rv->name = (char *) MyMalloc(strlen(name) + 1);
    strcpy(rv->name, name);

    issue_forward(rv, name);
}


/* --------------------------------------------------------------------------
 * Public lookup entry points
 * -------------------------------------------------------------------------- */

struct hostent *gethost_byname(char *name, Link *lp)
{
    aCache *cp;
    ResRQ  *r;

    reinfo.re_na_look++;
    cainfo.ca_lookups++;

    if (!name || !*name)
        return NULL;

    if ((cp = find_cache_name(name)))
        return (struct hostent *) &cp->he;

    if (!lp || !resolver_initialized)
        return NULL;

    r = make_request(lp);
    r->type    = RESRQ_FORWARD;
    r->phase   = 0;
    r->has_rev = 0;
    r->name    = (char *) MyMalloc(strlen(name) + 1);
    strcpy(r->name, name);

    issue_forward(r, name);
    return NULL;
}

struct hostent *gethost_byaddr(char *addr, Link *lp)
{
    aCache                  *cp;
    ResRQ                   *r;
    struct sockaddr_storage  ss;
    socklen_t                sslen;
    struct IN_ADDR          *ipa = (struct IN_ADDR *) addr;

    reinfo.re_nu_look++;
    cainfo.ca_lookups++;

    if (!addr)
        return NULL;

    if ((cp = find_cache_number(ipa)))
        return (struct hostent *) &cp->he;

    if (!lp || !resolver_initialized)
        return NULL;

    r = make_request(lp);
    r->type    = RESRQ_REVERSE;
    r->phase   = 0;
    r->has_rev = 0;
    memcpy((char *) &r->rev_addr, (char *) ipa, sizeof(struct IN_ADDR));

    /* Build the sockaddr c-ares expects. Under INET6, v4-mapped addresses go
     * out as AF_INET (so c-ares queries in-addr.arpa, not ip6.arpa); native
     * v6 goes out as AF_INET6 (ip6.arpa). */
    memset((char *) &ss, 0, sizeof(ss));
#ifndef INET6
    {
        struct sockaddr_in *sin4 = (struct sockaddr_in *) &ss;
        sin4->sin_family      = AF_INET;
        sin4->sin_addr.s_addr = ipa->S_ADDR;
        sslen = sizeof(struct sockaddr_in);
    }
#else
    {
        const u_char *p = (const u_char *) ipa->S_ADDR;
        if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0
         && p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] == 0
         && p[8] == 0 && p[9] == 0 && p[10] == 0xff && p[11] == 0xff)
        {
            struct sockaddr_in *sin4 = (struct sockaddr_in *) &ss;
            sin4->sin_family = AF_INET;
            memcpy(&sin4->sin_addr, p + 12, 4);
            sslen = sizeof(struct sockaddr_in);
        }
        else
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
            sin6->sin6_family = AF_INET6;
            memcpy(&sin6->sin6_addr, p, 16);
            sslen = sizeof(struct sockaddr_in6);
        }
    }
#endif

    reinfo.re_sent++;
    ares_getnameinfo(resolver_channel, (struct sockaddr *) &ss, sslen,
                     ARES_NI_LOOKUPHOST | ARES_NI_NAMEREQD,
                     on_nameinfo_cb, r);
    return NULL;
}


/* --------------------------------------------------------------------------
 * Channel lifecycle
 * -------------------------------------------------------------------------- */

int init_resolver(void)
{
    struct ares_options opts;
    int                 optmask;
    int                 rc, i;

    if (!library_initialized)
    {
        rc = ares_library_init(ARES_LIB_INIT_ALL);
        if (rc != ARES_SUCCESS)
        {
            sendto_realops("ares_library_init failed: %s", ares_strerror(rc));
            return -1;
        }
        library_initialized = 1;
    }

    if (resolver_initialized)
        return -1;

    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
    {
        cares_fds[i].fd         = ARES_SOCKET_BAD;
        cares_fds[i].want_read  = 0;
        cares_fds[i].want_write = 0;
    }

    memset((char *) &cainfo, 0, sizeof(cainfo));
    memset((char *) &reinfo, 0, sizeof(reinfo));
    memset((char *) hashtable, 0, sizeof(hashtable));
    saved_search_domain[0] = '\0';

    memset((char *) &opts, 0, sizeof(opts));
    opts.sock_state_cb      = on_sock_state;
    opts.sock_state_cb_data = NULL;
    opts.timeout            = DNS_QUERY_TIMEOUT_MS;
    opts.tries              = DNS_QUERY_TRIES;
    optmask = ARES_OPT_SOCK_STATE_CB | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

    rc = ares_init_options(&resolver_channel, &opts, optmask);
    if (rc != ARES_SUCCESS)
    {
        sendto_realops("ares_init_options failed: %s", ares_strerror(rc));
        return -1;
    }

    capture_search_domain();
    resolver_initialized = 1;

    /* No single fd to expose any more — the I/O loop drives c-ares via
     * resolver_collect_pfds + resolver_process. resfd stays -1 in s_bsd.c so
     * the legacy do_dns_async path never fires. */
    return -1;
}

void shutdown_resolver(void)
{
    ResRQ *r;

    if (!resolver_initialized)
        return;

    /*
     * Belt: pre-tombstone every pending request before destroying the
     * channel. ares_destroy() fires every callback with ARES_EDESTRUCTION;
     * each callback unlinks itself and frees.
     *
     * Suspenders: each callback also checks for ARES_EDESTRUCTION
     * independently, so abnormal exit paths that skip pre-tombstoning still
     * won't touch freed memory.
     */
    for (r = pending_first; r; r = r->next)
        r->cancelled = 1;

    ares_destroy(resolver_channel);
    resolver_channel = NULL;
    resolver_initialized = 0;

    if (library_initialized)
    {
        ares_library_cleanup();
        library_initialized = 0;
    }

    saved_search_domain[0] = '\0';
}

void resolver_reinit(void)
{
    if (!resolver_initialized)
        return;
    (void) ares_reinit(resolver_channel);
    capture_search_domain();
}


/* --------------------------------------------------------------------------
 * get_res — legacy stub.
 *
 * The c-ares-based resolver delivers replies via the on_addrinfo /
 * on_nameinfo callbacks. The legacy do_dns_async path in s_bsd.c only fires
 * when resfd >= 0, but init_resolver now returns -1 unconditionally — so
 * this stub is unreachable. It is retained for the duration of Step 3
 * because s_bsd.c::do_dns_async still references it; both go away in Step 4.
 * -------------------------------------------------------------------------- */

struct hostent *get_res(char *lp)
{
    (void) lp;
    return NULL;
}


/* --------------------------------------------------------------------------
 * STATS
 * -------------------------------------------------------------------------- */

int m_dns(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aCache *cp;
    int     i;

    (void) parc;

    if (!IsAnOper(cptr))
    {
        sendto_one(cptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parv[1] && *parv[1] == 'l')
    {
        if (!MyClient(sptr) || !IsAdmin(sptr))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        for (cp = cachetop; cp; cp = cp->list_next)
        {
            sendto_one(sptr, "NOTICE %s :Ex %d ttl %d host %s(%s)",
                       parv[0], (int) (cp->expireat - timeofday), (int) cp->ttl,
                       cp->he.h_name,
                       inet_ntop(AFINET, cp->he.h_addr_list[0],
                                 mydummy, sizeof(mydummy)));
            for (i = 0; cp->he.h_aliases[i]; i++)
                sendto_one(sptr, "NOTICE %s : %s = %s (CN)",
                           parv[0], cp->he.h_name, cp->he.h_aliases[i]);
            for (i = 1; cp->he.h_addr_list[i]; i++)
                sendto_one(sptr, "NOTICE %s : %s = %s (IP)",
                           parv[0], cp->he.h_name,
                           inet_ntop(AFINET, cp->he.h_addr_list[i],
                                     mydummy, sizeof(mydummy)));
        }
        return 0;
    }

    sendto_one(sptr, "NOTICE %s :Ca %d Cd %d Ce %d Cl %d Ch %d:%d Cu %d",
               sptr->name,
               cainfo.ca_adds, cainfo.ca_dels, cainfo.ca_expires,
               cainfo.ca_lookups,
               cainfo.ca_na_hits, cainfo.ca_nu_hits, cainfo.ca_updates);
    sendto_one(sptr, "NOTICE %s :Re %d Rl %d/%d Rp %d Rq %d",
               sptr->name, reinfo.re_errors, reinfo.re_nu_look,
               reinfo.re_na_look, reinfo.re_replies, reinfo.re_requests);
    sendto_one(sptr, "NOTICE %s :Ru %d Rsh %d Rs %d(%d) Rt %d", sptr->name,
               reinfo.re_unkrep, reinfo.re_shortttl, reinfo.re_sent,
               reinfo.re_resends, reinfo.re_timeouts);
    return 0;
}

u_long cres_mem(aClient *sptr)
{
    aCache         *c;
    struct hostent *h;
    int             i;
    u_long          nm = 0, im = 0, sm = 0, ts = 0;

    for (c = cachetop; c; c = c->list_next)
    {
        sm += sizeof(*c);
        h = &c->he;
        if (h->h_addr_list)
        {
            for (i = 0; h->h_addr_list[i]; i++)
            {
                im += sizeof(char *);
                im += sizeof(struct IN_ADDR);
            }
            im += sizeof(char *);
        }
        if (h->h_aliases)
        {
            for (i = 0; h->h_aliases[i]; i++)
            {
                nm += sizeof(char *);
                nm += strlen(h->h_aliases[i]);
            }
            nm += sizeof(char *);
        }
        if (h->h_name)
            nm += strlen(h->h_name);
    }
    ts = ARES_CACSIZE * sizeof(CacheTable);
    sendto_one(sptr, ":%s %d %s :RES table sz %d",
               me.name, RPL_STATSDEBUG, sptr->name, (int) ts);
    sendto_one(sptr, ":%s %d %s :RES Structs sz %d IP storage sz %d "
               "Name storage sz %d",
               me.name, RPL_STATSDEBUG, sptr->name,
               (int) sm, (int) im, (int) nm);
    return ts + sm + im + nm;
}
