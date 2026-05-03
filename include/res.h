/*
 * irc2.7.2/ircd/res.h (C)opyright 1992 Darren Reed.
 */

/* $Id$ */

#ifndef	__res_include__
#define	__res_include__

#define IRC_MAXALIASES	10
#define IRC_MAXADDRS	10

#define	AR_TTL		600	 /* TTL in seconds for dns cache entries */

struct hent
{
    char       *h_name;		    /* official name of host */
    char       *h_aliases[IRC_MAXALIASES];	/* alias list */
    int         h_addrtype;	    /* host address type */
    int         h_length;	    /* length of address */

    /* list of addresses from name server */
    struct IN_ADDR h_addr_list[IRC_MAXADDRS];

#define	h_addr	h_addr_list[0]	    /* address, for backward compatiblity */
};

typedef struct cache
{
    time_t      expireat;
    time_t      ttl;
    struct hostent he;
    struct cache *hname_next, *hnum_next, *list_next;
} aCache;

#define	IRC_MAXCACHED	281

#endif /* __res_include__ */
