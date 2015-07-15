/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation, www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/* Copyright (c) 2003-2015 Intel Corporation. All rights reserved. */

#include <netdb.h>		/* gethostbyname */
#include "psm_user.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"

int psmi_ep_device_is_enabled(const psm_ep_t ep, int devid);

struct psmi_epid_table psmi_epid_table;

/* Iterator to access the epid table.
 * 'ep' can be NULL if remote endpoints from all endpoint handles are requested
 */
void psmi_epid_itor_init(struct psmi_eptab_iterator *itor, psm_ep_t ep)
{
	itor->i = 0;
	itor->ep = ep;
	pthread_mutex_lock(&psmi_epid_table.tablock);
}

void *psmi_epid_itor_next(struct psmi_eptab_iterator *itor)
{
	int i;
	struct psmi_epid_tabentry *e;

	if (itor->i >= psmi_epid_table.tabsize)
		return NULL;
	for (i = itor->i; i < psmi_epid_table.tabsize; i++) {
		e = &psmi_epid_table.table[i];
		if (!e->entry || e->entry == EPADDR_DELETED)
			continue;
		if (itor->ep && e->ep != itor->ep)
			continue;
		itor->i = i + 1;
		return e->entry;
	}
	itor->i = psmi_epid_table.tabsize;	/* put at end of table */
	return NULL;
}

void psmi_epid_itor_fini(struct psmi_eptab_iterator *itor)
{
	pthread_mutex_unlock(&psmi_epid_table.tablock);
	itor->i = 0;
}

#define mix64(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>43); \
	b -= c; b -= a; b ^= (a<<9);  \
	c -= a; c -= b; c ^= (b>>8);  \
	a -= b; a -= c; a ^= (c>>38); \
	b -= c; b -= a; b ^= (a<<23); \
	c -= a; c -= b; c ^= (b>>5);  \
	a -= b; a -= c; a ^= (c>>35); \
	b -= c; b -= a; b ^= (a<<49); \
	c -= a; c -= b; c ^= (b>>11); \
	a -= b; a -= c; a ^= (c>>12); \
	b -= c; b -= a; b ^= (a<<18); \
	c -= a; c -= b; c ^= (b>>22); \
}

psm_error_t psmi_epid_init()
{
	pthread_mutexattr_t attr;
	psmi_epid_table.table = NULL, psmi_epid_table.tabsize = 0;
	psmi_epid_table.tabsize_used = 0;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&psmi_epid_table.tablock, &attr);
	pthread_mutexattr_destroy(&attr);
	return PSM_OK;
};

psm_error_t psmi_epid_fini()
{
	if (psmi_epid_table.table != NULL) {
		psmi_free(psmi_epid_table.table);
		psmi_epid_table.table = NULL;
	}
	psmi_epid_table.tabsize = 0;
	psmi_epid_table.tabsize_used = 0;
	return PSM_OK;
}

PSMI_ALWAYS_INLINE(
uint64_t
hash_this(const psm_ep_t ep, const psm_epid_t epid))
{
	uint64_t ep_i = (uint64_t) (uintptr_t) ep;
	uint64_t epid_i = (uint64_t) epid;
	uint64_t hash = 0x9e3779b97f4a7c13LL;
	mix64(ep_i, epid_i, hash);
	return hash;
}

PSMI_ALWAYS_INLINE(
void *
psmi_epid_lookup_inner(psm_ep_t ep, psm_epid_t epid, int remove))
{
	uint64_t key = hash_this(ep, epid);
	struct psmi_epid_tabentry *e;
	void *entry = NULL;
	int idx;

	pthread_mutex_lock(&psmi_epid_table.tablock);
	if (!psmi_epid_table.table)
		goto ret;
	idx = (int)(key % psmi_epid_table.tabsize);
	while (psmi_epid_table.table[idx].entry != NULL) {
		/* An epid can be added twice if there's more than one opened endpoint,
		 * but really we match on epid *and* on endpoint */
		e = &psmi_epid_table.table[idx];
		if (e->entry != EPADDR_DELETED && e->key == key) {
			entry = e->entry;
			if (remove)
				psmi_epid_table.table[idx].entry =
				    EPADDR_DELETED;
			goto ret;
		}
		if (++idx == psmi_epid_table.tabsize)
			idx = 0;
	}
ret:
	pthread_mutex_unlock(&psmi_epid_table.tablock);
	return entry;
}

void *psmi_epid_lookup(psm_ep_t ep, psm_epid_t epid)
{
	void *entry = psmi_epid_lookup_inner(ep, epid, 0);
	if (PSMI_EP_HOSTNAME != ep)
		_HFI_VDBG("lookup of (%p,%" PRIx64 ") returns %p\n", ep, epid,
			  entry);
	return entry;
}

void *psmi_epid_remove(psm_ep_t ep, psm_epid_t epid)
{
	if (PSMI_EP_HOSTNAME != ep)
		_HFI_VDBG("remove of (%p,%" PRIx64 ")\n", ep, epid);
	return psmi_epid_lookup_inner(ep, epid, 1);
}

psm_error_t psmi_epid_add(psm_ep_t ep, psm_epid_t epid, void *entry)
{
	uint64_t key;
	int idx, i, newsz;
	struct psmi_epid_tabentry *e;
	psm_error_t err = PSM_OK;

	if (PSMI_EP_HOSTNAME != ep)
		_HFI_VDBG("add of (%p,%" PRIx64 ") with entry %p\n", ep, epid,
			  entry);
	pthread_mutex_lock(&psmi_epid_table.tablock);
	/* Leave this here, mostly for sanity and for the fact that the epid
	 * table is currently not used in the critical path */
	if (++psmi_epid_table.tabsize_used >
	    (int)(psmi_epid_table.tabsize * PSMI_EPID_TABLOAD_FACTOR)) {
		struct psmi_epid_tabentry *newtab;
		newsz = psmi_epid_table.tabsize + PSMI_EPID_TABSIZE_CHUNK;
		newtab = (struct psmi_epid_tabentry *)
		    psmi_calloc(ep, PER_PEER_ENDPOINT,
				newsz, sizeof(struct psmi_epid_tabentry));
		if (newtab == NULL) {
			err = PSM_NO_MEMORY;
			goto fail;
		}
		if (psmi_epid_table.table) {	/* rehash the table */
			for (i = 0; i < psmi_epid_table.tabsize; i++) {
				e = &psmi_epid_table.table[i];
				if (e->entry == NULL)
					continue;
				/* When rehashing, mark deleted as free again */
				if (e->entry == EPADDR_DELETED) {
					psmi_epid_table.tabsize_used--;
					continue;
				}
				idx = (int)(e->key % newsz);
				while (newtab[idx].entry != NULL)
					if (++idx == newsz)
						idx = 0;
				newtab[idx].entry = e->entry;
				newtab[idx].key = e->key;
				newtab[idx].ep = e->ep;
				newtab[idx].epid = e->epid;
			}
			psmi_free(psmi_epid_table.table);
		}
		psmi_epid_table.table = newtab;
		psmi_epid_table.tabsize = newsz;
	}
	key = hash_this(ep, epid);
	idx = (int)(key % psmi_epid_table.tabsize);
	e = &psmi_epid_table.table[idx];
	while (e->entry && e->entry != EPADDR_DELETED) {
		if (++idx == psmi_epid_table.tabsize)
			idx = 0;
		e = &psmi_epid_table.table[idx];
	}
	e->entry = entry;
	e->key = key;
	e->epid = epid;
	e->ep = ep;

fail:
	pthread_mutex_unlock(&psmi_epid_table.tablock);
	return err;
}

char *psmi_gethostname(void)
{
	/* XXX this will need a lock in a multi-threaded environment */
	static char hostname[80] = { '\0' };
	char *c;

	if (hostname[0] == '\0') {
		gethostname(hostname, sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';	/* no guarantee of nul termination */
		if ((c = strchr(hostname, '.')))
			*c = '\0';
	}

	return hostname;
}

/*
 * Hostname stuff.  We really only register the network portion of the epid
 * since all epids from the same nid are assumed to have the same hostname.
 */
psm_error_t
psmi_epid_set_hostname(uint64_t nid, const char *hostname, int overwrite)
{
	size_t hlen;
	char *h;
	psm_error_t err = PSM_OK;

	if (hostname == NULL)
		return PSM_OK;
	/* First see if a hostname already exists */
	if ((h = psmi_epid_lookup(PSMI_EP_HOSTNAME, nid)) != NULL) {
		if (!overwrite)
			return PSM_OK;

		h = psmi_epid_remove(PSMI_EP_HOSTNAME, nid);
		if (h != NULL)	/* free the previous hostname if so exists */
			psmi_free(h);
	}

	hlen = min(PSMI_EP_HOSTNAME_LEN, strlen(hostname) + 1);
	h = (char *)psmi_malloc(PSMI_EP_NONE, PER_PEER_ENDPOINT, hlen);
	if (h == NULL)
		return PSM_NO_MEMORY;
	snprintf(h, hlen, "%s", hostname);
	h[hlen - 1] = '\0';
	err = psmi_epid_add(PSMI_EP_HOSTNAME, nid, h);
	return err;
}

/* XXX These two functions are not thread safe, we'll use a rotating buffer
 * trick whenever we need to make them thread safe */
const char *psmi_epaddr_get_hostname(psm_epid_t epid)
{
	static char hostnamebufs[4][PSMI_EP_HOSTNAME_LEN];
	static int bufno;
	uint64_t nid = psm_epid_nid(epid);
	char *h, *hostname;

	hostname = hostnamebufs[bufno];
	bufno = (bufno + 1) % 4;

	/* First, if we have registered a host for this epid, just return that, or
	 * else try to return something with lid and context */
	h = psmi_epid_lookup(PSMI_EP_HOSTNAME, nid);
	if (h != NULL)
		return h;
	else {
		snprintf(hostname, PSMI_EP_HOSTNAME_LEN - 1, "LID=%d:%d.%d",
			 (int)PSMI_EPID_GET_LID(epid),
			 (int)PSMI_EPID_GET_CONTEXT(epid),
			 (int)PSMI_EPID_GET_SUBCONTEXT(epid));
		hostname[PSMI_EP_HOSTNAME_LEN - 1] = '\0';
		return hostname;
	}
}

/* This one gives the hostname with a lid */
const char *psmi_epaddr_get_name(psm_epid_t epid)
{
	static char hostnamebufs[4][PSMI_EP_HOSTNAME_LEN];
	static int bufno;
	char *h, *hostname;
	hostname = hostnamebufs[bufno];
	bufno = (bufno + 1) % 4;

	h = psmi_epid_lookup(PSMI_EP_HOSTNAME, psm_epid_nid(epid));
	if (h == NULL)
		return psmi_epaddr_get_hostname(epid);
	else {
		snprintf(hostname, PSMI_EP_HOSTNAME_LEN - 1,
			 "%s (LID=%d:%d.%d)", h,
			 (int)PSMI_EPID_GET_LID(epid),
			 (int)PSMI_EPID_GET_CONTEXT(epid),
			 (int)PSMI_EPID_GET_SUBCONTEXT(epid));
		hostname[PSMI_EP_HOSTNAME_LEN - 1] = '\0';
	}
	return hostname;
}

/* Wrapper, in case we port to OS xyz that doesn't have sysconf */
uintptr_t psmi_getpagesize(void)
{
	static uintptr_t pagesz = (uintptr_t) -1;
	long sz;
	if (pagesz != (uintptr_t) -1)
		return pagesz;
	sz = sysconf(_SC_PAGESIZE);
	if (sz == -1) {
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
				  "Can't query system page size");
	}

	pagesz = (uintptr_t) sz;
	return pagesz;
}

/* If PSM_VERBOSE_ENV is set in the environment, we determine
 * what its verbose level is and print the environment at "INFO"
 * level if the environment's level matches the desired printlevel.
 */
static int psmi_getenv_verblevel = -1;
static int psmi_getenv_is_verblevel(int printlevel)
{
	if (psmi_getenv_verblevel == -1) {
		char *env = getenv("PSM_VERBOSE_ENV");
		if (env && *env) {
			char *ep;
			int val = (int)strtol(env, &ep, 0);
			if (ep == env)
				psmi_getenv_verblevel = 0;
			else if (val == 2)
				psmi_getenv_verblevel = 2;
			else
				psmi_getenv_verblevel = 1;
		} else
			psmi_getenv_verblevel = 0;
	}
	return (printlevel <= psmi_getenv_verblevel);
}

#define GETENV_PRINTF(_level, _fmt, ...)			\
	do {							\
		int nlevel = _level;				\
		if (psmi_getenv_is_verblevel(nlevel))		\
		nlevel = 0;					\
		_HFI_ENVDBG(nlevel, _fmt, ##__VA_ARGS__);	\
	} while (0)

int
psmi_getenv(const char *name, const char *descr, int level,
	    int type, union psmi_envvar_val defval,
	    union psmi_envvar_val *newval)
{
	int used_default = 0;
	union psmi_envvar_val tval;
	char *env = getenv(name);
	int ishex = (type == PSMI_ENVVAR_TYPE_ULONG_FLAGS ||
		     type == PSMI_ENVVAR_TYPE_UINT_FLAGS);

	/* If we're not using the default, always reset the print
	 * level to '1' so the changed value gets seen at low
	 * verbosity */
#define _GETENV_PRINT(used_default, fmt, val, defval) \
	do {	\
		if (used_default)					\
			GETENV_PRINTF(level, "%s%-25s %-40s =>%s" fmt	\
				"\n", level > 1 ? "*" : " ", name,	\
				descr, ishex ? "0x" : " ", val);	\
		else							\
			GETENV_PRINTF(1, "%s%-25s %-40s =>%s"		\
				fmt " (default was%s" fmt ")\n",	\
				level > 1 ? "*" : " ", name, descr,	\
				ishex ? " 0x" : " ", val,		\
				ishex ? " 0x" : " ", defval);		\
	} while (0)

	switch (type) {
	case PSMI_ENVVAR_TYPE_YESNO:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else if (env[0] == 'Y' || env[0] == 'y')
			tval.e_int = 1;
		else if (env[0] == 'N' || env[0] == 'n')
			tval.e_int = 0;
		else {
			char *ep;
			tval.e_ulong = strtoul(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			} else if (tval.e_ulong != 0)
				tval.e_ulong = 1;
		}
		_GETENV_PRINT(used_default, "%s", tval.e_long ? "YES" : "NO",
			      defval.e_int ? "YES" : "NO");
		break;

	case PSMI_ENVVAR_TYPE_STR:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else
			tval.e_str = env;
		_GETENV_PRINT(used_default, "%s", tval.e_str, defval.e_str);
		break;

	case PSMI_ENVVAR_TYPE_INT:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else {
			char *ep;
			tval.e_int = (int)strtol(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			}
		}
		_GETENV_PRINT(used_default, "%d", tval.e_int, defval.e_int);
		break;

	case PSMI_ENVVAR_TYPE_UINT:
	case PSMI_ENVVAR_TYPE_UINT_FLAGS:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else {
			char *ep;
			tval.e_int = (unsigned int)strtoul(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			}
		}
		if (type == PSMI_ENVVAR_TYPE_UINT_FLAGS)
			_GETENV_PRINT(used_default, "%x", tval.e_uint,
				      defval.e_uint);
		else
			_GETENV_PRINT(used_default, "%u", tval.e_uint,
				      defval.e_uint);
		break;

	case PSMI_ENVVAR_TYPE_LONG:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else {
			char *ep;
			tval.e_long = strtol(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			}
		}
		_GETENV_PRINT(used_default, "%ld", tval.e_long, defval.e_long);
		break;
	case PSMI_ENVVAR_TYPE_ULONG_ULONG:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else {
			char *ep;
			tval.e_ulonglong =
			    (unsigned long long)strtoull(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			}
		}
		_GETENV_PRINT(used_default, "%llu",
			      tval.e_ulonglong, defval.e_ulonglong);
		break;
	case PSMI_ENVVAR_TYPE_ULONG:
	case PSMI_ENVVAR_TYPE_ULONG_FLAGS:
	default:
		if (!env || *env == '\0') {
			tval = defval;
			used_default = 1;
		} else {
			char *ep;
			tval.e_ulong = (unsigned long)strtoul(env, &ep, 0);
			if (ep == env) {
				used_default = 1;
				tval = defval;
			}
		}
		if (type == PSMI_ENVVAR_TYPE_ULONG_FLAGS)
			_GETENV_PRINT(used_default, "%lx", tval.e_ulong,
				      defval.e_ulong);
		else
			_GETENV_PRINT(used_default, "%lu", tval.e_ulong,
				      defval.e_ulong);
		break;
	}
#undef _GETENV_PRINT
	*newval = tval;

	return used_default;
}

/*
 * Parsing int parameters set in string tuples.
 * Output array int *vals should be able to store 'ntup' elements.
 * Values are only overwritten if they are parsed.
 * Tuples are always separated by colons ':'
 */
int psmi_parse_str_tuples(const char *string, int ntup, int *vals)
{
	char *b = (char *)string;
	char *e = b;
	int tup_i = 0;
	int n_parsed = 0;
	char *buf = psmi_strdup(NULL, string);
	psmi_assert_always(buf != NULL);

	while (*e && tup_i < ntup) {
		b = e;
		while (*e && *e != ':')
			e++;
		if (e > b) {	/* something to parse */
			char *ep;
			int len = e - b;
			long int l;
			strncpy(buf, b, len);
			buf[len] = '\0';
			l = strtol(buf, &ep, 0);
			if (ep != buf) {	/* successful conversion */
				vals[tup_i] = (int)l;
				n_parsed++;
			}
		}
		if (*e == ':')
			e++;	/* skip delimiter */
		tup_i++;
	}
	psmi_free(buf);
	return n_parsed;
}

/*
 * Memory footprint/usage mode.
 *
 * This can be used for debug or for separating large installations from
 * small/medium ones.  The default is to assume a medium installation.  Large
 * is not that much larger in memory footprint, but we make a conscious effort
 * an consuming only the amount of memory we need.
 */
int psmi_parse_memmode(void)
{
	union psmi_envvar_val env_mmode;
	int used_default =
	    psmi_getenv("PSM_MEMORY", "Memory usage mode (normal or large)",
			PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
			(union psmi_envvar_val)"normal", &env_mmode);
	if (used_default || !strcasecmp(env_mmode.e_str, "normal"))
		return PSMI_MEMMODE_NORMAL;
	else if (!strcasecmp(env_mmode.e_str, "min"))
		return PSMI_MEMMODE_MINIMAL;
	else if (!strcasecmp(env_mmode.e_str, "large") ||
		 !strcasecmp(env_mmode.e_str, "big"))
		return PSMI_MEMMODE_LARGE;
	else {
		_HFI_PRDBG("PSM_MEMORY env value %s unrecognized, "
			   "using 'normal' memory mode instead\n",
			   env_mmode.e_str);
		return PSMI_MEMMODE_NORMAL;
	}
}

static
const char *psmi_memmode_string(int mode)
{
	psmi_assert(mode >= PSMI_MEMMODE_NORMAL && mode < PSMI_MEMMODE_NUM);
	switch (mode) {
	case PSMI_MEMMODE_NORMAL:
		return "normal";
	case PSMI_MEMMODE_MINIMAL:
		return "minimal";
	case PSMI_MEMMODE_LARGE:
		return "large";
	default:
		return "unknown";
	}
}

psm_error_t
psmi_parse_mpool_env(const psm_mq_t mq, int level,
		     const struct psmi_rlimit_mpool *rlim,
		     uint32_t *valo, uint32_t *chunkszo)
{
	uint32_t val;
	const char *env = rlim->env;
	int mode = mq->memmode;
	psm_error_t err = PSM_OK;
	union psmi_envvar_val env_val;

	psmi_assert_always(mode >= PSMI_MEMMODE_NORMAL
			   && mode < PSMI_MEMMODE_NUM);

	psmi_getenv(rlim->env, rlim->descr, rlim->env_level,
		    PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val)rlim->mode[mode].obj_max, &env_val);

	val = env_val.e_uint;
	if (val < rlim->minval || val > rlim->maxval) {
		err = psmi_handle_error(NULL, PSM_PARAM_ERR,
					"Env. var %s=%u is invalid (valid settings in mode PSM_MEMORY=%s"
					" are inclusively between %u and %u)",
					env, val, psmi_memmode_string(mode),
					rlim->minval, rlim->maxval);
		goto fail;
	}

	_HFI_VDBG("%s max=%u,chunk=%u (mode=%s(%u),min=%u,max=%u)\n",
		  env, val, rlim->mode[mode].obj_chunk,
		  psmi_memmode_string(mode), mode, rlim->minval, rlim->maxval);

	*valo = val;
	*chunkszo = rlim->mode[mode].obj_chunk;

fail:
	return err;
}

uint64_t psmi_cycles_left(uint64_t start_cycles, int64_t timeout_ns)
{
	if (timeout_ns < 0)
		return 0ULL;
	else if (timeout_ns == 0ULL || timeout_ns == ~0ULL)
		return ~0ULL;
	else {
		uint64_t t_end = nanosecs_to_cycles(timeout_ns);
		uint64_t t_now = get_cycles() - start_cycles;

		if (t_now >= t_end)
			return 0ULL;
		else
			return (t_end - t_now);
	}
}

uint32_t psmi_get_ipv4addr()
{
	struct hostent *he;
	uint32_t addr = 0;

	he = gethostbyname(psmi_gethostname());
	if (he != NULL && he->h_addrtype == AF_INET && he->h_addr != NULL) {
		memcpy(&addr, he->h_addr, sizeof(uint32_t));
		return addr;
	} else
		return 0;
}

#define PSMI_EP_IS_PTR(ptr)	    ((ptr) != NULL && (ptr) < PSMI_EP_LOGEVENT)

void
psmi_syslog(psm_ep_t ep, int to_console, int level, const char *format, ...)
{
	va_list ap;

	/* If we've never syslogged anything from this ep at the PSM level, make
	 * sure we log context information */
	if (PSMI_EP_IS_PTR(ep) && !ep->did_syslog) {
		char uuid_str[64];
		ep->did_syslog = 1;

		memset(&uuid_str, 0, sizeof(uuid_str));
		psmi_uuid_unparse(ep->uuid, uuid_str);
		hfi_syslog("PSM", 0, LOG_WARNING,
			   "uuid_key=%s,unit=%d,context=%d,subcontext=%d",
			   uuid_str,
			   ep->context.ctrl->ctxt_info.unit,
			   ep->context.ctrl->ctxt_info.ctxt,
			   ep->context.ctrl->ctxt_info.subctxt);
	}

	va_start(ap, format);
	hfi_vsyslog("PSM", to_console, level, format, ap);
	va_end(ap);
}

/* Table of CRCs of all 8-bit messages. */
static uint32_t crc_table[256];

/* Flag: has the table been computed? Initially false. */
static int crc_table_computed;

/* Make the table for a fast CRC. */
static void make_crc_table(void)
{
	uint32_t c;
	int n, k;

	for (n = 0; n < 256; n++) {
		c = (uint32_t) n;
		for (k = 0; k < 8; k++) {
			if (c & 1)
				c = 0xedb88320 ^ (c >> 1);
			else
				c = c >> 1;
		}
		crc_table[n] = c;
	}
	crc_table_computed = 1;
}

/* Update a running CRC with the bytes buf[0..len-1]--the CRC
 * should be initialized to all 1's, and the transmitted value
 * is the 1's complement of the final running CRC (see the
 * crc() routine below)).
 */

static uint32_t update_crc(uint32_t crc, unsigned char *buf, int len)
{
	uint32_t c = crc;
	int n;

	if_pf(!crc_table_computed)
	    make_crc_table();
	for (n = 0; n < len; n++) {
		c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
	}
	return c;
}

/* Return the CRC of the bytes buf[0..len-1]. */
uint32_t psmi_crc(unsigned char *buf, int len)
{
	return update_crc(0xffffffff, buf, len) ^ 0xffffffff;
}

/* Return the HFI type being used for a context */
uint32_t psmi_get_hfi_type(psmi_context_t *context)
{
	return PSMI_HFI_TYPE_OPA1;
}

#define PSMI_FAULTINJ_SPEC_NAMELEN  32
struct psmi_faultinj_spec {
	STAILQ_ENTRY(psmi_faultinj_spec) next;
	char spec_name[PSMI_FAULTINJ_SPEC_NAMELEN];

	unsigned long long num_faults;
	unsigned long long num_calls;

	unsigned int seedp;
	int num;
	int denom;

};

int psmi_faultinj_enabled = 0;
int psmi_faultinj_verbose = 0;
char *psmi_faultinj_outfile = NULL;

static struct psmi_faultinj_spec psmi_faultinj_dummy;
static STAILQ_HEAD(, psmi_faultinj_spec) psmi_faultinj_head =
STAILQ_HEAD_INITIALIZER(psmi_faultinj_head);

void psmi_faultinj_init()
{
	union psmi_envvar_val env_fi;

	psmi_getenv("PSM_FI", "PSM Fault Injection (yes/no)",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_YESNO,
		    PSMI_ENVVAR_VAL_NO, &env_fi);

	psmi_faultinj_enabled = !!env_fi.e_uint;

	if (psmi_faultinj_enabled) {
		char *def = NULL;
		if (!psmi_getenv
		    ("PSM_FI_TRACEFILE", "PSM Fault Injection output file",
		     PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
		     (union psmi_envvar_val)def, &env_fi)) {
			psmi_faultinj_outfile = psmi_strdup(NULL, env_fi.e_str);
		}
	}

	return;
}

void psmi_faultinj_fini()
{
	struct psmi_faultinj_spec *fi;
	FILE *fp;
	int do_fclose = 0;

	if (!psmi_faultinj_enabled || psmi_faultinj_outfile == NULL)
		return;

	if (strncmp(psmi_faultinj_outfile, "stdout", 7) == 0)
		fp = stdout;
	else if (strncmp(psmi_faultinj_outfile, "stderr", 7) == 0)
		fp = stderr;
	else {
		char *c = psmi_faultinj_outfile;
		char buf[192];
		int append = 0;
		if (*c == '+') {
			append = 1;
			++c;
		}
		do_fclose = 1;
		snprintf(buf, sizeof(buf) - 1, "%s.%s", c, __hfi_mylabel);
		buf[sizeof(buf) - 1] = '\0';
		fp = fopen(buf, append ? "a" : "w");
	}

	if (fp != NULL) {
		STAILQ_FOREACH(fi, &psmi_faultinj_head, next) {
			fprintf(fp, "%s:%s PSM_FI_%-12s %2.3f%% => "
				"%2.3f%% %10lld faults/%10lld events\n",
				__progname, __hfi_mylabel, fi->spec_name,
				(double)fi->num * 100.0 / fi->denom,
				(double)fi->num_faults * 100.0 / fi->num_calls,
				fi->num_faults, fi->num_calls);
		}
		fflush(fp);
		if (do_fclose)
			fclose(fp);
	}

	psmi_free(psmi_faultinj_outfile);
	return;
}

/*
 * Intended to be used only once, not in the critical path
 */
struct psmi_faultinj_spec *psmi_faultinj_getspec(char *spec_name, int num,
						 int denom)
{
	struct psmi_faultinj_spec *fi;

	if (!psmi_faultinj_enabled)
		return &psmi_faultinj_dummy;

	STAILQ_FOREACH(fi, &psmi_faultinj_head, next) {
		if (strcmp(fi->spec_name, spec_name) == 0)
			return fi;
	}

	/* We got here, so no spec -- allocate one */
	fi = psmi_malloc(PSMI_EP_NONE, UNDEFINED,
			 sizeof(struct psmi_faultinj_spec));
	strncpy(fi->spec_name, spec_name, PSMI_FAULTINJ_SPEC_NAMELEN - 1);
	fi->spec_name[PSMI_FAULTINJ_SPEC_NAMELEN - 1] = '\0';
	fi->num = num;
	fi->denom = denom;
	fi->num_faults = 0;
	fi->num_calls = 0;

	/*
	 * See if we get a hint from the environment.
	 * Format is
	 * <num:denom:initial_seed>
	 *
	 * By default, we chose the initial seed to be the 'pid'.  If users need
	 * repeatability, they should set initial_seed to be the 'pid' when the
	 * error was observed or force the initial_seed to be a constant number in
	 * each running process.  Using 'pid' is useful because core dumps store
	 * pids and our backtrace format does as well so if a crash is observed for
	 * a specific seed, programs can reuse the 'pid' to regenerate the same
	 * error condition.
	 */
	{
		int fvals[3] = { num, denom, (int)getpid() };
		union psmi_envvar_val env_fi;
		char fvals_str[128];
		char fname[128];
		char fdesc[256];

		snprintf(fvals_str, sizeof(fvals_str) - 1, "%d:%d:1", num,
			 denom);
		fvals_str[sizeof(fvals_str) - 1] = '\0';
		snprintf(fname, sizeof(fname) - 1, "PSM_FI_%s", spec_name);
		fname[sizeof(fname) - 1] = '\0';
		snprintf(fdesc, sizeof(fdesc) - 1, "Fault Injection %s <%s>",
			 fname, fvals_str);

		if (!psmi_getenv(fname, fdesc, PSMI_ENVVAR_LEVEL_HIDDEN,
				 PSMI_ENVVAR_TYPE_STR,
				 (union psmi_envvar_val)fvals_str, &env_fi)) {
			/* not using default values */
			int n_parsed =
			    psmi_parse_str_tuples(env_fi.e_str, 3, fvals);
			if (n_parsed >= 1)
				fi->num = fvals[0];
			if (n_parsed >= 2)
				fi->denom = fvals[1];
			if (n_parsed >= 3)
				fi->seedp = fvals[2];
		}
	}

	STAILQ_INSERT_TAIL(&psmi_faultinj_head, fi, next);
	return fi;
}

int psmi_faultinj_is_fault(struct psmi_faultinj_spec *fi)
{
	int r;
	if (!psmi_faultinj_enabled)	/* never fault if disabled */
		return 0;
	if (fi->num == 0)
		return 0;

	fi->num_calls++;
	r = rand_r(&fi->seedp);
	if (r % fi->denom <= fi->num) {
		fi->num_faults++;
		return 1;
	} else
		return 0;
}

/* For memory allocation, we kind of break the PSM error handling rules.
 * If the caller gets NULL, it has to assume that the error has been handled
 * and should always return PSM_NO_MEMORY */

/*
 * Log memory increments or decrements of type memstats_t.
 */
struct psmi_memtype_hdr {
	struct {
		uint64_t size:48;
		uint64_t magic:8;
		uint64_t type:8;
	};
};

struct psmi_stats_malloc psmi_stats_memory;

void psmi_log_memstats(psmi_memtype_t type, int64_t nbytes)
{
#define _add_max_total(type, nbytes)				\
	psmi_stats_memory.m_ ## type ## _total += (nbytes);	\
	psmi_stats_memory.m_ ## type ## _max = max(		\
	    psmi_stats_memory.m_ ## type ## _total,		\
	    psmi_stats_memory.m_ ## type ## _max);

	switch (type) {
	case PER_PEER_ENDPOINT:
		_add_max_total(perpeer, nbytes);
		break;
	case NETWORK_BUFFERS:
		_add_max_total(netbufs, nbytes);
		break;
	case DESCRIPTORS:
		_add_max_total(descriptors, nbytes);
		break;
	case UNEXPECTED_BUFFERS:
		_add_max_total(unexpbufs, nbytes);
		break;
	case STATS:
		_add_max_total(stats, nbytes);
		break;
	case UNDEFINED:
		_add_max_total(undefined, nbytes);
		break;
	default:
		psmi_assert_always(type == TOTAL);
		break;
	}
	_add_max_total(all, nbytes);
	psmi_stats_memory.m_all_max++;
#undef _add_max_total

	return;
}

// Memory stats will only be collected under debug builds
// Memory stats at O3 optimization will cause memory problems
// because the 8B header to memory will throw off alignment assumptions
//
// This can be re-enabled with padding to prevent alignment issues
// if it is determined that the stats are needed


#ifdef PSM_DEBUG
#define psmi_stats_mask PSMI_STATSTYPE_MEMORY
#else
#define psmi_stats_mask 0
#endif

#ifdef malloc
#undef malloc
#endif
void *psmi_malloc_internal(psm_ep_t ep, psmi_memtype_t type,
			   size_t sz, const char *curloc)
{
	size_t newsz = sz;
	void *newa;

	psmi_assert(sizeof(struct psmi_memtype_hdr) == 8);

	if_pf(psmi_stats_mask & PSMI_STATSTYPE_MEMORY)
	    newsz += sizeof(struct psmi_memtype_hdr);

	newa = malloc(newsz);
	if (newa == NULL) {
		psmi_handle_error(PSMI_EP_NORETURN, PSM_NO_MEMORY,
				  "Out of memory for malloc at %s", curloc);
		return NULL;
	}

	if_pf(psmi_stats_mask & PSMI_STATSTYPE_MEMORY) {
		struct psmi_memtype_hdr *hdr = (struct psmi_memtype_hdr *)newa;
		hdr->size = newsz;
		hdr->type = type;
		hdr->magic = 0x8c;
		psmi_log_memstats(type, newsz);
		newa = (void *)(hdr + 1);
		/* _HFI_INFO("alloc is %p\n", newa); */
	}
	return newa;
}

#ifdef memalign
#undef memalign
#endif
void *psmi_memalign_internal(psm_ep_t ep, psmi_memtype_t type,
			     size_t alignment, size_t sz, const char *curloc)
{
	size_t newsz = sz;
	void *newa;
	int ret;

	psmi_assert(sizeof(struct psmi_memtype_hdr) == 8);

	if_pf(psmi_stats_mask & PSMI_STATSTYPE_MEMORY)
		newsz += sizeof(struct psmi_memtype_hdr);

	ret = posix_memalign(&newa, alignment, newsz);
	if (ret) {
		psmi_handle_error(PSMI_EP_NORETURN, PSM_NO_MEMORY,
				  "Out of memory for malloc at %s", curloc);
		return NULL;
	}

	if_pf(psmi_stats_mask & PSMI_STATSTYPE_MEMORY) {
		struct psmi_memtype_hdr *hdr = (struct psmi_memtype_hdr *)newa;
		hdr->size = newsz;
		hdr->type = type;
		hdr->magic = 0x8c;
		psmi_log_memstats(type, newsz);
		newa = (void *)(hdr + 1);
		/* _HFI_INFO("alloc is %p\n", newa); */
	}
	return newa;
}

#ifdef calloc
#undef calloc
#endif
void *psmi_calloc_internal(psm_ep_t ep, psmi_memtype_t type, size_t nelem,
			   size_t elemsz, const char *curloc)
{
	void *newa = psmi_malloc_internal(ep, type, nelem * elemsz, curloc);
	if (newa == NULL)	/* error handled above */
		return NULL;
	memset(newa, 0, nelem * elemsz);
	return newa;
}

#ifdef strdup
#undef strdup
#endif
void *psmi_strdup_internal(psm_ep_t ep, const char *string, const char *curloc)
{
	size_t len = strlen(string) + 1;
	void *newa = psmi_malloc_internal(ep, UNDEFINED, len, curloc);
	if (newa == NULL)
		return NULL;
	memcpy(newa, string, len);	/* copy with \0 */
	return newa;
}

#ifdef free
#undef free
#endif

void psmi_free_internal(void *ptr)
{
	if_pf(psmi_stats_mask & PSMI_STATSTYPE_MEMORY) {
		struct psmi_memtype_hdr *hdr =
		    (struct psmi_memtype_hdr *)ptr - 1;
		/* _HFI_INFO("hdr is %p, ptr is %p\n", hdr, ptr); */
		psmi_memtype_t type = hdr->type;
		int64_t size = hdr->size;
		int magic = (int)hdr->magic;
		psmi_log_memstats(type, -size);
		psmi_assert_always(magic == 0x8c);
		ptr = (void *)hdr;
	}
	free(ptr);
}

PSMI_ALWAYS_INLINE(
psm_error_t
psmi_coreopt_ctl(const void *core_obj, int optname,
		 void *optval, uint64_t *optlen, int get))
{
	psm_error_t err = PSM_OK;
	char err_string[256];

	switch (optname) {
	case PSM_CORE_OPT_DEBUG:
		/* Sanity check length */
		if (*optlen < sizeof(unsigned)) {
			snprintf(err_string, 256, "Option value length error");
			*optlen = sizeof(unsigned);
			goto fail;
		}

		if (get) {
			*((unsigned *)optval) = hfi_debug;
		} else
			hfi_debug = *(unsigned *)optval;
		break;
	case PSM_CORE_OPT_EP_CTXT:
		{
			/* core object is epaddr */
			psm_epaddr_t epaddr = (psm_epaddr_t) core_obj;

			/* Sanity check epaddr */
			if (!epaddr) {
				snprintf(err_string, 256,
					 "Invalid endpoint address");
				goto fail;
			}

			/* Sanity check length */
			if (*optlen < sizeof(unsigned long)) {
				snprintf(err_string, 256,
					 "Option value length error");
				*optlen = sizeof(void *);
				goto fail;
			}

			if (get) {
				*((unsigned long *)optval) =
				    (unsigned long)epaddr->usr_ep_ctxt;
			} else
				epaddr->usr_ep_ctxt = optval;
		}
		break;
	default:
		/* Unknown/unrecognized option */
		snprintf(err_string, 256, "Unknown PSM_CORE option %u.",
			 optname);
		goto fail;
	}

	return err;

fail:
	/* Unrecognized/unknown option */
	return psmi_handle_error(NULL, PSM_PARAM_ERR, err_string);
}

psm_error_t psmi_core_setopt(const void *core_obj, int optname,
			     const void *optval, uint64_t optlen)
{
	return psmi_coreopt_ctl(core_obj, optname, (void *)optval, &optlen, 0);
}

psm_error_t psmi_core_getopt(const void *core_obj, int optname,
			     void *optval, uint64_t *optlen)
{
	return psmi_coreopt_ctl(core_obj, optname, optval, optlen, 1);
}

/* PSM AM component option handling */
PSMI_ALWAYS_INLINE(
psm_error_t
psmi_amopt_ctl(const void *am_obj, int optname,
	       void *optval, uint64_t *optlen, int get))
{
	psm_error_t err = PSM_OK;

	/* AM object is a psm_epaddr (or NULL for global minimum sz) */
	/* psm_epaddr_t epaddr = (psm_epaddr_t) am_obj; */

	/* All AM options are read-only. */
	if (!get) {
		return err =
		    psmi_handle_error(PSMI_EP_LOGEVENT, PSM_OPT_READONLY,
				      "Attempted to set read-only option value");
	}

	/* Sanity check length -- all AM options are uint32_t. */
	if (*optlen < sizeof(uint32_t)) {
		*optlen = sizeof(uint32_t);
		return err = psmi_handle_error(PSMI_EP_LOGEVENT, PSM_PARAM_ERR,
					       "Option value length error");
	}

	switch (optname) {
	case PSM_AM_OPT_FRAG_SZ:
		*((uint32_t *) optval) = psmi_am_parameters.max_request_short;
		break;
	case PSM_AM_OPT_NARGS:
		*((uint32_t *) optval) = psmi_am_parameters.max_nargs;
		break;
	case PSM_AM_OPT_HANDLERS:
		*((uint32_t *) optval) = psmi_am_parameters.max_handlers;
		break;
	default:
		err =
		    psmi_handle_error(NULL, PSM_PARAM_ERR,
				      "Unknown PSM_AM option %u.", optname);
	}

	return err;
}

psm_error_t psmi_am_setopt(const void *am_obj, int optname,
			   const void *optval, uint64_t optlen)
{
	return psmi_amopt_ctl(am_obj, optname, (void *)optval, &optlen, 0);
}

psm_error_t psmi_am_getopt(const void *am_obj, int optname,
			   void *optval, uint64_t *optlen)
{
	return psmi_amopt_ctl(am_obj, optname, optval, optlen, 1);
}
