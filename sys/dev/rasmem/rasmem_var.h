/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Viktor Hlavaji (DaVieS) <davies@npulse.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * rasmem - internal kernel declarations.
 */

#ifndef _DEV_RASMEM_RASMEM_VAR_H_
#define	_DEV_RASMEM_RASMEM_VAR_H_

#include <dev/rasmem/rasmem.h>

#include <machine/vmparam.h>

#define	RASMEM_CHUNK_PAGES	512	/* boot-test work unit: 2 MiB */
#define	RASMEM_SUB_PAGES	64	/* periodic / fallback unit (aligned) */
#define	RASMEM_MINI_PAGES	8	/* evacuation granularity */
/*
 * The allocator's number of buddy orders (largest block 16 MiB on amd64).
 * Only used for efficiency (grouping, probing); a different value costs
 * speed, not correctness.
 */
#ifdef VM_NFREEORDER
#define	RAS_NFREEORDER		VM_NFREEORDER
#else
#define	RAS_NFREEORDER		13
#endif

/* Boot work unit: the allocator's largest buddy block. */
#define	RASMEM_GROUP_PAGES	(1u << (RAS_NFREEORDER - 1))

MALLOC_DECLARE(M_RASMEM);

/* Result of testing one page. */
struct rasmem_fail
{
	uint32_t	nbad;		/* bad words seen (all passes)   */
	uint32_t	first_off;	/* offset in page of first bad word */
	uint64_t	xor_or;		/* OR of all XOR masks           */
	uint64_t	last_xor;
	uint8_t		pattern;	/* pattern bit index of first failure */
};

/* A physically contiguous run of pages under test. */
struct rasmem_span
{
	vm_paddr_t	pa;
	vm_page_t	m;		/* first page if owned, else NULL */
	u_int		npages;
	u_int		fidx;		/* index of first page in fails[] */
};

/* State for testing boot chunks (rasmem_test_span()). */
struct rasmem_span_ctx
{
	uint32_t	patterns;	/* RASMEM_PAT_* */
	bool		can_sleep;	/* may yield */
	int		src;		/* RASMEM_SRC_* used for reports */
	int		reqx;		/* extra VM_ALLOC_* flags */
	volatile int	*abort;		/* stop when *abort != 0 */
	struct rasmem_fail *fails;	/* RASMEM_CHUNK_PAGES entries */
	uint64_t	chunks;		/* boot chunks processed */
	uint64_t	failed;		/* ranges with failures */
	uint64_t	tested;		/* pages tested */
	uint64_t	skipped;	/* pages not available */
	uint64_t	bytes;		/* bytes verified */
};

/* A batch of spans collected for one test run (periodic, neighbour). */
struct rasmem_window
{
	struct rasmem_span *spans;
	struct rasmem_fail *fails;
	u_int		maxpages;	/* capacity (pages and spans) */
	u_int		nspans;
	u_int		npages;
	int		reqx;		/* extra VM_ALLOC_* flags */
	bool		may_break;	/* may break superpage reservations */
	uint64_t	skipped;
	uint64_t	held;		/* free by the hints, refused */
	uint64_t	breaks;		/* reservations broken */
	u_int		fail_base;	/* allocator failures at run start */
	u_int		fail_limit;	/* failed allocator calls per run */
};

/* rasmem_test.c: engine */
void		rasmem_test_init(void);
uint32_t	rasmem_test_spans(struct rasmem_span *s, u_int ns, uint32_t patterns, int hold_ms, uint32_t hold_mask, bool can_sleep, struct rasmem_fail *fails, uint64_t *bytes);
uint32_t	rasmem_test_range(vm_paddr_t pa, u_int npages, uint32_t patterns, bool can_sleep, struct rasmem_fail *fails, uint64_t *bytes);
void		rasmem_fill_addr(vm_paddr_t pa, u_int npages, bool inv);
uint32_t	rasmem_check_addr(vm_paddr_t pa, u_int npages, bool inv, struct rasmem_fail *fails);
void		rasmem_test_span(struct rasmem_span_ctx *c, vm_paddr_t pa, u_int npages, int domain);
void		rasmem_test_group(struct rasmem_span_ctx *c, uint64_t gid);
const char	*rasmem_pattern_name(int bit);

/* rasmem_test.c: ownership */
void		rasmem_vm_init_pages(void);
void		rasmem_hints_check(bool enable);
bool		rasmem_hints_enabled(void);
vm_page_t	rasmem_grab(vm_paddr_t pa, u_int npages, int domain, int reqx);
void		rasmem_release(vm_page_t m, u_int npages);
bool		rasmem_evacuate_range(vm_paddr_t pa, u_int npages, int domain);
bool		rasmem_mem_ok(uint64_t npages);
uint64_t	rasmem_used_mask(vm_paddr_t pa, u_int npages, bool *movable);

/* rasmem_test.c: windows */
void		rasmem_win_init(struct rasmem_window *w, u_int maxpages);
void		rasmem_win_budget(struct rasmem_window *w, u_int limit);
bool		rasmem_win_spent(const struct rasmem_window *w);
vm_page_t	rasmem_grab_break(vm_paddr_t pa, u_int npages, int domain);
u_int		rasmem_alloc_failures(void);
void		rasmem_win_fini(struct rasmem_window *w);
void		rasmem_win_collect(struct rasmem_window *w, vm_paddr_t pa, u_int npages, int domain);
uint64_t	rasmem_win_run(struct rasmem_window *w, uint32_t patterns, int hold_ms, uint32_t hold_mask, int src, uint64_t *bytes);

/* rasmem_test.c: physical memory map (snapshot of vm_phys_segs) */
struct rasmem_seg
{
	vm_paddr_t	start;
	vm_paddr_t	end;
	int		domain;
	vm_paddr_t	chunk_base;	/* start rounded down to a chunk */
	vm_paddr_t	group_base;	/* start rounded down to a group */
	uint64_t	lin_first;	/* linear page index of start */
	uint64_t	chunk_first;	/* first boot chunk id        */
	uint64_t	group_first;	/* first boot group id        */
};
int		rasmem_segs_init(void);
void		rasmem_segs_fini(void);
uint64_t	rasmem_segs_pages(void);
uint64_t	rasmem_segs_chunks(void);
uint64_t	rasmem_segs_groups(void);
bool		rasmem_lin_to_pa(uint64_t lin, vm_paddr_t *pa, u_int *run, int *domain);
bool		rasmem_chunk_to_pa(uint64_t id, vm_paddr_t *pa, u_int *npages, int *domain);
bool		rasmem_group_to_pa(uint64_t id, vm_paddr_t *pa, u_int *npages, int *domain, uint64_t *cfirst, uint64_t *cend);
int		rasmem_pa_domain(vm_paddr_t pa);
bool		rasmem_pa_to_lin(vm_paddr_t pa, uint64_t *lin);
int		rasmem_segs_count(void);
void		rasmem_seg_get(int i, struct rasmem_map_seg *out);
bool		rasmem_pa_seg(vm_paddr_t pa, vm_paddr_t *start, vm_paddr_t *end);

/* rasmem_smbios.c */
int		rasmem_smbios_init(void);
void		rasmem_smbios_fini(void);
uint32_t	rasmem_dimm_mask(vm_paddr_t pa);
uint64_t	rasmem_hw_fingerprint(void);
int		rasmem_dimm_count(void);
void		rasmem_dimm_get(int i, struct rasmem_dimm_info *out);
void		rasmem_dimm_names(uint32_t mask, char *buf, size_t len);

/* rasmem.c */
void		rasmem_report(vm_paddr_t pa, vm_page_t m, const struct rasmem_fail *f, int src);
bool		rasmem_have_inuse(void);
void		rasmem_hold_wait(int ticks);
bool		rasmem_claim_known(vm_paddr_t pa, vm_page_t m);
void		rasmem_map_mark_pa(vm_paddr_t pa, uint64_t npages, uint16_t bits);
void		rasmem_map_count_pa(vm_paddr_t pa, uint64_t npages, uint64_t tested);
extern int	rasmem_verbose;
extern int	rasmem_cache_flush;

#define	RAS_VERBOSE()	(bootverbose || rasmem_verbose)
#define	RAS_LOG(...)	printf("rasmem: " __VA_ARGS__)
#define	RAS_VLOG(...)	do {						\
	if (RAS_VERBOSE())						\
		printf("rasmem: " __VA_ARGS__);				\
} while (0)

#endif /* !_DEV_RASMEM_RASMEM_VAR_H_ */
