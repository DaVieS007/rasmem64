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
 * rasmem - pattern test engine, page ownership and physical memory helpers.
 *
 * Memory is accessed through the direct map.  A pattern pass writes every
 * span with non-temporal stores (MOVNTI), which bypass/evict the cache,
 * optionally CLFLUSHes it, optionally waits (retention test), and finally
 * reads everything back, so the read-back comes from DRAM, not from the CPU
 * cache.  March C- works one cache line at a time and CLFLUSHes each line
 * after its read/write element, which is the granularity DRAM actually sees.
 *
 * Only memory that rasmem owns is ever written: free pages taken out of the
 * VM free lists for exactly the physical range under test, or pages on the
 * VM's own boot-time blacklist (owned by nobody).  Memory holding data is
 * never moved to test it; rasmem tests free memory only.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/pmap.h>

#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <machine/vmparam.h>

#include <dev/rasmem/rasmem_var.h>

#if !defined(__amd64__)
#error "rasmem currently supports amd64 only (needs the direct map and MOVNTI)"
#endif

/* PHYS_TO_DMAP() returns vm_offset_t up to 15.x and void * in 16.x. */
#ifdef PHYS_TO_DMAP_ADDR
#define	RAS_DMAP(pa)	((volatile uint64_t *)PHYS_TO_DMAP_ADDR(pa))
#else
#define	RAS_DMAP(pa)	((volatile uint64_t *)PHYS_TO_DMAP(pa))
#endif

/* ------------------------------------------------------------------------ */
/* Pattern engine                                                           */
/* ------------------------------------------------------------------------ */

/* Read-back hook; overridden by the userland fault-injection harness. */
#ifndef RAS_LOAD
#define	RAS_LOAD(p)	(*(p))
#endif

enum { K_CONST, K_ADDR, K_WALK, K_RAND };

struct ras_pass
{
	int		kind;
	int		bit;
	uint64_t	arg;
	uint64_t	inv;
	uint64_t	seed;
};

static const char *rasmem_pat_names[RASMEM_PAT_NBITS] = {
	"zero", "ones", "checker", "addr", "walk1", "walk0", "random", "march"
};

const char *rasmem_pattern_name(int bit)
{

	if (bit < 0 || bit >= RASMEM_PAT_NBITS)
	{
		return ("?");
	}
	return (rasmem_pat_names[bit]);
}

static __inline void ras_store_nt(volatile uint64_t *p, uint64_t v)
{

	__asm __volatile("movnti %1, %0" : "=m" (*p) : "r" (v) : "memory");
}

static __inline uint64_t ras_rand(uint64_t *s)
{
	uint64_t x;

	/* xorshift64* */
	x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return (x * 0x2545F4914F6CDD1DULL);
}

static __inline uint64_t ras_val(int kind, uint64_t arg, uint64_t addr, size_t i, uint64_t *rs)
{

	switch (kind)
	{
	case K_CONST:
		return (arg);
	case K_ADDR:
		return (addr);
	case K_WALK:
		return (1ULL << ((i + arg) & 63));
	default:
		return (ras_rand(rs));
	}
}

static bool ras_have_clflushopt;

static __inline void ras_flush_line(u_long addr)
{

	if (ras_have_clflushopt)
	{
		clflushopt(addr);	/* weakly ordered: fenced by callers */
	}
	else
	{
		clflush(addr);
	}
}

static u_int ras_line(void)
{

	return (cpu_clflush_line_size != 0 ? cpu_clflush_line_size : 64);
}

static void ras_flush(volatile uint64_t *va, size_t len, bool force)
{
	vm_offset_t p, e;
	u_int line;

	if ((!rasmem_cache_flush && !force) || (cpu_feature & CPUID_CLFSH) == 0)
	{
		return;
	}
	line = ras_line();
	mfence();
	for (p = (vm_offset_t)va, e = p + len; p < e; p += line)
	{
		ras_flush_line(p);
	}
	mfence();
}

static __inline void ras_bad(struct rasmem_fail *fails, size_t i, uint64_t x, int bit)
{
	struct rasmem_fail *f;
	size_t off;

	off = i * sizeof(uint64_t);
	f = &fails[off >> PAGE_SHIFT];
	if (f->nbad == 0)
	{
		f->first_off = off & PAGE_MASK;
		f->pattern = bit;
	}
	if (f->nbad != UINT32_MAX)
	{
		f->nbad++;
	}
	f->xor_or |= x;
	f->last_xor = x;
}

static __inline uint64_t ras_seed(uint64_t seed, vm_paddr_t pa)
{
	uint64_t s;

	s = seed ^ (pa * 0x9E3779B97F4A7C15ULL);
	return (s != 0 ? s : 1);
}

static void ras_write(vm_paddr_t pa, size_t nwords, const struct ras_pass *p)
{
	volatile uint64_t *base;
	uint64_t rs;
	size_t i;

	base = RAS_DMAP(pa);
	rs = ras_seed(p->seed, pa);
	for (i = 0; i < nwords; i++)
	{
		ras_store_nt(&base[i], ras_val(p->kind, p->arg, pa + i * sizeof(uint64_t), i, &rs) ^ p->inv);
	}
	sfence();
	ras_flush(base, nwords * sizeof(uint64_t), false);
}

static void ras_verify(vm_paddr_t pa, size_t nwords, const struct ras_pass *p, struct rasmem_fail *fails)
{
	volatile uint64_t *base;
	uint64_t exp, got, rs;
	size_t i;

	base = RAS_DMAP(pa);
	rs = ras_seed(p->seed, pa);
	for (i = 0; i < nwords; i++)
	{
		exp = ras_val(p->kind, p->arg, pa + i * sizeof(uint64_t), i, &rs) ^ p->inv;
		got = RAS_LOAD(&base[i]);
		if (__predict_false(got != exp))
		{
			ras_bad(fails, i, got ^ exp, p->bit);
		}
	}
}

/* Number of write/verify passes a pattern bit expands to (March: 0). */
static int ras_npasses(int bit)
{

	switch (1u << bit)
	{
	case RASMEM_PAT_CHECKER:
	case RASMEM_PAT_ADDR:
		return (2);
	case RASMEM_PAT_WALK1:
	case RASMEM_PAT_WALK0:
		return (64);
	case RASMEM_PAT_MARCH:
		return (0);
	default:
		return (1);
	}
}

static void ras_pass_get(int bit, int sub, uint64_t seed, struct ras_pass *p)
{

	bzero(p, sizeof(*p));
	p->bit = bit;
	switch (1u << bit)
	{
	case RASMEM_PAT_ZERO:
		p->kind = K_CONST;
		break;
	case RASMEM_PAT_ONES:
		p->kind = K_CONST;
		p->arg = ~0ULL;
		break;
	case RASMEM_PAT_CHECKER:
		p->kind = K_CONST;
		p->arg = sub == 0 ? 0x5555555555555555ULL : 0xAAAAAAAAAAAAAAAAULL;
		break;
	case RASMEM_PAT_ADDR:
		p->kind = K_ADDR;
		p->inv = sub == 0 ? 0 : ~0ULL;
		break;
	case RASMEM_PAT_WALK1:
	case RASMEM_PAT_WALK0:
		/*
		 * Word i holds bit (i + sub) % 64; over 64 passes every word
		 * sees a single 1 (or 0) in every bit position.
		 */
		p->kind = K_WALK;
		p->arg = sub;
		p->inv = (1u << bit) == RASMEM_PAT_WALK0 ? ~0ULL : 0;
		break;
	case RASMEM_PAT_RANDOM:
		p->kind = K_RAND;
		p->seed = seed;
		break;
	}
}

/*
 * One March element over a range: for every word (in ascending or
 * descending address order) read and expect rv, then write wv if do_write.
 * Works one cache line at a time and CLFLUSHes the line afterwards, so each
 * element reads the line from DRAM and writes it back to DRAM.
 */
static void ras_march_elem(volatile uint64_t *base, size_t nwords, uint64_t rv, uint64_t wv, bool do_write, bool up, int bit, struct rasmem_fail *fails)
{
	size_t wpl, nlines, l, ln, k, i;
	uint64_t v;

	wpl = ras_line() / sizeof(uint64_t);
	nlines = nwords / wpl;
	for (l = 0; l < nlines; l++)
	{
		ln = up ? l : nlines - 1 - l;
		for (k = 0; k < wpl; k++)
		{
			i = ln * wpl + (up ? k : wpl - 1 - k);
			v = RAS_LOAD(&base[i]);
			if (__predict_false(v != rv))
			{
				ras_bad(fails, i, v ^ rv, bit);
			}
			if (do_write)
			{
				base[i] = wv;
			}
		}
		if (do_write)
		{
			ras_flush_line((u_long)&base[ln * wpl]);
		}
	}
	mfence();
}

/*
 * March C- on 64-bit words with data background bg:
 *   M0 up w(a); M1 up r(a)w(b); M2 up r(b)w(a); M3 down r(a)w(b);
 *   M4 down r(b)w(a); M5 r(a)
 * Detects stuck-at, transition, address-decoder and most coupling faults
 * between lines, which plain write-all/read-all patterns miss.
 */
static void ras_march(vm_paddr_t pa, size_t nwords, uint64_t bg, int bit, struct rasmem_fail *fails)
{
	volatile uint64_t *base;
	uint64_t a, b;
	size_t i;

	base = RAS_DMAP(pa);
	a = bg;
	b = ~bg;
	for (i = 0; i < nwords; i++)
	{
		ras_store_nt(&base[i], a);
	}
	sfence();
	ras_flush(base, nwords * sizeof(uint64_t), true);
	ras_march_elem(base, nwords, a, b, true, true, bit, fails);
	ras_march_elem(base, nwords, b, a, true, true, bit, fails);
	ras_march_elem(base, nwords, a, b, true, false, bit, fails);
	ras_march_elem(base, nwords, b, a, true, false, bit, fails);
	ras_march_elem(base, nwords, a, a, false, true, bit, fails);
}

/*
 * Test a set of owned spans.  Every pass writes all spans before verifying
 * any of them, so the time between write and read of a cell is at least the
 * time to write the whole set; for patterns in hold_mask the engine also
 * sleeps hold_ms between the two (retention test).  fails[] must hold one
 * entry per page of all spans (indexed by span.fidx).  Returns the number of
 * failing pages; *bytes is incremented by the number of bytes verified.
 */
uint32_t rasmem_test_spans(struct rasmem_span *s, u_int ns, uint32_t patterns, int hold_ms, uint32_t hold_mask, bool can_sleep, struct rasmem_fail *fails, uint64_t *bytes)
{
	struct ras_pass p;
	uint64_t seed, total;
	uint32_t nfail;
	u_int i, j;
	int bit, sub, np;

	total = 0;
	for (j = 0; j < ns; j++)
	{
		total += s[j].npages;
	}
	bzero(fails, total * sizeof(*fails));

	for (bit = 0; bit < RASMEM_PAT_NBITS; bit++)
	{
		if ((patterns & (1u << bit)) == 0)
		{
			continue;
		}
		if ((1u << bit) == RASMEM_PAT_MARCH)
		{
			for (j = 0; j < ns; j++)
			{
				ras_march(s[j].pa, ptoa(s[j].npages) / 8, 0, bit, fails + s[j].fidx);
				ras_march(s[j].pa, ptoa(s[j].npages) / 8, 0x5555555555555555ULL, bit, fails + s[j].fidx);
				if (can_sleep)
				{
					maybe_yield();
				}
			}
			/* 2 backgrounds x 5 read elements */
			*bytes += ptoa(total) * 10;
			continue;
		}
		seed = 0;
		if ((1u << bit) == RASMEM_PAT_RANDOM)
		{
			seed = get_cyclecount() ^ 0x9E3779B97F4A7C15ULL;
		}
		np = ras_npasses(bit);
		for (sub = 0; sub < np; sub++)
		{
			ras_pass_get(bit, sub, seed, &p);
			for (j = 0; j < ns; j++)
			{
				ras_write(s[j].pa, ptoa(s[j].npages) / 8, &p);
			}
			if (hold_ms > 0 && can_sleep && (hold_mask & (1u << bit)) != 0)
			{
				rasmem_hold_wait(MAX(1, (hold_ms * hz) / 1000));
			}
			for (j = 0; j < ns; j++)
			{
				ras_verify(s[j].pa, ptoa(s[j].npages) / 8, &p, fails + s[j].fidx);
			}
			*bytes += ptoa(total);
			if (can_sleep)
			{
				maybe_yield();
			}
		}
	}

	for (i = 0, nfail = 0; i < total; i++)
	{
		if (fails[i].nbad != 0)
		{
			nfail++;
		}
	}
	return (nfail);
}

/* Single contiguous range, no retention hold. */
uint32_t rasmem_test_range(vm_paddr_t pa, u_int npages, uint32_t patterns, bool can_sleep, struct rasmem_fail *fails, uint64_t *bytes)
{
	struct rasmem_span s;

	bzero(&s, sizeof(s));
	s.pa = pa;
	s.npages = npages;
	return (rasmem_test_spans(&s, 1, patterns, 0, 0, can_sleep, fails, bytes));
}

/* Global address-line test helpers (write and verify done separately). */
void rasmem_fill_addr(vm_paddr_t pa, u_int npages, bool inv)
{
	struct ras_pass p;

	ras_pass_get(ffs(RASMEM_PAT_ADDR) - 1, inv ? 1 : 0, 0, &p);
	ras_write(pa, ptoa(npages) / 8, &p);
}

uint32_t rasmem_check_addr(vm_paddr_t pa, u_int npages, bool inv, struct rasmem_fail *fails)
{
	struct ras_pass p;
	uint32_t nfail;
	u_int i;

	bzero(fails, npages * sizeof(*fails));
	ras_pass_get(ffs(RASMEM_PAT_ADDR) - 1, inv ? 1 : 0, 0, &p);
	ras_verify(pa, ptoa(npages) / 8, &p, fails);
	for (i = 0, nfail = 0; i < npages; i++)
	{
		if (fails[i].nbad != 0)
		{
			nfail++;
		}
	}
	return (nfail);
}

/* ------------------------------------------------------------------------ */
/* Page ownership                                                           */
/* ------------------------------------------------------------------------ */

/*
 * Dependence on VM internals.
 *
 * Taking memory goes through the allocator only
 * (vm_page_alloc_noobj_contig_domain()), which is authoritative.  Two
 * things read vm_page fields directly, without locks, and are only hints:
 *
 *  - "is this page free?" (object == NULL && ref_count == 0), which saves
 *    allocator calls for ranges that are obviously in use;
 *  - rasmem_used_mask() (object, ref_count, oflags), which decides whether
 *    the data on a page already known to be bad can be moved off it
 *    (hw.rasmem.evacuate only).
 *
 * A wrong hint can cost coverage or time, never a wrong write.  Even so the
 * hints are checked against the allocator at load (rasmem_hints_check())
 * and switched off if they disagree, e.g. if a future VM changes what these
 * fields mean for free pages.
 *
 * Since FreeBSD 15 the VM initializes the page structures of free memory
 * lazily (debug.vm.lazy_page_init): at boot only the first page of each
 * free block is set up and a background thread, started at SI_SUB_SMP,
 * does the rest.  rasmem's boot phases run before that, so the hints would
 * read uninitialized memory.  vm_phys_find_range() completes the
 * initialization of a domain as a side effect (it does nothing once the
 * domain is done).  Correctness does not depend on this: without it the
 * hint check fails and rasmem works from the allocator alone.
 */
static bool ras_hints = true;		/* page structure hints usable */

bool rasmem_hints_enabled(void)
{

	return (ras_hints);
}

static bool ras_hint_free(vm_page_t m)
{

	return (atomic_load_ptr(&m->object) == NULL && atomic_load_int(&m->ref_count) == 0);
}

void rasmem_vm_init_pages(void)
{
#ifdef VM_FREEPOOL_LAZYINIT
	vm_page_t bounds[2];
	int domain;

	for (domain = 0; domain < vm_ndomains; domain++)
	{
		(void)vm_phys_find_range(bounds, 0, domain, 1, 0, ~(vm_paddr_t)0);
	}
#endif
}

/*
 * Failed allocator calls are expensive for the whole system: the contiguous
 * allocator searches the free lists linearly while holding the domain's
 * free page lock, which every page fault also needs, and each failure adds
 * to the page daemon's deficit, so it starts reclaiming memory.  rasmem
 * therefore asks only for pieces of RASMEM_SUB_PAGES or more at runtime
 * (short free lists), checks the hints first, and limits the failures per
 * run (rasmem_win_budget()).
 */
static volatile u_int ras_alloc_fails;

/* Allocate exactly [pa, pa + npages); NULL if that is not one free run. */
static vm_page_t ras_alloc_at(vm_paddr_t pa, u_long npages, int domain, int req)
{
	vm_page_t m;

	m = vm_page_alloc_noobj_contig_domain(domain, req, npages, pa, pa + ptoa(npages), PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (m == NULL)
	{
		atomic_add_int(&ras_alloc_fails, 1);
	}
	if (m != NULL && VM_PAGE_TO_PHYS(m) != pa)
	{
		rasmem_release(m, npages);
		m = NULL;
	}
	return (m);
}

/*
 * The buddy allocator keeps free memory in naturally aligned power-of-two
 * blocks, and vm_phys_alloc_contig() only hands out runs that start at the
 * first page of a free block.  Free memory is mostly in large blocks (16 MiB
 * on amd64), so a range in the middle of a free block cannot be allocated
 * directly: rasmem allocates from the block's head up to pa + npages and
 * gives the prefix back.
 */
static vm_page_t ras_alloc_from(vm_paddr_t head, vm_paddr_t pa, u_long npages, int domain, int req)
{
	vm_page_t m;
	u_long pre;

	if (head == pa)
	{
		return (ras_alloc_at(pa, npages, domain, req));
	}
	pre = atop(pa - head);
	m = ras_alloc_at(head, pre + npages, domain, req);
	if (m == NULL)
	{
		return (NULL);
	}
	rasmem_release(m, pre);
	return (m + pre);
}

/*
 * With the hints: the head of the free block that contains pa.  Buddy
 * blocks are naturally aligned and fully coalesced, so it is the earliest
 * aligned candidate (rounddown2(pa, size), largest size first) that does not
 * reach back past the nearest page below pa in use.  This is one allocator
 * call for a free range, wherever it sits in its block; trying pa itself
 * first would cost a failed call for every range inside a block.
 */
static vm_paddr_t ras_guess_head(vm_paddr_t pa, u_long npages, vm_paddr_t seg_start)
{
	vm_paddr_t head, lim, used;
	vm_page_t m;
	int j;

	lim = pa - ptoa(MIN(atop(pa - seg_start), ((vm_paddr_t)1 << (RAS_NFREEORDER - 1)) - 1));
	for (used = pa; used > lim; used -= PAGE_SIZE)
	{
		m = PHYS_TO_VM_PAGE(used - PAGE_SIZE);
		if (m == NULL || !ras_hint_free(m))
		{
			break;
		}
	}
	for (j = RAS_NFREEORDER - 1; j > flsl(npages - 1); j--)
	{
		head = rounddown2(pa, ptoa((vm_paddr_t)1 << j));
		if (head >= used && head >= seg_start)
		{
			return (head);
		}
	}
	return (pa);
}

/*
 * Without the hints: the block containing pa starts at pa rounded down to
 * its size, so try each candidate size, smallest first.  Only allocator
 * calls, no page structure is read.  pa itself has been tried already.
 */
static vm_page_t ras_alloc_inside(vm_paddr_t pa, u_long npages, int domain, int req, vm_paddr_t seg_start)
{
	vm_paddr_t head, prev;
	vm_page_t m;
	int j;

	prev = pa;
	for (j = flsl(npages - 1) + 1; j < RAS_NFREEORDER; j++)
	{
		head = rounddown2(pa, ptoa((vm_paddr_t)1 << j));
		if (head < seg_start)
		{
			return (NULL);
		}
		if (head == prev)
		{
			continue;	/* same candidate as the smaller size */
		}
		prev = head;
		m = ras_alloc_from(head, pa, npages, domain, req);
		if (m != NULL)
		{
			return (m);
		}
	}
	return (NULL);
}

/*
 * Take [pa, pa + npages) out of the free lists.  Returns NULL if any page of
 * the range is not free.  The pages are wired and unmanaged, nobody else
 * will touch them until rasmem_release().  The range must not cross a
 * vm_phys segment.
 *
 * The range is taken as its naturally aligned power-of-two pieces, lowest
 * first.  Only the first piece can sit inside a larger free block: every
 * later piece is preceded by a page that rasmem already holds, so a free
 * block containing it must start at it.
 */
vm_page_t rasmem_grab(vm_paddr_t pa, u_int npages, int domain, int reqx)
{
	vm_paddr_t cur, end, seg_start, seg_end;
	vm_page_t m, first;
	u_long n;
	u_int i;
	int k, req;

	/*
	 * Cheap, lockless pre-check (see above): it avoids allocator calls
	 * for ranges that are obviously in use.
	 */
	for (i = 0; ras_hints && i < npages; i++)
	{
		m = PHYS_TO_VM_PAGE(pa + ptoa(i));
		if (m == NULL || !ras_hint_free(m))
		{
			return (NULL);
		}
	}
	if (!rasmem_pa_seg(pa, &seg_start, &seg_end) || pa + ptoa(npages) > seg_end)
	{
		return (NULL);
	}

	req = VM_ALLOC_NORMAL | VM_ALLOC_NOWAIT | VM_ALLOC_WIRED | reqx;
	first = NULL;
	end = pa + ptoa(npages);
	for (cur = pa; cur < end; cur += ptoa(n))
	{
		/* Largest aligned power of two that starts at cur and fits. */
		k = MIN(ffsll(atop(cur)) - 1, RAS_NFREEORDER - 1);
		if (atop(cur) == 0)
		{
			k = RAS_NFREEORDER - 1;
		}
		while (cur + ptoa((vm_paddr_t)1 << k) > end)
		{
			k--;
		}
		n = 1UL << k;
		if (cur == pa && ras_hints)
		{
			/*
			 * One call: a free range succeeds, one the hints
			 * misjudge (per-CPU caches, superpage reservations)
			 * costs one failure.
			 */
			m = ras_alloc_from(ras_guess_head(cur, n, seg_start), cur, n, domain, req);
		}
		else
		{
			m = ras_alloc_at(cur, n, domain, req);
			if (m == NULL && cur == pa)
			{
				m = ras_alloc_inside(cur, n, domain, req, seg_start);
			}
		}
		if (m == NULL)
		{
			if (first != NULL)
			{
				rasmem_release(first, atop(cur - pa));
			}
			return (NULL);
		}
		if (first == NULL)
		{
			first = m;
		}
	}
	return (first);
}

/*
 * Take [pa, pa + npages), which the hints call free but the allocator does
 * not have, by letting the allocator break the partly used superpage
 * reservation it sits in (vm_reserv_reclaim_contig()).  Breaking moves no
 * data and changes no mapping: the reservation's free pages go back to the
 * free lists, and its owner can no longer get a superpage for that 2 MiB.
 * The kernel does the same under memory pressure.  One allocator call; a
 * failure costs a search of the partly used reservations, and counts
 * against the run's budget like any other.  npages must be <= 511 and the
 * range inside one reservation.
 */
vm_page_t rasmem_grab_break(vm_paddr_t pa, u_int npages, int domain)
{

	return (ras_alloc_at(pa, npages, domain, VM_ALLOC_NORMAL | VM_ALLOC_NOWAIT | VM_ALLOC_WIRED));
}

/*
 * Check the "free" hint against the allocator on a sample of pages spread
 * over all memory.  A page the allocator hands out is free, so a hint
 * calling it "in use" is wrong.  The opposite case is normal: pages cached
 * per CPU or inside superpage reservations are free by the hint but not on
 * the allocator's free lists.  If more than 1 in 10 free pages are
 * misjudged, the hints are switched off.
 */
void rasmem_hints_check(bool enable)
{
	vm_paddr_t pa, seg_start, seg_end;
	vm_page_t m;
	uint64_t total, lin;
	u_int i, k, run, nsample, nfree, wrong;
	int dom, req;
	bool hint;

	if (!enable)
	{
		ras_hints = false;
		RAS_LOG("page structure hints disabled (hw.rasmem.page_hints=0)\n");
		return;
	}
	total = rasmem_segs_pages();
	nsample = 64;
	req = VM_ALLOC_NORMAL | VM_ALLOC_NOWAIT | VM_ALLOC_WIRED | VM_ALLOC_NORECLAIM;
	nfree = wrong = 0;
	for (i = 0; i < nsample && total > 0; i++)
	{
		/*
		 * 64-page pieces spread over memory, away from 16 MiB block
		 * boundaries.  Pieces of that size keep the allocator on its
		 * short free lists (see ras_alloc_fails).
		 */
		lin = (total / nsample) * i + total / nsample / 2;
		if (lin >= total || !rasmem_lin_to_pa(lin, &pa, &run, &dom) || !rasmem_pa_seg(pa, &seg_start, &seg_end))
		{
			continue;
		}
		pa = rounddown2(pa, ptoa(RASMEM_SUB_PAGES)) + ptoa(RASMEM_SUB_PAGES);
		if (pa < seg_start || pa + ptoa(RASMEM_SUB_PAGES) > seg_end)
		{
			continue;
		}
		hint = true;
		for (k = 0; k < RASMEM_SUB_PAGES && hint; k++)
		{
			m = PHYS_TO_VM_PAGE(pa + ptoa(k));
			hint = m != NULL && ras_hint_free(m);
		}
		m = ras_alloc_at(pa, RASMEM_SUB_PAGES, dom, req);
		if (m == NULL)
		{
			m = ras_alloc_inside(pa, RASMEM_SUB_PAGES, dom, req, seg_start);
		}
		if (m == NULL)
		{
			continue;
		}
		nfree++;
		if (!hint)
		{
			wrong++;
		}
		rasmem_release(m, RASMEM_SUB_PAGES);
	}
	ras_hints = nfree == 0 || wrong * 10 <= nfree;
	if (ras_hints)
	{
		RAS_VLOG("page structure hints: %u of %u free sample piece(s) judged correctly\n", nfree - wrong, nfree);
	}
	else
	{
		RAS_LOG("page structure hints disagree with the allocator (%u of %u free pieces look used); using the allocator only\n", wrong, nfree);
	}
}

void rasmem_release(vm_page_t m, u_int npages)
{
	u_int i;

	for (i = 0; i < npages; i++)
	{
		vm_page_unwire_noq(&m[i]);
		vm_page_free(&m[i]);
	}
}

/*
 * Which pages of the range currently hold data (bit i = page i), and can
 * all of them be moved (evacuation)?  Lockless hint, like rasmem_grab().
 */
uint64_t rasmem_used_mask(vm_paddr_t pa, u_int npages, bool *movable)
{
	vm_object_t obj;
	vm_page_t m;
	uint64_t mask;
	u_int i, ref;

	*movable = true;
	if (!ras_hints)
	{
		/* Unknown: let the evacuation itself decide. */
		return (npages >= 64 ? ~0ULL : (1ULL << npages) - 1);
	}
	mask = 0;
	for (i = 0; i < npages && i < 64; i++)
	{
		m = PHYS_TO_VM_PAGE(pa + ptoa(i));
		if (m == NULL)
		{
			*movable = false;
			continue;
		}
		obj = atomic_load_ptr(&m->object);
		ref = atomic_load_int(&m->ref_count);
		if (obj == NULL && ref == 0)
		{
			continue;		/* free (or about to be) */
		}
		mask |= 1ULL << i;
		/* Wired or object-less kernel memory cannot be moved. */
		if (obj == NULL || VPRC_WIRE_COUNT(ref) != 0 || (atomic_load_char(&m->oflags) & VPO_UNMANAGED) != 0)
		{
			*movable = false;
		}
	}
	return (mask);
}

/*
 * Is there comfortably more free memory than the page daemon's target, so
 * that taking (or evacuating) npages more pages cannot push the system into
 * a shortage?  Everything rasmem takes is optional; under pressure it backs
 * off instead of competing with real work.
 */
bool rasmem_mem_ok(uint64_t npages)
{

	return ((uint64_t)vm_free_count() > (uint64_t)vm_cnt.v_free_target + 2 * npages);
}

/*
 * Evacuation: move the movable pages of [pa, pa + npages) (process memory,
 * file cache) elsewhere, so that a known bad page in the range can be
 * isolated.  Only used for pages already known to be bad, never to test
 * memory.  The range must be aligned to its (power of two) size.
 */
bool rasmem_evacuate_range(vm_paddr_t pa, u_int npages, int domain)
{

	return (vm_page_reclaim_contig_domain(domain, VM_ALLOC_NORMAL, npages, pa, pa + ptoa(npages), PAGE_SIZE, 0) == 0);
}

/*
 * Boot chunks: test an owned range, release the good pages, hand the bad
 * ones to rasmem_report(), which keeps them (quarantine).
 */
static void rasmem_test_owned(struct rasmem_span_ctx *c, vm_page_t m, vm_paddr_t pa, u_int npages)
{
	uint32_t nfail;
	u_int i;

	nfail = rasmem_test_range(pa, npages, c->patterns, c->can_sleep, c->fails, &c->bytes);
	c->tested += npages;
	if (nfail != 0)
	{
		c->failed++;
	}
	if (nfail == 0 && !rasmem_have_inuse())
	{
		rasmem_release(m, npages);
		return;
	}
	for (i = 0; i < npages; i++)
	{
		if (c->fails[i].nbad != 0)
		{
			rasmem_report(pa + ptoa(i), &m[i], &c->fails[i], c->src);
		}
		else if (!rasmem_claim_known(pa + ptoa(i), &m[i]))
		{
			rasmem_release(&m[i], 1);
		}
	}
}

/*
 * Test whatever is free in [pa, pa + npages).  Tries the whole span first,
 * then RASMEM_SUB_PAGES sub-spans, then single pages.  The span must not
 * cross a vm_phys segment and npages must be <= RASMEM_CHUNK_PAGES.
 */

void rasmem_test_span(struct rasmem_span_ctx *c, vm_paddr_t pa, u_int npages, int domain)
{
	vm_page_t m;
	u_int i, step;

	if (*c->abort)
	{
		return;
	}
	m = rasmem_grab(pa, npages, domain, c->reqx);
	if (m != NULL)
	{
		rasmem_test_owned(c, m, pa, npages);
		return;
	}
	if (npages == 1)
	{
		c->skipped++;
		return;
	}
	step = npages > RASMEM_SUB_PAGES ? RASMEM_SUB_PAGES : 1;
	for (i = 0; i < npages; i += step)
	{
		rasmem_test_span(c, pa + ptoa(i), MIN(step, npages - i), domain);
	}
}

/*
 * Test boot group gid (one worker per group, so workers never compete for
 * the same buddy block).  A completely free group is one free block: take
 * it in one allocation and test it chunk by chunk.  Otherwise test chunk by
 * chunk, taking what is free.  Updates c->chunks.
 */
void rasmem_test_group(struct rasmem_span_ctx *c, uint64_t gid)
{
	vm_paddr_t gpa, pa;
	vm_page_t m;
	uint64_t cid, cfirst, cend, t, sk, fl;
	u_int gnp, np;
	int dom, gdom;
	uint16_t bits;

	if (!rasmem_group_to_pa(gid, &gpa, &gnp, &gdom, &cfirst, &cend))
	{
		return;
	}
	m = *c->abort ? NULL : rasmem_grab(gpa, gnp, gdom, c->reqx);
	for (cid = cfirst; cid < cend; cid++)
	{
		if (!rasmem_chunk_to_pa(cid, &pa, &np, &dom))
		{
			continue;
		}
		t = c->tested;
		sk = c->skipped;
		fl = c->failed;
		if (m != NULL)
		{
			if (*c->abort)
			{
				rasmem_release(m + atop(pa - gpa), np);
			}
			else
			{
				rasmem_test_owned(c, m + atop(pa - gpa), pa, np);
			}
		}
		else
		{
			rasmem_test_span(c, pa, np, dom);
		}
		c->chunks++;
		/*
		 * The boot test is the "previous pass" of the coverage map,
		 * and counts for the test types it applied to whole chunks.
		 */
		bits = (c->tested != t ? RASMEM_MAP_PREV_TESTED : 0) | (c->skipped != sk ? RASMEM_MAP_PREV_SKIPPED : 0);
		if (c->tested == t + np && c->skipped == sk && c->failed == fl && !*c->abort)
		{
			bits |= RASMEM_MAP_DONE_BASIC;
			if (c->patterns & RASMEM_PAT_MARCH)
			{
				bits |= RASMEM_MAP_DONE_MARCH;
			}
		}
		rasmem_map_mark_pa(pa, np, bits);
		rasmem_map_count_pa(pa, np, c->tested - t);
	}
}

/* ------------------------------------------------------------------------ */
/* Test windows (periodic scan, neighbourhood retests)                      */
/* ------------------------------------------------------------------------ */

u_int rasmem_alloc_failures(void)
{

	return (atomic_load_int(&ras_alloc_fails));
}

/* Allow at most limit failed allocator calls from now (0: no limit). */
void rasmem_win_budget(struct rasmem_window *w, u_int limit)
{

	w->fail_base = atomic_load_int(&ras_alloc_fails);
	w->fail_limit = limit;
}

/* Has this run used up its failed allocator calls? */
bool rasmem_win_spent(const struct rasmem_window *w)
{

	return (w->fail_limit != 0 && atomic_load_int(&ras_alloc_fails) - w->fail_base >= w->fail_limit);
}

void rasmem_win_init(struct rasmem_window *w, u_int maxpages)
{

	bzero(w, sizeof(*w));
	w->maxpages = MAX(maxpages, RASMEM_SUB_PAGES);
	w->spans = malloc(w->maxpages * sizeof(*w->spans), M_RASMEM, M_WAITOK | M_ZERO);
	w->fails = malloc(w->maxpages * sizeof(*w->fails), M_RASMEM, M_WAITOK | M_ZERO);
}

void rasmem_win_fini(struct rasmem_window *w)
{

	free(w->spans, M_RASMEM);
	free(w->fails, M_RASMEM);
	w->spans = NULL;
	w->fails = NULL;
}

static void win_add(struct rasmem_window *w, vm_paddr_t pa, vm_page_t m, u_int n)
{
	struct rasmem_span *s;

	s = &w->spans[w->nspans++];
	s->pa = pa;
	s->m = m;
	s->npages = n;
	s->fidx = w->npages;
	w->npages += n;
}

/*
 * Take what can be had of [pa, pa + npages) into the window: the whole
 * range if it is free, else (larger ranges only) its free RASMEM_SUB_PAGES
 * pieces.  The caller must leave room for npages more pages.  Memory in use
 * is skipped, never moved.
 */
void rasmem_win_collect(struct rasmem_window *w, vm_paddr_t pa, u_int npages, int domain)
{
	vm_page_t m;
	u_int f0, i, step;

	if (w->npages + npages > w->maxpages)
	{
		return;
	}
	if (rasmem_win_spent(w))
	{
		/*
		 * This run has cost the allocator enough.  Callers check
		 * rasmem_win_spent() first and stop, so that the rest is
		 * scanned later instead of being counted as in use; this is
		 * only reached from the split below.
		 */
		w->skipped += npages;
		return;
	}
	f0 = atomic_load_int(&ras_alloc_fails);
	m = rasmem_grab(pa, npages, domain, w->reqx);
	if (m != NULL)
	{
		win_add(w, pa, m, npages);
		return;
	}
	if (ras_hints && npages <= RASMEM_SUB_PAGES && atomic_load_int(&ras_alloc_fails) != f0)
	{
		/*
		 * The hints call the range free, yet the allocator refused
		 * it: the VM holds it, nearly always in a partly used
		 * superpage reservation (rarely in a per-CPU page cache).
		 */
		if (w->may_break && !rasmem_win_spent(w) && (m = rasmem_grab_break(pa, npages, domain)) != NULL)
		{
			w->breaks++;
			win_add(w, pa, m, npages);
			return;
		}
		w->held += npages;
	}
	/*
	 * No smaller pieces at runtime: small requests make the allocator
	 * walk its longest free lists under the free page lock.  A range that
	 * is partly in use is left for a later pass (or the retry).
	 */
	if (npages <= RASMEM_SUB_PAGES)
	{
		w->skipped += npages;
		return;
	}
	step = RASMEM_SUB_PAGES;
	for (i = 0; i < npages; i += step)
	{
		rasmem_win_collect(w, pa + ptoa(i), MIN(step, npages - i), domain);
	}
}

/*
 * Test the collected spans; report failures, release the
 * good pages and empty the window.  Returns the number of pages tested.
 */
uint64_t rasmem_win_run(struct rasmem_window *w, uint32_t patterns, int hold_ms, uint32_t hold_mask, int src, uint64_t *bytes)
{
	struct rasmem_span *s;
	struct rasmem_fail *f;
	uint64_t tested;
	uint32_t nfail;
	u_int i, j;

	if (w->nspans == 0)
	{
		return (0);
	}
	nfail = rasmem_test_spans(w->spans, w->nspans, patterns, hold_ms, hold_mask, true, w->fails, bytes);
	for (j = 0; j < w->nspans; j++)
	{
		s = &w->spans[j];
		if (nfail == 0 && !rasmem_have_inuse())
		{
			rasmem_release(s->m, s->npages);
			continue;
		}
		for (i = 0; i < s->npages; i++)
		{
			f = &w->fails[s->fidx + i];
			if (f->nbad != 0)
			{
				rasmem_report(s->pa + ptoa(i), &s->m[i], f, src);
			}
			else if (!rasmem_claim_known(s->pa + ptoa(i), &s->m[i]))
			{
				rasmem_release(&s->m[i], 1);
			}
		}
	}
	tested = w->npages;
	w->nspans = 0;
	w->npages = 0;
	return (tested);
}

/* ------------------------------------------------------------------------ */
/* Physical memory map                                                      */
/* ------------------------------------------------------------------------ */

static struct rasmem_seg *rasmem_segs;
static int rasmem_nsegs;
static uint64_t rasmem_npages;
static uint64_t rasmem_nchunks;
static uint64_t rasmem_ngroups;

#define	RAS_CHUNK_BYTES	ptoa((vm_paddr_t)RASMEM_CHUNK_PAGES)
#define	RAS_GROUP_BYTES	ptoa((vm_paddr_t)RASMEM_GROUP_PAGES)

/*
 * vm_phys_segs[] is VM-internal.  Check that the snapshot means what rasmem
 * assumes before using it: sorted, non-overlapping, valid domains, and
 * every segment's first and last page have page structures that map back
 * to the same physical address.
 */
static bool ras_segs_valid(void)
{
	struct rasmem_seg *s;
	vm_paddr_t pa[2];
	vm_page_t m;
	int i, k;

	for (i = 0; i < rasmem_nsegs; i++)
	{
		s = &rasmem_segs[i];
		if ((i > 0 && s->start < rasmem_segs[i - 1].end) || s->domain < 0 || s->domain >= vm_ndomains)
		{
			RAS_LOG("physical segment %d (0x%jx-0x%jx, domain %d) is not as expected\n", i, (uintmax_t)s->start, (uintmax_t)s->end, s->domain);
			return (false);
		}
		pa[0] = s->start;
		pa[1] = s->end - PAGE_SIZE;
		for (k = 0; k < 2; k++)
		{
			m = PHYS_TO_VM_PAGE(pa[k]);
			if (m == NULL || VM_PAGE_TO_PHYS(m) != pa[k])
			{
				RAS_LOG("no page structure for physical address 0x%jx\n", (uintmax_t)pa[k]);
				return (false);
			}
		}
	}
	return (true);
}

int rasmem_segs_init(void)
{
	struct rasmem_seg *s;
	vm_paddr_t start, end;
	int i;

	rasmem_segs = malloc(sizeof(*rasmem_segs) * MAX(vm_phys_nsegs, 1), M_RASMEM, M_WAITOK | M_ZERO);
	rasmem_nsegs = 0;
	rasmem_npages = 0;
	rasmem_nchunks = 0;
	rasmem_ngroups = 0;
	for (i = 0; i < vm_phys_nsegs; i++)
	{
		start = round_page(vm_phys_segs[i].start);
		end = trunc_page(vm_phys_segs[i].end);
		if (end <= start)
		{
			continue;
		}
		s = &rasmem_segs[rasmem_nsegs++];
		s->start = start;
		s->end = end;
		s->domain = vm_phys_segs[i].domain;
		/*
		 * Boot chunks and groups are naturally aligned (clipped to
		 * the segment), like the allocator's buddy blocks.
		 */
		s->chunk_base = rounddown2(start, RAS_CHUNK_BYTES);
		s->group_base = rounddown2(start, RAS_GROUP_BYTES);
		s->lin_first = rasmem_npages;
		s->chunk_first = rasmem_nchunks;
		s->group_first = rasmem_ngroups;
		rasmem_npages += atop(end - start);
		rasmem_nchunks += howmany(end - s->chunk_base, RAS_CHUNK_BYTES);
		rasmem_ngroups += howmany(end - s->group_base, RAS_GROUP_BYTES);
		RAS_VLOG("segment %d: 0x%016jx-0x%016jx domain %d (%ju MiB)\n", rasmem_nsegs - 1, (uintmax_t)start, (uintmax_t)end, s->domain, (uintmax_t)((end - start) >> 20));
	}
	if (!ras_segs_valid())
	{
		rasmem_nsegs = 0;
		rasmem_npages = rasmem_nchunks = rasmem_ngroups = 0;
	}
	return (rasmem_nsegs);
}

void rasmem_segs_fini(void)
{

	free(rasmem_segs, M_RASMEM);
	rasmem_segs = NULL;
	rasmem_nsegs = 0;
}

uint64_t rasmem_segs_pages(void)
{

	return (rasmem_npages);
}

uint64_t rasmem_segs_chunks(void)
{

	return (rasmem_nchunks);
}

uint64_t rasmem_segs_groups(void)
{

	return (rasmem_ngroups);
}

/* Linear page index -> physical address and pages left in the segment. */
bool rasmem_lin_to_pa(uint64_t lin, vm_paddr_t *pa, u_int *run, int *domain)
{
	struct rasmem_seg *s;
	uint64_t left;
	int i;

	for (i = rasmem_nsegs - 1; i >= 0; i--)
	{
		s = &rasmem_segs[i];
		if (lin < s->lin_first)
		{
			continue;
		}
		if (lin >= s->lin_first + atop(s->end - s->start))
		{
			return (false);
		}
		*pa = s->start + ptoa(lin - s->lin_first);
		left = atop(s->end - *pa);
		*run = left > UINT_MAX ? UINT_MAX : (u_int)left;
		*domain = s->domain;
		return (true);
	}
	return (false);
}

/* Domain of a physical page, or -1 if it is not managed memory. */
int rasmem_pa_domain(vm_paddr_t pa)
{
	int i;

	for (i = 0; i < rasmem_nsegs; i++)
	{
		if (pa >= rasmem_segs[i].start && pa < rasmem_segs[i].end)
		{
			return (rasmem_segs[i].domain);
		}
	}
	return (-1);
}

/* Linear page number of a physical address. */
bool rasmem_pa_to_lin(vm_paddr_t pa, uint64_t *lin)
{
	int i;

	for (i = 0; i < rasmem_nsegs; i++)
	{
		if (pa >= rasmem_segs[i].start && pa < rasmem_segs[i].end)
		{
			*lin = rasmem_segs[i].lin_first + atop(pa - rasmem_segs[i].start);
			return (true);
		}
	}
	return (false);
}

int rasmem_segs_count(void)
{

	return (rasmem_nsegs);
}

void rasmem_seg_get(int i, struct rasmem_map_seg *out)
{

	bzero(out, sizeof(*out));
	if (i < 0 || i >= rasmem_nsegs)
	{
		return;
	}
	out->start = rasmem_segs[i].start;
	out->end = rasmem_segs[i].end;
	out->lin_first = rasmem_segs[i].lin_first;
	out->domain = rasmem_segs[i].domain;
}

/* Bounds of the segment containing pa. */
bool rasmem_pa_seg(vm_paddr_t pa, vm_paddr_t *start, vm_paddr_t *end)
{
	int i;

	for (i = 0; i < rasmem_nsegs; i++)
	{
		if (pa >= rasmem_segs[i].start && pa < rasmem_segs[i].end)
		{
			*start = rasmem_segs[i].start;
			*end = rasmem_segs[i].end;
			return (true);
		}
	}
	return (false);
}

/*
 * Boot chunk id -> physical range: the id-th naturally aligned 2 MiB block,
 * clipped to its segment.
 */
bool rasmem_chunk_to_pa(uint64_t id, vm_paddr_t *pa, u_int *npages, int *domain)
{
	struct rasmem_seg *s;
	vm_paddr_t lo, hi;
	int i;

	for (i = rasmem_nsegs - 1; i >= 0; i--)
	{
		s = &rasmem_segs[i];
		if (id < s->chunk_first)
		{
			continue;
		}
		lo = s->chunk_base + (id - s->chunk_first) * RAS_CHUNK_BYTES;
		if (lo >= s->end)
		{
			return (false);
		}
		hi = MIN(s->end, lo + RAS_CHUNK_BYTES);
		lo = MAX(lo, s->start);
		*pa = lo;
		*npages = atop(hi - lo);
		*domain = s->domain;
		return (true);
	}
	return (false);
}

/*
 * Boot group id -> physical range (the id-th naturally aligned block of the
 * allocator's largest order, clipped to its segment) and the boot chunks it
 * contains, [*cfirst, *cend).
 */
bool rasmem_group_to_pa(uint64_t id, vm_paddr_t *pa, u_int *npages, int *domain, uint64_t *cfirst, uint64_t *cend)
{
	struct rasmem_seg *s;
	vm_paddr_t lo, hi;
	int i;

	for (i = rasmem_nsegs - 1; i >= 0; i--)
	{
		s = &rasmem_segs[i];
		if (id < s->group_first)
		{
			continue;
		}
		lo = s->group_base + (id - s->group_first) * RAS_GROUP_BYTES;
		if (lo >= s->end)
		{
			return (false);
		}
		hi = MIN(s->end, lo + RAS_GROUP_BYTES);
		lo = MAX(lo, s->start);
		*pa = lo;
		*npages = atop(hi - lo);
		*domain = s->domain;
		*cfirst = s->chunk_first + (rounddown2(lo, RAS_CHUNK_BYTES) - s->chunk_base) / RAS_CHUNK_BYTES;
		*cend = s->chunk_first + (roundup2(hi, RAS_CHUNK_BYTES) - s->chunk_base) / RAS_CHUNK_BYTES;
		return (true);
	}
	return (false);
}

void rasmem_test_init(void)
{

	ras_have_clflushopt = (cpu_stdext_feature & CPUID_STDEXT_CLFLUSHOPT) != 0;
	if ((cpu_feature & CPUID_CLFSH) == 0)
	{
		RAS_LOG("CPU has no CLFLUSH, relying on non-temporal stores only\n");
	}
	else
	{
		RAS_VLOG("cache line flush: %s\n", ras_have_clflushopt ? "CLFLUSHOPT" : "CLFLUSH");
	}
}
