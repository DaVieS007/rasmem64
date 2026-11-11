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
 * rasmem - RAS memory test suite for FreeBSD, with or without ECC (beta).
 *
 * Phase 1 (preloaded: SI_SUB_KLD, right after the VM system is up)
 *   - load the bad-page database preloaded by loader(8) ("rasmem_db") and
 *     quarantine the pages that are still free,
 *   - checksum every page of the kernel's read-only image (text + rodata),
 *   - test the free pages that early boot is about to hand out.
 *
 * Phase 2 (SI_SUB_KTHREAD_INIT, before init(8) and the root mount)
 *   - read the memory module inventory (SMBIOS), compare the hardware
 *     fingerprint with the database and re-verify old records if it changed,
 *   - read the VM's own boot-time blacklist (vm.page_blacklist),
 *   - global address-line test: write all free memory, then verify all,
 *   - multi-threaded, CPU-bound per-chunk pattern + March C- test.
 *
 * Phase 3 (kernel process "rasmem", after boot)
 *   - rate-based periodic scan of free memory (default >= 32 GiB/h tested),
 *     spread over all RAM, passing quickly over memory in use and retrying
 *     blocks that were in use,
 *   - retention test (pattern held for hold_ms before it is read back),
 *   - neighbourhood retests around every new bad page,
 *   - retest quarantined pages and classify them (transient/hard),
 *   - verify the read-only checksums,
 *   - health evaluation from history (survives reboots) and severity,
 *     periodic "reboot" / "replace memory" warnings and optional panic,
 *   - persist the database and the loader blacklist.
 *
 * Bad pages are quarantined while the module is loaded by never freeing
 * them.  Across reboots they are excluded by the VM's built-in
 * ram_blacklist mechanism, fed from hw.rasmem.blacklist_path.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cons.h>
#include <sys/devctl.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/gsb_crc32.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/stat.h>
#include <sys/stdarg.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>
#include <sys/filedesc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <machine/cpu.h>

#include <dev/rasmem/rasmem_var.h>

MALLOC_DEFINE(M_RASMEM, "rasmem", "RAS memory test");

/* ------------------------------------------------------------------------ */
/* Tunables / sysctls                                                       */
/* ------------------------------------------------------------------------ */

int rasmem_verbose = 0;
int rasmem_cache_flush = 0;	/* MOVNTI already evicts; 1 = also CLFLUSH */

/* Periodic scan */
static int rasmem_enable = 1;
static int rasmem_interval = 1000;	/* ms between periodic runs */
static int rasmem_scan_mb_per_hour = 32768;
static int rasmem_sweep_hours = 24;
static int rasmem_pages = 0;		/* 0: derived from the rate */
static int rasmem_window_mb = 128;
static int rasmem_evacuate = 1;		/* move live data off known bad pages */
static int rasmem_break_reserv = 1;	/* break partly used reservations */
static int rasmem_page_hints = 1;	/* lockless page structure hints */
static int rasmem_start_delay = 60;
static int rasmem_periodic_patterns = RASMEM_PAT_CHECKER | RASMEM_PAT_ADDR | RASMEM_PAT_RANDOM | RASMEM_PAT_MARCH;
static int rasmem_hold_ms = 1000;
static int rasmem_hold_patterns = RASMEM_PAT_CHECKER;
static int rasmem_hold_every = 10;	/* hold on 1/N of memory per pass */
static int rasmem_march_every = 10;	/* March C- on 1/N of memory per pass */
static int rasmem_neighbor_pages = 64;
static int rasmem_scan_order = 1;	/* 0 sequential, 1 spread */
static int rasmem_retry_pct = 10;	/* extra budget for skipped blocks */

/* Boot */
static int rasmem_early_mb = 64;
static int rasmem_boot_test = 1;	/* 0 off, 1 blocking, 2 background */
static int rasmem_boot_threads = 0;	/* 0: one per CPU */
static int rasmem_boot_patterns = RASMEM_PAT_CHECKER | RASMEM_PAT_ADDR | RASMEM_PAT_MARCH;
static int rasmem_boot_global = 1;
static int rasmem_boot_global_reserve_mb = 512;
static int rasmem_boot_abort_key = 1;	/* console key aborts boot test */

/* Retest / classification */
static int rasmem_retest_patterns = RASMEM_PAT_ALL;
static int rasmem_retest_interval = 600;
static int rasmem_classify_retests = 8;
static int rasmem_release_transient = 0;
static int rasmem_hwchange_action = 1;	/* 0 trust, 1 re-verify */

/* Read-only image */
static int rasmem_ro_interval = 300;
static int rasmem_ro_action = 1;	/* 0 log, 1 corruption event, 2 panic */

/* Escalation */
static int rasmem_warn_threshold = 1;	/* corruption events this boot */
static int rasmem_warn_interval = 60;
static int rasmem_panic_threshold = 0;	/* corruption events, 0: never */
static int rasmem_panic_save_timeout = 120;
static int rasmem_replace_pages = 16;
static int rasmem_trend_days = 7;
static int rasmem_trend_pages = 4;
static int rasmem_lane_pages = 4;
static int rasmem_dimm_pages = 4;
static int rasmem_replace_warn_interval = 3600;

/* Persistence / misc */
static int rasmem_save_interval = 300;
static int rasmem_max_records = 4096;
static int rasmem_allow_inject = 0;
static char rasmem_db_path[MAXPATHLEN] = "/boot/rasmem.db";
static char rasmem_bl_path[MAXPATHLEN] = "/boot/rasmem_blacklist.txt";

SYSCTL_NODE(_hw, OID_AUTO, rasmem, CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "RAS memory test suite (beta)");
SYSCTL_CONST_STRING(_hw_rasmem, OID_AUTO, version, CTLFLAG_RD, RASMEM_VERSION, "rasmem release");

#define	RAS_INT(name, flags, var, descr)				\
	SYSCTL_INT(_hw_rasmem, OID_AUTO, name, flags, &var, 0, descr)

RAS_INT(verbose, CTLFLAG_RWTUN, rasmem_verbose, "Verbose logging (also enabled by booting with -v)");
RAS_INT(cache_flush, CTLFLAG_RWTUN, rasmem_cache_flush, "CLFLUSH after non-temporal pattern writes");

RAS_INT(enable, CTLFLAG_RWTUN, rasmem_enable, "Enable the periodic scan");
RAS_INT(interval, CTLFLAG_RWTUN, rasmem_interval, "Periodic scan interval (milliseconds, at least 10)");
RAS_INT(scan_mb_per_hour, CTLFLAG_RWTUN, rasmem_scan_mb_per_hour, "Minimum periodic test rate (MiB tested per hour)");
RAS_INT(sweep_hours, CTLFLAG_RWTUN, rasmem_sweep_hours, "Test at least all memory / this many hours per hour (0: off); memory in use is passed over quickly, so passes are shorter on busy machines");
RAS_INT(pages, CTLFLAG_RWTUN, rasmem_pages, "Pages per periodic scan (0: derived from the rate tunables)");
RAS_INT(window_mb, CTLFLAG_RDTUN, rasmem_window_mb, "Maximum memory held for one test window (MiB)");
RAS_INT(break_reserv, CTLFLAG_RWTUN, rasmem_break_reserv, "Test free pages held in partly used superpage reservations by breaking the reservation (no data is moved): 0 never, 1 if it was still partly used a pass earlier, 2 always");
RAS_INT(evacuate, CTLFLAG_RWTUN, rasmem_evacuate, "Move live data off pages already known to be bad, so that they can be isolated");
RAS_INT(page_hints, CTLFLAG_RDTUN, rasmem_page_hints, "Use lockless page structure hints (checked against the allocator at load; reads 0 if switched off)");
RAS_INT(start_delay, CTLFLAG_RWTUN, rasmem_start_delay, "Seconds after load before periodic work starts");
RAS_INT(periodic_patterns, CTLFLAG_RWTUN, rasmem_periodic_patterns, "Patterns for the periodic scan (RASMEM_PAT_*)");
RAS_INT(hold_ms, CTLFLAG_RWTUN, rasmem_hold_ms, "Retention delay between write and read-back (periodic/retest, ms)");
RAS_INT(hold_patterns, CTLFLAG_RWTUN, rasmem_hold_patterns, "Patterns that get the retention delay");
RAS_INT(hold_every, CTLFLAG_RWTUN, rasmem_hold_every, "Retention hold on a rotating 1/N of memory per pass (1: all memory)");
RAS_INT(march_every, CTLFLAG_RWTUN, rasmem_march_every, "March C- on a rotating 1/N of memory per pass (1: all memory)");
RAS_INT(scan_order, CTLFLAG_RWTUN, rasmem_scan_order, "Periodic scan order: 0 by address, 1 spread (bit-reversed 8 MiB slots); takes effect with the next pass");
RAS_INT(retry_pct, CTLFLAG_RWTUN, rasmem_retry_pct, "Extra scan budget (%) for retrying blocks that were in use when the scan passed them (0: off)");
RAS_INT(neighbor_pages, CTLFLAG_RWTUN, rasmem_neighbor_pages, "Pages on each side of a new bad page to retest (0: off)");

RAS_INT(early_mb, CTLFLAG_RDTUN, rasmem_early_mb, "MiB of free memory tested in phase 1 (early boot)");
RAS_INT(boot_test, CTLFLAG_RDTUN, rasmem_boot_test, "Phase 2 full memory test: 0 off, 1 blocking, 2 background");
RAS_INT(boot_threads, CTLFLAG_RDTUN, rasmem_boot_threads, "Phase 2 threads (0: one per CPU)");
RAS_INT(boot_patterns, CTLFLAG_RDTUN, rasmem_boot_patterns, "Patterns for phases 1 and 2");
RAS_INT(boot_global, CTLFLAG_RDTUN, rasmem_boot_global, "Phase 2 global address-line test (write all, then verify all)");
RAS_INT(boot_global_reserve_mb, CTLFLAG_RDTUN, rasmem_boot_global_reserve_mb, "Memory left free during the global test (MiB)");
RAS_INT(boot_abort_key, CTLFLAG_RDTUN, rasmem_boot_abort_key, "A key press on the console aborts the boot test (0: off)");

RAS_INT(retest_patterns, CTLFLAG_RWTUN, rasmem_retest_patterns, "Patterns for retesting bad pages");
RAS_INT(retest_interval, CTLFLAG_RWTUN, rasmem_retest_interval, "Bad page retest interval (seconds, 0 off)");
RAS_INT(classify_retests, CTLFLAG_RWTUN, rasmem_classify_retests, "Clean retests before a bad page is classified transient");
RAS_INT(release_transient, CTLFLAG_RWTUN, rasmem_release_transient, "Give pages classified transient back to the VM system");
RAS_INT(hwchange_action, CTLFLAG_RWTUN, rasmem_hwchange_action, "Memory configuration changed: 0 trust database, 1 re-verify records");

RAS_INT(ro_interval, CTLFLAG_RWTUN, rasmem_ro_interval, "Read-only checksum verify interval (s, 0 off)");
RAS_INT(ro_action, CTLFLAG_RWTUN, rasmem_ro_action, "Read-only checksum mismatch: 0 log, 1 corruption event, 2 panic");

RAS_INT(warn_threshold, CTLFLAG_RWTUN, rasmem_warn_threshold, "Live-data corruption events this boot before 'reboot' warnings (0 off)");
RAS_INT(warn_interval, CTLFLAG_RWTUN, rasmem_warn_interval, "Seconds between 'reboot required' warnings");
RAS_INT(panic_threshold, CTLFLAG_RWTUN, rasmem_panic_threshold, "Panic after this many live-data corruption events this boot (0 off)");
RAS_INT(panic_save_timeout, CTLFLAG_RWTUN, rasmem_panic_save_timeout, "Max seconds a pending panic waits for the database to be saved");
RAS_INT(replace_pages, CTLFLAG_RWTUN, rasmem_replace_pages, "Replace memory: distinct verified non-transient bad pages (0 off)");
RAS_INT(trend_days, CTLFLAG_RWTUN, rasmem_trend_days, "Trend window for new bad pages (days)");
RAS_INT(trend_pages, CTLFLAG_RWTUN, rasmem_trend_pages, "Replace memory: new bad pages within trend_days (0 off)");
RAS_INT(lane_pages, CTLFLAG_RWTUN, rasmem_lane_pages, "Replace memory: bad pages failing in the same data bit (0 off)");
RAS_INT(dimm_pages, CTLFLAG_RWTUN, rasmem_dimm_pages, "Replace memory: bad pages attributed to one DIMM (0 off)");
RAS_INT(replace_warn_interval, CTLFLAG_RWTUN, rasmem_replace_warn_interval, "Seconds between 'replace memory' warnings");

RAS_INT(save_interval, CTLFLAG_RWTUN, rasmem_save_interval, "Seconds between saves of changed statistics");
RAS_INT(max_records, CTLFLAG_RDTUN, rasmem_max_records, "Maximum number of bad page records");
RAS_INT(allow_inject, CTLFLAG_RDTUN, rasmem_allow_inject, "Allow hw.rasmem.inject* (testing only)");
SYSCTL_STRING(_hw_rasmem, OID_AUTO, db_path, CTLFLAG_RWTUN, rasmem_db_path, sizeof(rasmem_db_path), "Bad page database file");
SYSCTL_STRING(_hw_rasmem, OID_AUTO, blacklist_path, CTLFLAG_RWTUN, rasmem_bl_path, sizeof(rasmem_bl_path), "Loader ram_blacklist file written by rasmem");

/* ------------------------------------------------------------------------ */
/* State                                                                    */
/* ------------------------------------------------------------------------ */

struct rasmem_rec
{
	struct rasmem_region	r;
	vm_page_t		m;	/* held page (state HELD) */
};

struct rasmem_worker
{
	int			cpu;
	struct rasmem_fail	*fails;
};

static struct mtx rasmem_mtx;
MTX_SYSINIT(rasmem_mtx, &rasmem_mtx, "rasmem", MTX_DEF);
static struct sx rasmem_save_sx;
SX_SYSINIT(rasmem_save_sx, &rasmem_save_sx, "rasmem save");

static struct rasmem_stats rasmem_st;
static struct rasmem_rec *rasmem_recs;	/* fixed capacity, never moved */
static u_int rasmem_nrec, rasmem_rec_cap;
static bool rasmem_inited;
static bool rasmem_at_boot;		/* loaded by loader(8) */
static int rasmem_dirty;
static int rasmem_urgent_save;
static time_t rasmem_panic_since;
static time_t rasmem_next_warn, rasmem_next_replace_warn;
static uint32_t rasmem_suspect_mask;	/* DIMMs holding active bad pages */
static uint64_t rasmem_db_fp;		/* fingerprint stored in the database */
static bool rasmem_db_loaded;

/* Read-only image checksums. */
static vm_offset_t rasmem_ro_start;
static u_int rasmem_ro_npages;
static uint32_t *rasmem_ro_crc;
static bool rasmem_ro_valid;

/*
 * Bad pages held without a record because the record table was full.  They
 * are never freed; the list only lets other code know they are taken.
 */
#define	RASMEM_UNTRACKED	256
static vm_paddr_t rasmem_untracked[RASMEM_UNTRACKED];
static u_int rasmem_nuntracked;

/* Neighbourhood retest queue (protected by rasmem_mtx). */
#define	RASMEM_NBQ	64
static vm_paddr_t rasmem_nbq[RASMEM_NBQ];
static u_int rasmem_nbq_n;

/* Threads. */
static struct proc *rasmem_proc;
static bool rasmem_main_started;
static volatile int rasmem_stop;
static int rasmem_main_running;
static int rasmem_main_chan;
static volatile int rasmem_want_scan, rasmem_want_save;
static volatile u_int rasmem_want_inject, rasmem_want_inject_corrupt;
static volatile int rasmem_want_rebaseline, rasmem_want_forget;
static vm_paddr_t rasmem_forget_pa;
static u_int rasmem_save_gen;

/* Phase 2. */
static struct rasmem_worker *rasmem_workers;
static int rasmem_nworkers;
static int rasmem_boot_running;		/* protected by rasmem_mtx */
static volatile int rasmem_boot_abort;
static volatile uint64_t rasmem_boot_next;
static bool rasmem_boot_deferred;
static sbintime_t rasmem_boot_t0;
static vm_page_t *rasmem_gm;		/* global test: held chunk per id */
static u_int *rasmem_gnp;		/* global test: its size (pages) */
static uint8_t *rasmem_gbad;		/* global test: chunk had failures */
static volatile uint64_t rasmem_gnext[3];
static u_int rasmem_greserve;		/* pages kept free */
static volatile u_int rasmem_gdone;	/* global test duration recorded */
static int rasmem_bar_count, rasmem_bar_target;
static u_int rasmem_bar_gen;

static eventhandler_tag rasmem_shutdown_tag;

static const char *rasmem_src_names[] = {
	"database", "early", "boot", "periodic", "ro-checksum", "blacklist",
	"inject", "live-data", "neighbour", "global"
};
static const char *rasmem_class_names[] = {
	"new", "transient", "intermittent", "hard", "ro-corrupt"
};

#define	SRC_NAME(s)	((s) < nitems(rasmem_src_names) ? \
	rasmem_src_names[(s)] : "?")
#define	CLASS_NAME(c)	((c) < nitems(rasmem_class_names) ? \
	rasmem_class_names[(c)] : "?")

static void	rasmem_policy_check(void);
static int	rasmem_request_save(int timo);

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

static void rasmem_notify(const char *type, const char *fmt, ...)
{
	char buf[192];
	va_list ap;

	/* devctl is not initialized before device configuration. */
	if (cold)
	{
		return;
	}
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	devctl_notify("RASMEM", "memory", type, buf);
}

/*
 * Retention hold used by the test engine.  Only unload wakes it early, so
 * ordinary events do not shorten the retention test.
 */
static int rasmem_hold_chan;

void rasmem_hold_wait(int ticks)
{
	sbintime_t t0;

	t0 = sbinuptime();
	/* Under the lock, so unload's wakeup cannot be missed. */
	mtx_lock(&rasmem_mtx);
	if (!rasmem_stop)
	{
		mtx_sleep(&rasmem_hold_chan, &rasmem_mtx, 0, "rasmhld", ticks);
	}
	rasmem_st.hold_usec += sbttous(sbinuptime() - t0);
	mtx_unlock(&rasmem_mtx);
}

/*
 * Active-time accounting: wall time of a piece of work minus the time it
 * slept in retention holds.  Returns the microseconds added.
 */
struct rasmem_tm
{
	sbintime_t	t0;
	uint64_t	hold0;
};

static void rasmem_tm_start(struct rasmem_tm *tm)
{

	tm->t0 = sbinuptime();
	tm->hold0 = rasmem_st.hold_usec;
}

static uint64_t rasmem_tm_stop(struct rasmem_tm *tm, uint64_t *acc)
{
	uint64_t us, held;

	us = sbttous(sbinuptime() - tm->t0);
	held = rasmem_st.hold_usec - tm->hold0;
	us = us > held ? us - held : 0;
	*acc += us;
	return (us);
}

static void rasmem_wakeup_main(void)
{

	wakeup(&rasmem_main_chan);
}

static bool rasmem_time_valid(time_t t)
{

	return (t > 1000000000);	/* RTC has been read */
}

/* Caller holds rasmem_mtx. */
static struct rasmem_rec *rec_find(vm_paddr_t pa)
{
	u_int i;

	mtx_assert(&rasmem_mtx, MA_OWNED);
	for (i = 0; i < rasmem_nrec; i++)
	{
		if (rasmem_recs[i].r.start_addr == pa)
		{
			return (&rasmem_recs[i]);
		}
	}
	return (NULL);
}

/* Caller holds rasmem_mtx.  Returns NULL if the table is full. */
static struct rasmem_rec *rec_add(vm_paddr_t pa, int src)
{
	struct rasmem_rec *r;

	mtx_assert(&rasmem_mtx, MA_OWNED);
	if (rasmem_nrec >= rasmem_rec_cap)
	{
		return (NULL);
	}
	r = &rasmem_recs[rasmem_nrec++];
	bzero(r, sizeof(*r));
	r->r.start_addr = pa;
	r->r.end_addr = pa + PAGE_SIZE;
	r->r.class = RASMEM_CLASS_NEW;
	r->r.state = RASMEM_ST_INUSE;
	r->r.source = src;
	r->r.dimm_mask = rasmem_dimm_mask(pa);
	return (r);
}

/* Caller holds rasmem_mtx; the rasmem process is the only remover. */
static void rec_remove(struct rasmem_rec *r)
{

	mtx_assert(&rasmem_mtx, MA_OWNED);
	*r = rasmem_recs[--rasmem_nrec];
}

static void rec_recount(void)
{
	u_int i, held, inuse;

	mtx_assert(&rasmem_mtx, MA_OWNED);
	for (i = held = inuse = 0; i < rasmem_nrec; i++)
	{
		switch (rasmem_recs[i].r.state)
		{
		case RASMEM_ST_HELD:
		case RASMEM_ST_BLACKLISTED:
			held++;
			break;
		case RASMEM_ST_INUSE:
			inuse++;
			break;
		}
	}
	rasmem_st.bad_pages = rasmem_nrec;
	rasmem_st.bad_pages_held = held;
	rasmem_st.bad_pages_inuse = inuse;
}

/* Does this record count as an active (real, verified) fault? */
static bool rec_active(const struct rasmem_region *r)
{

	return ((r->flags & RASMEM_RF_UNVERIFIED) == 0 && r->class != RASMEM_CLASS_TRANSIENT && r->class != RASMEM_CLASS_RO_CORRUPT && r->state != RASMEM_ST_RELEASED && r->source != RASMEM_SRC_INJECT);
}

static void rasmem_classify(struct rasmem_region *r)
{
	u_int min;

	if (r->class == RASMEM_CLASS_RO_CORRUPT || r->retests == 0)
	{
		return;
	}
	min = MAX(rasmem_classify_retests, 1);
	if (r->retest_fails == 0)
	{
		r->class = r->retests >= min ? RASMEM_CLASS_TRANSIENT : RASMEM_CLASS_NEW;
	}
	else if (r->retests >= 2 && (uint64_t)r->retest_fails * 10 >= (uint64_t)r->retests * 9)
	{
		r->class = RASMEM_CLASS_HARD;
	}
	else
	{
		r->class = RASMEM_CLASS_INTERMITTENT;
	}
}

/* ------------------------------------------------------------------------ */
/* Health evaluation                                                        */
/* ------------------------------------------------------------------------ */

/*
 * Derive health from the whole record history (which survives reboots):
 *  - REPLACE: too many distinct real bad pages, too many new ones within
 *    the trend window, the same data bit failing on many pages (a failing
 *    DQ line or chip), or too many bad pages on one DIMM;
 *  - REBOOT: live data was hit this boot (corruption events);
 *  - DEGRADED: bad cells known and isolated.
 * Caller holds rasmem_mtx.
 */
static void rasmem_health_eval(void)
{
	const struct rasmem_region *r;
	uint32_t lanes[64], dimms[32];
	uint32_t active, trend, unverified, reasons, mask, worstn;
	uint64_t bits;
	time_t now, since;
	u_int i;
	int b, worst, lane;

	mtx_assert(&rasmem_mtx, MA_OWNED);
	bzero(lanes, sizeof(lanes));
	bzero(dimms, sizeof(dimms));
	now = time_second;
	since = rasmem_time_valid(now) ? now - (time_t)MAX(rasmem_trend_days, 1) * 86400 : 0;
	active = trend = unverified = 0;
	mask = 0;
	for (i = 0; i < rasmem_nrec; i++)
	{
		r = &rasmem_recs[i].r;
		if (r->flags & RASMEM_RF_UNVERIFIED)
		{
			unverified++;
		}
		if (!rec_active(r))
		{
			continue;
		}
		active++;
		if (since != 0 && r->first_error_ts >= since)
		{
			trend++;
		}
		/* Lane analysis only for single-cell style failures. */
		bits = r->bad_bits;
		if (bits != 0 && __bitcount64(bits) <= 2)
		{
			while (bits != 0)
			{
				b = ffsll(bits) - 1;
				lanes[b]++;
				bits &= bits - 1;
			}
		}
		mask |= r->dimm_mask;
		if (r->dimm_mask != 0 && powerof2(r->dimm_mask))
		{
			dimms[ffs(r->dimm_mask) - 1]++;
		}
	}

	lane = -1;
	for (b = 0; b < 64; b++)
	{
		if (lanes[b] > 0 && (lane < 0 || lanes[b] > lanes[lane]))
		{
			lane = b;
		}
	}
	worst = -1;
	worstn = 0;
	for (b = 0; b < 32; b++)
	{
		if (dimms[b] > worstn)
		{
			worst = b;
			worstn = dimms[b];
		}
	}

	reasons = 0;
	if (rasmem_replace_pages > 0 && active >= (u_int)rasmem_replace_pages)
	{
		reasons |= RASMEM_RR_PAGES;
	}
	if (rasmem_trend_pages > 0 && trend >= (u_int)rasmem_trend_pages)
	{
		reasons |= RASMEM_RR_TREND;
	}
	if (rasmem_lane_pages > 0 && lane >= 0 && lanes[lane] >= (u_int)rasmem_lane_pages)
	{
		reasons |= RASMEM_RR_LANE;
	}
	if (rasmem_dimm_pages > 0 && worstn >= (u_int)rasmem_dimm_pages)
	{
		reasons |= RASMEM_RR_DIMM;
	}

	rasmem_st.active_pages = active;
	rasmem_st.trend_pages = trend;
	rasmem_st.unverified_pages = unverified;
	rasmem_st.lane_bit = lane;
	rasmem_st.lane_max_pages = lane >= 0 ? lanes[lane] : 0;
	rasmem_st.worst_dimm = worst;
	rasmem_st.worst_dimm_pages = worstn;
	rasmem_st.replace_reasons = reasons;
	rasmem_suspect_mask = worst >= 0 ? 1u << worst : mask;

	if (reasons != 0)
	{
		rasmem_st.health = RASMEM_HEALTH_REPLACE;
	}
	else if (rasmem_st.reboot_required)
	{
		rasmem_st.health = RASMEM_HEALTH_REBOOT;
	}
	else if (rasmem_nrec > 0)
	{
		rasmem_st.health = RASMEM_HEALTH_DEGRADED;
	}
	else
	{
		rasmem_st.health = RASMEM_HEALTH_OK;
	}
}

static void rasmem_reasons_str(uint32_t reasons, char *buf, size_t len)
{

	snprintf(buf, len, "%s%s%s%s", reasons & RASMEM_RR_PAGES ? "too-many-bad-pages " : "", reasons & RASMEM_RR_TREND ? "new-bad-pages-trend " : "", reasons & RASMEM_RR_LANE ? "failing-data-bit " : "", reasons & RASMEM_RR_DIMM ? "bad-pages-concentrated-on-dimm " : "");
}

/*
 * Threshold evaluation after something changed.  Only sets flags; the main
 * thread prints the periodic warnings and performs the panic (after saving
 * the database).
 */
static void rasmem_policy_check(void)
{
	char why[96], dimm[96];
	uint32_t newreasons;
	bool reboot, pnc;

	reboot = pnc = false;
	mtx_lock(&rasmem_mtx);
	newreasons = rasmem_st.replace_reasons;
	if (rasmem_warn_threshold > 0 && !rasmem_st.reboot_required && rasmem_st.corrupt_boot >= (u_int)rasmem_warn_threshold)
	{
		rasmem_st.reboot_required = 1;
		rasmem_next_warn = 0;
		reboot = true;
	}
	if (rasmem_panic_threshold > 0 && !rasmem_st.panic_pending && rasmem_st.corrupt_boot >= (u_int)rasmem_panic_threshold)
	{
		rasmem_st.panic_pending = 1;
		rasmem_panic_since = time_uptime;
		pnc = true;
	}
	rasmem_health_eval();
	newreasons = rasmem_st.replace_reasons & ~newreasons;
	if (newreasons != 0)
	{
		rasmem_next_replace_warn = 0;	/* warn right away */
	}
	rasmem_dimm_names(rasmem_suspect_mask, dimm, sizeof(dimm));
	mtx_unlock(&rasmem_mtx);

	if (reboot)
	{
		RAS_LOG("live-data corruption threshold (%d) reached\n", rasmem_warn_threshold);
	}
	if (newreasons != 0)
	{
		rasmem_reasons_str(newreasons, why, sizeof(why));
		RAS_LOG("memory is failing (%s), suspected module(s): %s\n", why, dimm);
	}
	if (pnc)
	{
		RAS_LOG("panic threshold (%d) reached: the system will panic as soon as the bad page database is saved\n", rasmem_panic_threshold);
	}
	if (reboot || pnc || newreasons != 0)
	{
		rasmem_wakeup_main();
	}
}

/* ------------------------------------------------------------------------ */
/* Error reporting                                                          */
/* ------------------------------------------------------------------------ */

static void rasmem_nbq_push(vm_paddr_t pa)
{
	u_int i;

	mtx_assert(&rasmem_mtx, MA_OWNED);
	for (i = 0; i < rasmem_nbq_n; i++)
	{
		if (rasmem_nbq[i] == pa)
		{
			return;
		}
	}
	if (rasmem_nbq_n < RASMEM_NBQ)
	{
		rasmem_nbq[rasmem_nbq_n++] = pa;
	}
}

/*
 * A page failed a pattern test outside of a scheduled retest.  If m is not
 * NULL the caller owns the page and hands it over: it stays allocated, i.e.
 * quarantined, until the module is unloaded.
 *
 * Severity: the failure is a live-data corruption event if the page held
 * data right before the test (old records, or injected as such with
 * hw.rasmem.inject_corrupt) or had been given back
 * to the VM system earlier (released transient); otherwise the bad cell was
 * found in free memory and isolated before anyone used it (aging).
 */
static void	rasmem_map_bad(vm_paddr_t pa);

void rasmem_report(vm_paddr_t pa, vm_page_t m, const struct rasmem_fail *f, int src)
{
	struct rasmem_rec *r;
	char dimm[96];
	time_t now;
	u_int nerr;
	bool corrupt, confirmed;

	rasmem_map_bad(pa);
	now = time_second;
	confirmed = false;
	mtx_lock(&rasmem_mtx);
	r = rec_find(pa);
	corrupt = src == RASMEM_SRC_RECLAIM || (r != NULL && r->r.state == RASMEM_ST_RELEASED);
	if (r == NULL)
	{
		r = rec_add(pa, src);
	}
	if (r != NULL)
	{
		if (m != NULL && r->m == NULL)
		{
			r->m = m;
			r->r.state = RASMEM_ST_HELD;
		}
		r->r.errors++;
		if (r->r.first_error_ts == 0)
		{
			r->r.first_error_ts = now;
		}
		r->r.last_error_ts = now;
		r->r.last_test_ts = now;
		r->r.bad_bits |= f->xor_or;
		r->r.last_xor = f->last_xor;
		r->r.bad_offset = f->first_off;
		r->r.pattern = f->pattern;
		r->r.consecutive_pass = 0;
		r->r.dimm_mask = rasmem_dimm_mask(pa);
		if (r->r.class == RASMEM_CLASS_TRANSIENT)
		{
			r->r.class = RASMEM_CLASS_INTERMITTENT;
		}
		if (r->r.flags & RASMEM_RF_UNVERIFIED)
		{
			r->r.flags &= ~RASMEM_RF_UNVERIFIED;
			confirmed = true;
		}
		if (corrupt)
		{
			r->r.flags |= RASMEM_RF_CORRUPTION;
		}
	}
	nerr = ++rasmem_st.errors_boot;
	if (corrupt)
	{
		rasmem_st.corrupt_boot++;
	}
	rasmem_st.last_error_ts = now;
	rasmem_dirty = 1;
	rasmem_urgent_save = 1;
	if (r == NULL && m != NULL && rasmem_nuntracked < RASMEM_UNTRACKED)
	{
		rasmem_untracked[rasmem_nuntracked++] = pa;
	}
	if (src != RASMEM_SRC_NEIGHBOR && src != RASMEM_SRC_INJECT && rasmem_neighbor_pages > 0)
	{
		rasmem_nbq_push(pa);
	}
	rec_recount();
	rasmem_dimm_names(rasmem_dimm_mask(pa), dimm, sizeof(dimm));
	mtx_unlock(&rasmem_mtx);

	RAS_LOG("%s #%u: pa 0x%016jx+0x%03x xor 0x%016jx (%u bad word(s), pattern %s, %s test, module %s)%s%s\n", corrupt ? "MEMORY CORRUPTION (live data)" : "MEMORY ERROR", nerr, (uintmax_t)pa, f->first_off, (uintmax_t)f->xor_or, f->nbad, rasmem_pattern_name(f->pattern), SRC_NAME(src), dimm, r == NULL ? " - record table full, page held untracked" : m != NULL ? " - page quarantined" : "", confirmed ? " - old record confirmed" : "");
	rasmem_notify(corrupt ? "CORRUPTION" : "ERROR", "pa=0x%jx xor=0x%jx bits=%d source=%s dimm=%s", (uintmax_t)pa, (uintmax_t)f->xor_or, __bitcount64(f->xor_or), SRC_NAME(src), dimm);
	rasmem_policy_check();
	rasmem_wakeup_main();
}

/* Are there known bad pages we could not quarantine yet? */
bool rasmem_have_inuse(void)
{

	return (atomic_load_int(&rasmem_st.bad_pages_inuse) != 0);
}

/*
 * A test passed on a page we own.  If it is a known bad page that was in
 * use so far (e.g. from the database), keep it instead of freeing it.
 */
bool rasmem_claim_known(vm_paddr_t pa, vm_page_t m)
{
	struct rasmem_rec *r;
	bool claimed;

	if (!rasmem_have_inuse())
	{
		return (false);
	}
	claimed = false;
	mtx_lock(&rasmem_mtx);
	r = rec_find(pa);
	if (r != NULL && r->r.state == RASMEM_ST_INUSE && r->m == NULL)
	{
		r->m = m;
		r->r.state = RASMEM_ST_HELD;
		rasmem_dirty = 1;
		rec_recount();
		claimed = true;
	}
	mtx_unlock(&rasmem_mtx);
	if (claimed)
	{
		RAS_LOG("known bad page 0x%016jx was freed and is now quarantined\n", (uintmax_t)pa);
	}
	return (claimed);
}

/*
 * Any one free page.  The contiguous allocator never hands out pages from
 * the per-CPU page caches, so such a page can later be freed straight into
 * the buddy lists, and vm_page_blacklist_add() can find it at unload.
 */
static vm_page_t rasmem_alloc_page(void)
{

	return (vm_page_alloc_noobj_contig(VM_ALLOC_NORMAL | VM_ALLOC_NOWAIT | VM_ALLOC_WIRED, 1, 0, ~(vm_paddr_t)0, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT));
}

/* Is pa a record whose page we already hold? */
static bool rasmem_page_held(vm_paddr_t pa)
{
	struct rasmem_rec *r;
	u_int i;
	bool held;

	mtx_lock(&rasmem_mtx);
	r = rec_find(pa);
	held = r != NULL && r->m != NULL;
	for (i = 0; !held && i < rasmem_nuntracked; i++)
	{
		held = rasmem_untracked[i] == pa;
	}
	mtx_unlock(&rasmem_mtx);
	return (held);
}

static void rasmem_report_ro(vm_offset_t va, uint32_t was, uint32_t now_crc)
{
	struct rasmem_rec *r;
	char sym[64];
	long off;
	vm_paddr_t pa;
	time_t now;

	now = time_second;
	pa = trunc_page(pmap_kextract(va));
	/*
	 * Never block on the linker lock: kldunload holds it exclusively
	 * while it waits for this thread to exit.
	 */
	if (linker_search_symbol_name_flags((caddr_t)va, sym, sizeof(sym), &off, M_NOWAIT) != 0)
	{
		strlcpy(sym, "?", sizeof(sym));
		off = 0;
	}

	mtx_lock(&rasmem_mtx);
	r = rec_find(pa);
	if (r == NULL)
	{
		r = rec_add(pa, RASMEM_SRC_RO);
	}
	if (r != NULL)
	{
		r->r.class = RASMEM_CLASS_RO_CORRUPT;
		r->r.state = RASMEM_ST_KERNEL;
		r->r.errors++;
		if (r->r.first_error_ts == 0)
		{
			r->r.first_error_ts = now;
		}
		r->r.last_error_ts = now;
		r->r.last_test_ts = now;
		r->r.last_xor = (uint64_t)was << 32 | now_crc;
		if (rasmem_ro_action >= 1)
		{
			r->r.flags |= RASMEM_RF_CORRUPTION;
		}
	}
	rasmem_st.ro_mismatch++;
	rasmem_st.errors_boot++;
	if (rasmem_ro_action >= 1)
	{
		rasmem_st.corrupt_boot++;
	}
	if (rasmem_ro_action >= 2 && !rasmem_st.panic_pending)
	{
		rasmem_st.panic_pending = 1;
		rasmem_panic_since = time_uptime;
	}
	rasmem_st.last_error_ts = now;
	rasmem_dirty = 1;
	rasmem_urgent_save = 1;
	rec_recount();
	mtx_unlock(&rasmem_mtx);

	RAS_LOG("KERNEL IMAGE CORRUPTION: read-only page va %p (%s+0x%lx) pa 0x%016jx checksum 0x%08x, expected 0x%08x\n", (void *)va, sym, off, (uintmax_t)pa, now_crc, was);
	rasmem_notify("RO_CORRUPT", "va=%p pa=0x%jx symbol=%s", (void *)va, (uintmax_t)pa, sym);
	rasmem_policy_check();
}

/* ------------------------------------------------------------------------ */
/* Persistence                                                              */
/* ------------------------------------------------------------------------ */

static int rasmem_rename(struct thread *td, const char *from, const char *to)
{

#ifdef AT_RENAME_NOREPLACE	/* renameat2() era: kern_renameat() has flags */
	return (kern_renameat(td, AT_FDCWD, from, AT_FDCWD, to, UIO_SYSSPACE, 0));
#else
	return (kern_renameat(td, AT_FDCWD, from, AT_FDCWD, to, UIO_SYSSPACE));
#endif
}

/* Write data to path.new, fsync it, then rename it over path. */
static int rasmem_write_file(const char *path, const void *data, size_t len)
{
	struct thread *td;
	struct nameidata nd;
	struct vnode *vp;
	struct mount *mp;
	char *tmp;
	int error, error2, flags;

	td = curthread;
	tmp = malloc(MAXPATHLEN, M_RASMEM, M_WAITOK);
	if (snprintf(tmp, MAXPATHLEN, "%s.new", path) >= MAXPATHLEN)
	{
		error = ENAMETOOLONG;
		goto out;
	}
	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, tmp);
	flags = FWRITE | O_CREAT | O_NOFOLLOW;
	error = vn_open(&nd, &flags, S_IRUSR | S_IWUSR, NULL);
	if (error != 0)
	{
		goto out;
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
	VOP_UNLOCK(vp);

	/* vn_open() does not truncate; drop a stale tail. */
	error = vn_start_write(vp, &mp, V_WAIT);
	if (error == 0)
	{
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = vn_truncate_locked(vp, 0, false, td->td_ucred);
		VOP_UNLOCK(vp);
		vn_finished_write(mp);
	}
	if (error == 0 && len > 0)
	{
		error = vn_rdwr(UIO_WRITE, vp, __DECONST(void *, data), (int)len, 0, UIO_SYSSPACE, IO_SYNC, td->td_ucred, NOCRED, NULL, td);
	}
	error2 = vn_close(vp, FWRITE, td->td_ucred, td);
	if (error == 0)
	{
		error = error2;
	}
	if (error == 0)
	{
		error = rasmem_rename(td, tmp, path);
	}
out:
	free(tmp, M_RASMEM);
	return (error);
}

#define	RASMEM_MAX_FILE	(16 * 1024 * 1024)

static int rasmem_read_file(const char *path, char **bufp, size_t *lenp)
{
	struct thread *td;
	struct nameidata nd;
	struct vattr va;
	struct vnode *vp;
	ssize_t resid;
	char *buf;
	int error, flags;

	td = curthread;
	*bufp = NULL;
	*lenp = 0;
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	flags = FREAD;
	error = vn_open(&nd, &flags, 0, NULL);
	if (error != 0)
	{
		return (error);
	}
	NDFREE_PNBUF(&nd);
	vp = nd.ni_vp;
	buf = NULL;
	error = VOP_GETATTR(vp, &va, td->td_ucred);
	if (error == 0 && (va.va_size == 0 || va.va_size > RASMEM_MAX_FILE))
	{
		error = EFBIG;
	}
	if (error == 0)
	{
		buf = malloc(va.va_size, M_RASMEM, M_WAITOK);
		error = vn_rdwr(UIO_READ, vp, buf, (int)va.va_size, 0, UIO_SYSSPACE, IO_NODELOCKED, td->td_ucred, NOCRED, &resid, td);
		if (error == 0 && resid != 0)
		{
			error = EIO;
		}
	}
	VOP_UNLOCK(vp);
	vn_close(vp, FREAD, td->td_ucred, td);
	if (error != 0)
	{
		free(buf, M_RASMEM);
		return (error);
	}
	*bufp = buf;
	*lenp = va.va_size;
	return (0);
}

/*
 * Snapshot the records into the database image and the loader blacklist
 * text.  The blacklist lists every page that should be kept away from the
 * VM system at the next boot.
 */
static void rasmem_build_files(char **dbp, size_t *dblen, char **blp, size_t *bllen)
{
	struct rasmem_db_header *h;
	struct rasmem_region *out;
	char *db, *bl;
	size_t blcap, blpos;
	u_int i, n, cap;

	mtx_lock(&rasmem_mtx);
	n = rasmem_nrec;
	mtx_unlock(&rasmem_mtx);
	cap = n + 16;
	db = malloc(sizeof(*h) + cap * sizeof(*out), M_RASMEM, M_WAITOK | M_ZERO);
	blcap = cap * 24 + 1;
	bl = malloc(blcap, M_RASMEM, M_WAITOK);
	h = (struct rasmem_db_header *)db;
	out = (struct rasmem_region *)(h + 1);

	mtx_lock(&rasmem_mtx);
	n = MIN(rasmem_nrec, cap);
	blpos = 0;
	for (i = 0; i < n; i++)
	{
		out[i] = rasmem_recs[i].r;
		switch (out[i].state)
		{
		case RASMEM_ST_HELD:
		case RASMEM_ST_BLACKLISTED:
		case RASMEM_ST_INUSE:
			blpos += snprintf(bl + blpos, blcap - blpos, "0x%016jx\n", (uintmax_t)out[i].start_addr);
			break;
		}
	}
	h->hw_fingerprint = rasmem_st.hw_fingerprint != 0 ? rasmem_st.hw_fingerprint : rasmem_db_fp;
	mtx_unlock(&rasmem_mtx);

	memcpy(h->magic, RASMEM_DB_MAGIC, sizeof(h->magic));
	h->version = RASMEM_DB_VERSION;
	h->count = n;
	h->rec_size = sizeof(*out);
	h->crc = calculate_crc32c(~0U, (const unsigned char *)out, n * sizeof(*out));
	h->saved_ts = time_second;

	*dbp = db;
	*dblen = sizeof(*h) + n * sizeof(*out);
	*blp = bl;
	*bllen = blpos;
}

/* Save both files.  Called from the rasmem process or at unload. */
static int rasmem_save(const char *why)
{
	char *db, *bl;
	size_t dblen, bllen;
	int error, urgent;

	if (rootvnode == NULL)
	{
		/* No root file system yet; let waiters know. */
		mtx_lock(&rasmem_mtx);
		rasmem_st.last_save_error = EAGAIN;
		rasmem_save_gen++;
		wakeup(&rasmem_save_gen);
		mtx_unlock(&rasmem_mtx);
		return (EAGAIN);
	}
	if (curproc == rasmem_proc)
	{
		pwd_ensure_dirs();	/* kernel process: root/cwd = "/" */
	}

	sx_xlock(&rasmem_save_sx);
	mtx_lock(&rasmem_mtx);
	/* Changes from now on dirty it again. */
	rasmem_dirty = 0;
	urgent = rasmem_urgent_save;
	rasmem_urgent_save = 0;
	rasmem_st.phase = RASMEM_PHASE_SAVE;
	mtx_unlock(&rasmem_mtx);

	rasmem_build_files(&db, &dblen, &bl, &bllen);
	error = rasmem_write_file(rasmem_db_path, db, dblen);
	if (error == 0)
	{
		error = rasmem_write_file(rasmem_bl_path, bl, bllen);
	}
	free(db, M_RASMEM);
	free(bl, M_RASMEM);

	mtx_lock(&rasmem_mtx);
	rasmem_st.last_save_error = error;
	if (error == 0)
	{
		rasmem_st.last_save_ts = time_second;
	}
	else
	{
		rasmem_dirty = 1;
		rasmem_urgent_save |= urgent;
	}
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	rasmem_save_gen++;
	wakeup(&rasmem_save_gen);
	mtx_unlock(&rasmem_mtx);
	sx_xunlock(&rasmem_save_sx);

	if (error == 0)
	{
		RAS_VLOG("saved %s and %s (%s)\n", rasmem_db_path, rasmem_bl_path, why);
	}
	else
	{
		RAS_VLOG("saving %s failed: error %d (%s)\n", rasmem_db_path, error, why);
	}
	return (error);
}

static int rasmem_db_import(const char *buf, size_t len, const char *from)
{
	const struct rasmem_db_header *h;
	const struct rasmem_region *in;
	struct rasmem_rec *r;
	vm_paddr_t pa;
	vm_page_t m;
	uint32_t i, n;
	int dom, held, inuse, gone, kept, st;

	if (len < sizeof(*h))
	{
		goto bad;
	}
	h = (const struct rasmem_db_header *)buf;
	if (memcmp(h->magic, RASMEM_DB_MAGIC, sizeof(h->magic)) != 0 || h->version < 1 || h->version > RASMEM_DB_VERSION || h->rec_size != sizeof(struct rasmem_region))
	{
		goto bad;
	}
	n = h->count;
	if (n > (len - sizeof(*h)) / sizeof(*in))
	{
		goto bad;
	}
	in = (const struct rasmem_region *)(h + 1);
	if (calculate_crc32c(~0U, (const unsigned char *)in, n * sizeof(*in)) != h->crc)
	{
		goto bad;
	}
	rasmem_db_fp = h->version >= 2 ? h->hw_fingerprint : 0;
	rasmem_db_loaded = true;

	held = inuse = gone = kept = 0;
	for (i = 0; i < n; i++)
	{
		pa = trunc_page(in[i].start_addr);
		mtx_lock(&rasmem_mtx);
		r = rec_find(pa);
		if (r == NULL)
		{
			r = rec_add(pa, in[i].source);
		}
		if (r != NULL)
		{
			r->r = in[i];
			r->r.start_addr = pa;
			r->r.end_addr = pa + PAGE_SIZE;
			if (h->version < 2)
			{
				r->r.dimm_mask = 0;
				r->r.flags = 0;
				r->r.reserved = 0;
			}
			r->m = NULL;
		}
		mtx_unlock(&rasmem_mtx);
		if (r == NULL)
		{
			RAS_LOG("record table full, %u database record(s) dropped (raise hw.rasmem.max_records)\n", n - i);
			break;
		}

		/*
		 * Decide the state for this boot.  The stored state is only
		 * kept for pages we deliberately do not hold.
		 */
		m = NULL;
		dom = rasmem_pa_domain(pa);
		if (in[i].state == RASMEM_ST_RELEASED || in[i].state == RASMEM_ST_KERNEL)
		{
			st = in[i].state;
			kept++;
		}
		else if (dom < 0)
		{
			st = RASMEM_ST_RELEASED;	/* memory not present */
			gone++;
		}
		else if ((m = rasmem_grab(pa, 1, dom, 0)) != NULL)
		{
			st = RASMEM_ST_HELD;
			held++;
		}
		else
		{
			/* Blacklisted at boot or in use; phase 2 tells. */
			st = RASMEM_ST_INUSE;
			inuse++;
		}
		mtx_lock(&rasmem_mtx);
		r->r.state = st;
		r->m = m;
		mtx_unlock(&rasmem_mtx);
	}
	mtx_lock(&rasmem_mtx);
	rec_recount();
	mtx_unlock(&rasmem_mtx);
	RAS_LOG("loaded %u bad page record(s) from %s: %d quarantined, %d not free (blacklisted or in use), %d released, %d not present\n", n, from, held, inuse, kept, gone);
	return (0);
bad:
	RAS_LOG("ignoring invalid or incompatible database from %s\n", from);
	return (EINVAL);
}

/* Is pa listed in the ram_blacklist file the loader passed to the kernel? */
static bool rasmem_in_bl_text(const char *text, vm_paddr_t pa)
{
	const char *p;
	char *ep;

	for (p = text; *p != '\0';)
	{
		if (trunc_page(strtouq(p, &ep, 0)) == pa && ep != p)
		{
			return (true);
		}
		if (ep == p)
		{
			p++;
		}
		else
		{
			p = ep;
		}
		while (*p == ',' || *p == ' ' || *p == '\n')
		{
			p++;
		}
	}
	return (false);
}

/*
 * Known bad pages that are neither blacklisted nor held: say why, because
 * the remedy differs.  Either the loader did not pass the blacklist at all
 * (configuration), the file does not list the page (stale file), or the
 * page was already in use before the VM system started (kernel, modules,
 * loader data), which no boot-time blacklist can fix.
 */
static void rasmem_explain_inuse(u_int inuse)
{
	caddr_t mod;
	char *text;
	size_t len;
	vm_paddr_t pa;
	u_int i, shown, early, missing;

	mod = preload_search_by_type("ram_blacklist");
	if (mod == NULL || preload_fetch_addr(mod) == NULL)
	{
		RAS_LOG("WARNING: %u known bad page(s) are in use: the loader did not load a ram_blacklist file. Add to loader.conf: ram_blacklist_load=\"YES\" ram_blacklist_type=\"ram_blacklist\" ram_blacklist_name=\"%s\"\n", inuse, rasmem_bl_path);
		return;
	}
	len = preload_fetch_size(mod);
	text = malloc(len + 1, M_RASMEM, M_WAITOK);
	memcpy(text, preload_fetch_addr(mod), len);
	text[len] = '\0';

	shown = early = missing = 0;
	mtx_lock(&rasmem_mtx);
	for (i = 0; i < rasmem_nrec; i++)
	{
		if (rasmem_recs[i].r.state != RASMEM_ST_INUSE)
		{
			continue;
		}
		pa = rasmem_recs[i].r.start_addr;
		if (rasmem_in_bl_text(text, pa))
		{
			early++;
			if (shown++ < 8)
			{
				printf("rasmem:   0x%016jx: in the blacklist file, but already in use when the VM started (kernel, modules or loader data)\n", (uintmax_t)pa);
			}
		}
		else
		{
			missing++;
			if (shown++ < 8)
			{
				printf("rasmem:   0x%016jx: not in the loaded blacklist file\n", (uintmax_t)pa);
			}
		}
	}
	mtx_unlock(&rasmem_mtx);
	free(text, M_RASMEM);

	if (early > 0)
	{
		RAS_LOG("WARNING: %u known bad page(s) were in use before the VM system started and cannot be excluded at boot; they are quarantined if they are ever freed\n", early);
	}
	if (missing > 0)
	{
		RAS_LOG("WARNING: %u known bad page(s) are missing from the blacklist file the loader passed in (written before they were found, or a different file?): check ram_blacklist_name=\"%s\"\n", missing, rasmem_bl_path);
	}
}

/* Merge the VM's boot-time blacklist (vm.page_blacklist). */
static void rasmem_import_vm_blacklist(void)
{
	struct rasmem_rec *r;
	char name[] = "vm.page_blacklist";
	char *buf, *p, *ep;
	size_t len, got;
	vm_paddr_t pa;
	u_int n, added, i, inuse;
	int error;

	/*
	 * Unlike sysctl(3), kernel_sysctlbyname() does not update *oldlenp:
	 * the size needed (or copied) is returned through retval.
	 */
	len = 0;
	error = kernel_sysctlbyname(curthread, name, NULL, NULL, NULL, 0, &len, 0);
	if (error != 0)
	{
		RAS_LOG("cannot read vm.page_blacklist: error %d\n", error);
		goto check;
	}
	if (len <= 1)
	{
		RAS_VLOG("vm.page_blacklist is empty\n");
		goto check;
	}
	len += 256;			/* the list cannot grow, but be safe */
	buf = malloc(len + 1, M_RASMEM, M_WAITOK | M_ZERO);
	got = 0;
	error = kernel_sysctlbyname(curthread, name, buf, &len, NULL, 0, &got, 0);
	if (error != 0)
	{
		RAS_LOG("cannot read vm.page_blacklist: error %d\n", error);
		free(buf, M_RASMEM);
		goto check;
	}
	buf[MIN(got, len)] = '\0';
	n = added = 0;
	for (p = buf; *p != '\0';)
	{
		pa = trunc_page(strtouq(p, &ep, 0));
		if (ep == p)
		{
			break;
		}
		mtx_lock(&rasmem_mtx);
		r = rec_find(pa);
		if (r == NULL && (r = rec_add(pa, RASMEM_SRC_BLACKLIST)) != NULL)
		{
			added++;
			rasmem_dirty = 1;
		}
		if (r != NULL && r->m == NULL)
		{
			r->r.state = RASMEM_ST_BLACKLISTED;
		}
		mtx_unlock(&rasmem_mtx);
		n++;
		for (p = ep; *p == ',' || *p == ' ' || *p == '\n'; p++)
		{
		}
	}
	if (n == 0 && got > 1)
	{
		RAS_LOG("vm.page_blacklist has an unexpected format, ignored: %.40s\n", buf);
	}
	free(buf, M_RASMEM);
	RAS_LOG("%u page(s) excluded by the VM boot blacklist (%u not in the database)\n", n, added);
check:
	mtx_lock(&rasmem_mtx);
	rec_recount();
	inuse = rasmem_st.bad_pages_inuse;
	if (inuse > 0 && RAS_VERBOSE())
	{
		for (i = 0; i < rasmem_nrec; i++)
		{
			if (rasmem_recs[i].r.state == RASMEM_ST_INUSE)
			{
				printf("rasmem:   known bad page 0x%016jx is in use\n", (uintmax_t)rasmem_recs[i].r.start_addr);
			}
		}
	}
	mtx_unlock(&rasmem_mtx);
	if (inuse > 0)
	{
		rasmem_explain_inuse(inuse);
	}
}

/*
 * Hardware identity.  If the memory configuration changed since the
 * database was written, its addresses may point at different modules.
 */
static void rasmem_hw_check(void)
{
	uint64_t fp;
	u_int i, dropped, marked;
	bool changed;

	rasmem_smbios_init();
	fp = rasmem_hw_fingerprint();
	mtx_lock(&rasmem_mtx);
	rasmem_st.hw_fingerprint = fp;
	rasmem_st.ndimms = rasmem_dimm_count();
	for (i = 0; i < rasmem_nrec; i++)
	{
		rasmem_recs[i].r.dimm_mask = rasmem_dimm_mask(rasmem_recs[i].r.start_addr);
	}
	changed = rasmem_db_loaded && rasmem_db_fp != 0 && fp != 0 && ((uint32_t)rasmem_db_fp != (uint32_t)fp || ((rasmem_db_fp >> 32) != 0 && (fp >> 32) != 0 && (rasmem_db_fp >> 32) != (fp >> 32)));
	rasmem_st.hw_changed = changed;
	dropped = marked = 0;
	if (changed && rasmem_hwchange_action == 1)
	{
		/*
		 * Keep isolating the pages (conservative), but stop trusting
		 * the history: re-verify each record from scratch.
		 */
		for (i = 0; i < rasmem_nrec;)
		{
			struct rasmem_region *r = &rasmem_recs[i].r;

			if (r->state == RASMEM_ST_RELEASED && rasmem_recs[i].m == NULL)
			{
				rec_remove(&rasmem_recs[i]);
				dropped++;
				continue;
			}
			if (r->class != RASMEM_CLASS_RO_CORRUPT)
			{
				r->flags |= RASMEM_RF_UNVERIFIED;
				r->retests = r->retest_fails = 0;
				r->consecutive_pass = 0;
				r->class = RASMEM_CLASS_NEW;
				marked++;
			}
			i++;
		}
		rasmem_dirty = 1;
	}
	rec_recount();
	rasmem_health_eval();
	mtx_unlock(&rasmem_mtx);

	if (changed)
	{
		RAS_LOG("WARNING: memory configuration changed since the database was written (fingerprint %016jx -> %016jx); %s\n", (uintmax_t)rasmem_db_fp, (uintmax_t)fp, rasmem_hwchange_action == 1 ? "re-verifying old records" : "trusting old records");
		if (marked + dropped > 0)
		{
			RAS_LOG("%u record(s) to re-verify, %u released record(s) dropped\n", marked, dropped);
		}
		rasmem_notify("HW_CHANGED", "old=%016jx new=%016jx", (uintmax_t)rasmem_db_fp, (uintmax_t)fp);
	}
}

/* Unload: hand held pages over to the VM's own blacklist. */
static void rasmem_transfer_held(void)
{
	vm_page_t m;
	vm_paddr_t pa;
	u_int i, moved, lost;

	moved = lost = 0;
	for (i = 0; i < rasmem_nrec; i++)
	{
		mtx_lock(&rasmem_mtx);
		m = rasmem_recs[i].m;
		rasmem_recs[i].m = NULL;
		pa = rasmem_recs[i].r.start_addr;
		mtx_unlock(&rasmem_mtx);
		if (m == NULL)
		{
			continue;
		}
		/*
		 * There is a tiny window between the free and the blacklist
		 * removal; if someone allocates the page in between it is
		 * reported as lost.
		 */
		rasmem_release(m, 1);
		mtx_lock(&rasmem_mtx);
		if (vm_page_blacklist_add(pa, false))
		{
			rasmem_recs[i].r.state = RASMEM_ST_BLACKLISTED;
			moved++;
		}
		else
		{
			rasmem_recs[i].r.state = RASMEM_ST_INUSE;
			lost++;
		}
		mtx_unlock(&rasmem_mtx);
	}
	if (moved + lost > 0)
	{
		RAS_LOG("unload: %u quarantined page(s) moved to the VM blacklist, %u lost to concurrent allocation\n", moved, lost);
	}
	mtx_lock(&rasmem_mtx);
	rasmem_dirty = 1;
	rec_recount();
	mtx_unlock(&rasmem_mtx);
}

/* ------------------------------------------------------------------------ */
/* Read-only image checksums                                                */
/* ------------------------------------------------------------------------ */

/*
 * DTrace (FBT, kinst, SDT hot-patching) and DDB breakpoints legitimately
 * modify kernel text.  Skip verification while any of them is active.
 */
static bool rasmem_ro_patching_active(void)
{
	static const char *mods[] = { "dtrace", "fbt", "kinst", "sdt" };
	bool active;
	u_int i;

	if (kdb_active)
	{
		return (true);
	}
	active = false;
	MOD_SLOCK;
	for (i = 0; i < nitems(mods) && !active; i++)
	{
		if (module_lookupbyname(mods[i]) != NULL)
		{
			active = true;
		}
	}
	MOD_SUNLOCK;
	return (active);
}

static void rasmem_ro_baseline(void)
{
	u_int i;

	for (i = 0; i < rasmem_ro_npages; i++)
	{
		rasmem_ro_crc[i] = calculate_crc32c(~0U, (const unsigned char *)(rasmem_ro_start + ptoa(i)), PAGE_SIZE);
	}
	rasmem_ro_valid = true;
}

static void rasmem_ro_init(void)
{
	vm_offset_t end;

	/* [btext, brwsection) is mapped read-only by the amd64 pmap. */
	rasmem_ro_start = round_page((vm_offset_t)btext);
	end = trunc_page((vm_offset_t)brwsection);
	if (end <= rasmem_ro_start)
	{
		return;
	}
	rasmem_ro_npages = atop(end - rasmem_ro_start);
	rasmem_ro_crc = malloc(rasmem_ro_npages * sizeof(uint32_t), M_RASMEM, M_WAITOK | M_ZERO);
	rasmem_st.ro_pages = rasmem_ro_npages;
	if (!rasmem_ro_patching_active())
	{
		rasmem_ro_baseline();
	}
	RAS_LOG("checksummed %u read-only kernel page(s) at %p-%p%s\n", rasmem_ro_npages, (void *)rasmem_ro_start, (void *)end, rasmem_ro_valid ? "" : " (deferred: DTrace/kdb active)");
}

static void rasmem_ro_verify(void)
{
	struct rasmem_tm tm;
	uint32_t c;
	u_int i, bad;

	if (rasmem_ro_crc == NULL || rasmem_stop)
	{
		return;
	}
	rasmem_tm_start(&tm);
	if (rasmem_ro_patching_active())
	{
		rasmem_st.ro_skipped++;
		RAS_VLOG("read-only verification skipped: DTrace/kdb active\n");
		return;
	}
	if (!rasmem_ro_valid)
	{
		rasmem_ro_baseline();
		RAS_VLOG("read-only checksum baseline taken\n");
		return;
	}
	rasmem_st.phase = RASMEM_PHASE_RO;
	for (i = bad = 0; i < rasmem_ro_npages; i++)
	{
		c = calculate_crc32c(~0U, (const unsigned char *)(rasmem_ro_start + ptoa(i)), PAGE_SIZE);
		if (__predict_false(c != rasmem_ro_crc[i]))
		{
			rasmem_report_ro(rasmem_ro_start + ptoa(i), rasmem_ro_crc[i], c);
			rasmem_ro_crc[i] = c;	/* report each change once */
			bad++;
		}
		if ((i & 255) == 255)
		{
			maybe_yield();
			if (rasmem_stop)
			{
				return;
			}
		}
	}
	rasmem_st.ro_checks++;
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	rasmem_tm_stop(&tm, &rasmem_st.busy_ro_usec);
	RAS_VLOG("read-only verification: %u page(s), %u mismatch(es)\n", rasmem_ro_npages, bad);
}

/* ------------------------------------------------------------------------ */
/* Phase 1: early boot                                                      */
/* ------------------------------------------------------------------------ */

/*
 * Test the free pages early boot is about to use: take them off the free
 * lists (they are exactly the ones the next allocations would get), test
 * them, give the good ones back.
 */
static void rasmem_early_test(void)
{
	struct rasmem_fail f;
	vm_page_t *pages;
	uint64_t bytes;
	u_int i, n, got, bad;

	n = ((u_int)rasmem_early_mb << 20) / PAGE_SIZE;
	n = MIN(n, vm_free_count() / 4);
	if (n == 0)
	{
		return;
	}
	rasmem_st.phase = RASMEM_PHASE_EARLY;
	pages = malloc(n * sizeof(*pages), M_RASMEM, M_WAITOK);
	for (got = 0; got < n; got++)
	{
		pages[got] = rasmem_alloc_page();
		if (pages[got] == NULL)
		{
			break;
		}
	}
	bytes = 0;
	for (i = bad = 0; i < got; i++)
	{
		if (rasmem_test_range(VM_PAGE_TO_PHYS(pages[i]), 1, rasmem_boot_patterns, false, &f, &bytes) != 0)
		{
			rasmem_report(VM_PAGE_TO_PHYS(pages[i]), pages[i], &f, RASMEM_SRC_EARLY);
			bad++;
		}
		else if (!rasmem_claim_known(VM_PAGE_TO_PHYS(pages[i]), pages[i]))
		{
			rasmem_release(pages[i], 1);
		}
	}
	free(pages, M_RASMEM);
	rasmem_st.early_pages_tested = got;
	rasmem_st.pages_tested += got;
	rasmem_st.bytes_tested += bytes;
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	RAS_LOG("early test: %u page(s) (%u MiB) tested, %u bad\n", got, (u_int)(ptoa((uint64_t)got) >> 20), bad);
}

/* ------------------------------------------------------------------------ */
/* Coverage map (hw.rasmem.map)                                             */
/* ------------------------------------------------------------------------ */

static uint16_t *rasmem_map;		/* protected by rasmem_mtx (pointer) */
static uint16_t *rasmem_map_cnt;	/* pages tested this pass, per cell */
static uint8_t *rasmem_map_pshare;	/* previous pass: tested share */
static uint64_t rasmem_map_cells;
static u_int rasmem_map_shift;		/* cell = 1 << shift pages */

static void rasmem_map_init(void)
{
	uint64_t total;
	u_int shift;

	total = rasmem_segs_pages();
	/* 2 MiB cells, coarser above 1M cells (2 TiB of RAM). */
	for (shift = 9; (total >> shift) > (1u << 20); shift++)
	{
	}
	rasmem_map_shift = shift;
	rasmem_map_cells = MAX(howmany(total, (uint64_t)1 << shift), 1);
	rasmem_map = malloc(rasmem_map_cells * sizeof(*rasmem_map), M_RASMEM, M_WAITOK | M_ZERO);
	rasmem_map_cnt = malloc(rasmem_map_cells * sizeof(*rasmem_map_cnt), M_RASMEM, M_WAITOK | M_ZERO);
	rasmem_map_pshare = malloc(rasmem_map_cells, M_RASMEM, M_WAITOK | M_ZERO);
}

/* Pages in cell c (the last cell may be short). */
static uint64_t rasmem_map_cell_pages(uint64_t c)
{
	uint64_t cp;

	cp = (uint64_t)1 << rasmem_map_shift;
	return (MIN(cp, rasmem_segs_pages() - MIN(c * cp, rasmem_segs_pages())));
}

/* Tested share of cell c this pass, 0-255. */
static uint8_t rasmem_map_share(uint64_t c)
{
	uint64_t cp;

	cp = MAX(rasmem_map_cell_pages(c), 1);
	return ((uint8_t)(MIN(atomic_load_16(&rasmem_map_cnt[c]), cp) * 255 / cp));
}

/*
 * Credit tested pages of [lin, lin + npages) to their cells, in proportion
 * to how much of the range each cell holds.
 */
static void rasmem_map_count(uint64_t lin, uint64_t npages, uint64_t tested)
{
	uint64_t c, last, lo, hi, cp, part, left;

	if (rasmem_map_cnt == NULL || npages == 0 || tested == 0)
	{
		return;
	}
	cp = (uint64_t)1 << rasmem_map_shift;
	last = MIN((lin + npages - 1) >> rasmem_map_shift, rasmem_map_cells - 1);
	left = tested;
	for (c = lin >> rasmem_map_shift; c <= last && left > 0; c++)
	{
		lo = MAX(lin, c * cp);
		hi = MIN(lin + npages, (c + 1) * cp);
		part = c == last ? left : MIN(tested * (hi - lo) / npages, left);
		atomic_add_16(&rasmem_map_cnt[c], (uint16_t)MIN(part, cp));
		left -= part;
	}
}

void rasmem_map_count_pa(vm_paddr_t pa, uint64_t npages, uint64_t tested)
{
	uint64_t lin;

	if (rasmem_pa_to_lin(pa, &lin))
	{
		rasmem_map_count(lin, npages, tested);
	}
}

/* Make the counts so far the "previous" shares and start over. */
static void rasmem_map_fold_shares(void)
{
	uint64_t c;

	if (rasmem_map_cnt == NULL)
	{
		return;
	}
	for (c = 0; c < rasmem_map_cells; c++)
	{
		rasmem_map_pshare[c] = rasmem_map_share(c);
		rasmem_map_cnt[c] = 0;
	}
}

static void rasmem_map_mark(uint64_t lin, uint64_t npages, uint16_t bits)
{
	uint64_t c, last;

	if (rasmem_map == NULL || npages == 0 || bits == 0)
	{
		return;
	}
	last = MIN((lin + npages - 1) >> rasmem_map_shift, rasmem_map_cells - 1);
	for (c = lin >> rasmem_map_shift; c <= last; c++)
	{
		atomic_set_16(&rasmem_map[c], bits);
	}
}

void rasmem_map_mark_pa(vm_paddr_t pa, uint64_t npages, uint16_t bits)
{
	uint64_t lin;

	if (rasmem_pa_to_lin(pa, &lin))
	{
		rasmem_map_mark(lin, npages, bits);
	}
}

/*
 * A periodic pass is complete: credit the test types it applied to whole
 * cells, and make it the "previous pass".
 */
static void rasmem_map_new_pass(void)
{
	uint64_t c;
	uint16_t v, n;

	if (rasmem_map == NULL)
	{
		return;
	}
	rasmem_map_fold_shares();
	for (c = 0; c < rasmem_map_cells; c++)
	{
		v = rasmem_map[c];
		n = v & RASMEM_MAP_DONE_ALL;
		if ((v & (RASMEM_MAP_TESTED | RASMEM_MAP_SKIPPED | RASMEM_MAP_FAILED)) == RASMEM_MAP_TESTED)
		{
			n |= RASMEM_MAP_DONE_BASIC;
			if (v & RASMEM_MAP_MARCH)
			{
				n |= RASMEM_MAP_DONE_MARCH;
			}
			if (v & RASMEM_MAP_HOLD)
			{
				n |= RASMEM_MAP_DONE_HOLD;
			}
		}
		if (v & RASMEM_MAP_TESTED)
		{
			n |= RASMEM_MAP_PREV_TESTED;
		}
		if (v & RASMEM_MAP_SKIPPED)
		{
			n |= RASMEM_MAP_PREV_SKIPPED;
		}
		if (v & RASMEM_MAP_HELD)
		{
			n |= RASMEM_MAP_PREV_HELD;
		}
		rasmem_map[c] = n;
	}
}

/* A new bad page: its cell has not passed everything after all. */
static void rasmem_map_bad(vm_paddr_t pa)
{
	uint64_t lin, c;

	if (rasmem_map == NULL || !rasmem_pa_to_lin(pa, &lin))
	{
		return;
	}
	c = lin >> rasmem_map_shift;
	if (c < rasmem_map_cells)
	{
		atomic_clear_16(&rasmem_map[c], RASMEM_MAP_DONE_ALL);
		atomic_set_16(&rasmem_map[c], RASMEM_MAP_FAILED);
	}
}

static void rasmem_phase1(void *dummy __unused)
{
	caddr_t mod;
	char *buf;
	size_t len;
	int error;

	rasmem_at_boot = (rootvnode == NULL);
	rasmem_st.abi_version = RASMEM_ABI_VERSION;
	rasmem_st.load_ts = time_second;
	rasmem_st.lane_bit = -1;
	rasmem_st.worst_dimm = -1;
	rasmem_stop = 0;
	rasmem_boot_abort = 0;

	rasmem_rec_cap = MAX(rasmem_max_records, 64);
	rasmem_recs = malloc(rasmem_rec_cap * sizeof(*rasmem_recs), M_RASMEM, M_WAITOK | M_ZERO);
	rasmem_nrec = 0;

	/*
	 * Before anything reads page structures, including the segment
	 * check in rasmem_segs_init(): on FreeBSD 15+ the page structures of
	 * free memory are initialized lazily, and an uninitialized one does
	 * not know its own address yet.
	 */
	rasmem_vm_init_pages();
	if (rasmem_segs_init() == 0)
	{
		RAS_LOG("physical memory layout not usable, disabled\n");
		free(rasmem_recs, M_RASMEM);
		rasmem_recs = NULL;
		rasmem_segs_fini();
		return;
	}
	rasmem_st.phys_pages = rasmem_segs_pages();
	rasmem_hints_check(rasmem_page_hints != 0);
	rasmem_page_hints = rasmem_hints_enabled();
	rasmem_map_init();
	rasmem_test_init();
	RAS_LOG("rasmem %s (%s), RAS memory test suite (ABI %d): %ju MiB of physical memory, %s\n", RASMEM_VERSION, RASMEM_STAGE, RASMEM_ABI_VERSION, (uintmax_t)(ptoa(rasmem_st.phys_pages) >> 20), rasmem_at_boot ? "loaded at boot" : "loaded at runtime");

	/* The bad page database. */
	mod = preload_search_by_type("rasmem_db");
	if (mod != NULL && preload_fetch_addr(mod) != NULL)
	{
		rasmem_db_import(preload_fetch_addr(mod), preload_fetch_size(mod), "loader");
	}
	else if (rootvnode != NULL)
	{
		error = rasmem_read_file(rasmem_db_path, &buf, &len);
		if (error == 0)
		{
			rasmem_db_import(buf, len, rasmem_db_path);
			free(buf, M_RASMEM);
		}
		else
		{
			RAS_VLOG("no database at %s (error %d)\n", rasmem_db_path, error);
		}
	}
	else
	{
		RAS_LOG("no database preloaded (rasmem_db_load=\"YES\" in loader.conf)\n");
	}

	rasmem_ro_init();

	if (rasmem_early_mb > 0 && rasmem_at_boot)
	{
		rasmem_early_test();
	}

	mtx_lock(&rasmem_mtx);
	rasmem_inited = true;
	mtx_unlock(&rasmem_mtx);
}
SYSINIT(rasmem_phase1, SI_SUB_KLD, SI_ORDER_ANY, rasmem_phase1, NULL);

/* ------------------------------------------------------------------------ */
/* Phase 2: global address-line test + multi-core chunk test                */
/* ------------------------------------------------------------------------ */

/* Simple barrier for the boot workers. */
static void rasmem_barrier(void)
{
	u_int gen;

	mtx_lock(&rasmem_mtx);
	gen = rasmem_bar_gen;
	rasmem_bar_count++;
	while (gen == rasmem_bar_gen)
	{
		if (rasmem_bar_count >= rasmem_bar_target || rasmem_boot_abort)
		{
			rasmem_bar_count = 0;
			rasmem_bar_gen++;
			wakeup(&rasmem_bar_gen);
			break;
		}
		mtx_sleep(&rasmem_bar_gen, &rasmem_mtx, 0, "rasmbar", hz);
	}
	mtx_unlock(&rasmem_mtx);
}

/*
 * Global address-line test.  Address-decoder faults alias two distant
 * addresses onto the same cells, which a per-chunk test never sees because
 * the alias is outside the chunk.  So: take as much free memory as is safe
 * (whole 2 MiB chunks), write every word with its own address, and only
 * after everything is written verify everything; then the same with the
 * inverted address.  The time between write and read-back of a word is the
 * time to write all of memory, which doubles as a retention test.
 */
static void rasmem_global_worker(struct rasmem_worker *w)
{
	vm_paddr_t gpa, pa;
	vm_page_t m, gm;
	uint64_t cid, cfirst, cend, gid, id, ngroups, total;
	u_int gnp, i, np, nf;
	int dom, gdom;
	bool held;

	total = rasmem_st.boot_chunks_total;
	ngroups = rasmem_segs_groups();

	/*
	 * G1: grab and write addr.  Work is handed out by group (the largest
	 * buddy block): a free group is taken in one allocation, a partly
	 * used one chunk by chunk, and no two workers compete for the same
	 * free block.
	 */
	while (!rasmem_boot_abort)
	{
		gid = atomic_fetchadd_64(&rasmem_gnext[0], 1);
		if (gid >= ngroups)
		{
			break;
		}
		if (!rasmem_group_to_pa(gid, &gpa, &gnp, &gdom, &cfirst, &cend))
		{
			continue;
		}
		gm = NULL;
		if (vm_free_count() >= rasmem_greserve + gnp)
		{
			gm = rasmem_grab(gpa, gnp, gdom, VM_ALLOC_NORECLAIM);
		}
		for (cid = cfirst; cid < cend && cid < total; cid++)
		{
			if (!rasmem_chunk_to_pa(cid, &pa, &np, &dom))
			{
				continue;
			}
			if (gm != NULL)
			{
				m = gm + atop(pa - gpa);
			}
			else if (vm_free_count() < rasmem_greserve + np || (m = rasmem_grab(pa, np, dom, VM_ALLOC_NORECLAIM)) == NULL)
			{
				continue;
			}
			rasmem_gm[cid] = m;
			rasmem_gnp[cid] = np;
			rasmem_fill_addr(pa, np, false);
			atomic_add_64(&rasmem_st.global_pages, np);
		}
		maybe_yield();
	}
	rasmem_barrier();

	/* G2: verify addr, write ~addr. */
	while (!rasmem_boot_abort)
	{
		id = atomic_fetchadd_64(&rasmem_gnext[1], 1);
		if (id >= total)
		{
			break;
		}
		if ((m = rasmem_gm[id]) == NULL)
		{
			continue;
		}
		pa = VM_PAGE_TO_PHYS(m);
		np = rasmem_gnp[id];
		if (rasmem_check_addr(pa, np, false, w->fails) != 0)
		{
			rasmem_gbad[id] = 1;
			for (i = 0; i < np; i++)
			{
				if (w->fails[i].nbad != 0)
				{
					rasmem_report(pa + ptoa(i), &m[i], &w->fails[i], RASMEM_SRC_GLOBAL);
				}
			}
		}
		rasmem_fill_addr(pa, np, true);
		maybe_yield();
	}
	rasmem_barrier();

	/* G3: verify ~addr, release. */
	while (true)
	{
		id = atomic_fetchadd_64(&rasmem_gnext[2], 1);
		if (id >= total)
		{
			break;
		}
		if ((m = rasmem_gm[id]) == NULL)
		{
			continue;
		}
		rasmem_gm[id] = NULL;
		pa = VM_PAGE_TO_PHYS(m);
		np = rasmem_gnp[id];
		nf = rasmem_boot_abort ? 0 : rasmem_check_addr(pa, np, true, w->fails);
		if (nf == 0 && !rasmem_gbad[id] && !rasmem_boot_abort)
		{
			/* Held across the whole write-all/verify-all cycle. */
			rasmem_map_mark_pa(pa, np, RASMEM_MAP_DONE_HOLD);
		}
		if (nf == 0 && !rasmem_gbad[id] && !rasmem_have_inuse())
		{
			rasmem_release(m, np);
			continue;
		}
		for (i = 0; i < np; i++)
		{
			held = rasmem_gbad[id] && rasmem_page_held(pa + ptoa(i));
			if (held)
			{
				continue;	/* already quarantined in G2 */
			}
			if (nf != 0 && w->fails[i].nbad != 0)
			{
				rasmem_report(pa + ptoa(i), &m[i], &w->fails[i], RASMEM_SRC_GLOBAL);
			}
			else if (!rasmem_claim_known(pa + ptoa(i), &m[i]))
			{
				rasmem_release(&m[i], 1);
			}
		}
	}
	rasmem_barrier();
}

static void rasmem_boot_worker(void *arg)
{
	struct rasmem_worker *w;
	struct rasmem_span_ctx c;
	uint64_t gid, ngroups, t, s, b, k;

	w = arg;
	thread_lock(curthread);
	sched_bind(curthread, w->cpu);
	thread_unlock(curthread);

	if (rasmem_gm != NULL)
	{
		rasmem_global_worker(w);
		/* All workers leave the last barrier together; first wins. */
		if (atomic_cmpset_int(&rasmem_gdone, 0, 1))
		{
			rasmem_st.global_msec = (sbinuptime() - rasmem_boot_t0) / SBT_1MS;
		}
	}
	rasmem_st.phase = RASMEM_PHASE_BOOT;

	bzero(&c, sizeof(c));
	c.patterns = rasmem_boot_patterns & RASMEM_PAT_ALL;
	c.can_sleep = true;
	c.src = RASMEM_SRC_BOOT;
	c.abort = &rasmem_boot_abort;
	c.fails = w->fails;
	ngroups = rasmem_segs_groups();

	/* One group (the largest buddy block) at a time, see G1. */
	while (!rasmem_boot_abort && c.patterns != 0)
	{
		gid = atomic_fetchadd_64(&rasmem_boot_next, 1);
		if (gid >= ngroups)
		{
			break;
		}
		k = c.chunks;
		t = c.tested;
		s = c.skipped;
		b = c.bytes;
		rasmem_test_group(&c, gid);
		atomic_add_64(&rasmem_st.pages_tested, c.tested - t);
		atomic_add_64(&rasmem_st.boot_pages_tested, c.tested - t);
		atomic_add_64(&rasmem_st.boot_pages_skipped, c.skipped - s);
		atomic_add_64(&rasmem_st.pages_skipped, c.skipped - s);
		atomic_add_64(&rasmem_st.bytes_tested, c.bytes - b);
		atomic_add_64(&rasmem_st.boot_chunks_done, c.chunks - k);
	}

	thread_lock(curthread);
	sched_unbind(curthread);
	thread_unlock(curthread);
	mtx_lock(&rasmem_mtx);
	if (--rasmem_boot_running == 0)
	{
		wakeup(&rasmem_boot_running);
	}
	mtx_unlock(&rasmem_mtx);
	kthread_exit();
}

static void rasmem_boot_start(void)
{
	struct rasmem_worker *w;
	uint64_t nchunks;
	u_int reserve;
	int cpu, i, n, error;

	n = mp_ncpus;
	if (rasmem_boot_threads > 0)
	{
		n = MIN(rasmem_boot_threads, mp_ncpus);
	}
	w = malloc(n * sizeof(*w), M_RASMEM, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++)
	{
		w[i].fails = malloc(RASMEM_CHUNK_PAGES * sizeof(struct rasmem_fail), M_RASMEM, M_WAITOK);
	}

	nchunks = rasmem_segs_chunks();
	rasmem_st.boot_chunks_total = nchunks;
	rasmem_st.boot_chunks_done = 0;
	rasmem_boot_next = 0;
	rasmem_gnext[0] = rasmem_gnext[1] = rasmem_gnext[2] = 0;
	rasmem_gdone = 0;
	if (rasmem_boot_global)
	{
		rasmem_gm = malloc(nchunks * sizeof(*rasmem_gm), M_RASMEM, M_WAITOK | M_ZERO);
		rasmem_gnp = malloc(nchunks * sizeof(*rasmem_gnp), M_RASMEM, M_WAITOK | M_ZERO);
		rasmem_gbad = malloc(nchunks, M_RASMEM, M_WAITOK | M_ZERO);
		/* Keep well above the page daemon's target. */
		reserve = (u_int)MAX(rasmem_boot_global_reserve_mb, 64) * (1024 * 1024 / PAGE_SIZE);
		rasmem_greserve = MAX(reserve, 2 * vm_cnt.v_free_target);
		rasmem_st.phase = RASMEM_PHASE_GLOBAL;
	}
	else
	{
		rasmem_st.phase = RASMEM_PHASE_BOOT;
	}
	rasmem_boot_t0 = sbinuptime();
	rasmem_st.boot_status = RASMEM_BOOT_RUNNING;
	RAS_LOG("boot test: %ju MiB in %ju chunk(s), %d thread(s), global address test %s, patterns 0x%02x\n", (uintmax_t)(ptoa(rasmem_st.phys_pages) >> 20), (uintmax_t)nchunks, n, rasmem_boot_global ? "on" : "off", rasmem_boot_patterns);

	mtx_lock(&rasmem_mtx);
	rasmem_workers = w;
	rasmem_nworkers = n;
	rasmem_boot_running = n;
	rasmem_bar_target = n;
	rasmem_bar_count = 0;
	mtx_unlock(&rasmem_mtx);

	i = 0;
	CPU_FOREACH(cpu)
	{
		if (i >= n)
		{
			break;
		}
		w[i].cpu = cpu;
		error = kproc_kthread_add(rasmem_boot_worker, &w[i], &rasmem_proc, NULL, 0, 0, "rasmem", "rasmem boot%d", cpu);
		if (error != 0)
		{
			RAS_LOG("cannot start boot worker on CPU %d: %d\n", cpu, error);
			mtx_lock(&rasmem_mtx);
			rasmem_boot_running--;
			rasmem_bar_target--;
			wakeup(&rasmem_bar_gen);
			mtx_unlock(&rasmem_mtx);
		}
		i++;
	}
	mtx_lock(&rasmem_mtx);
	rasmem_boot_running -= n - i;
	rasmem_bar_target -= n - i;
	if (rasmem_boot_running == 0)
	{
		wakeup(&rasmem_boot_running);
	}
	mtx_unlock(&rasmem_mtx);
}

/* Called once all workers are gone; only the first caller does the work. */
static void rasmem_boot_finish(void)
{
	struct rasmem_worker *w;
	uint64_t ms, mib;
	int i, n;

	mtx_lock(&rasmem_mtx);
	w = rasmem_workers;
	n = rasmem_nworkers;
	if (w == NULL || rasmem_boot_running != 0)
	{
		mtx_unlock(&rasmem_mtx);
		return;
	}
	rasmem_workers = NULL;
	mtx_unlock(&rasmem_mtx);

	ms = (sbinuptime() - rasmem_boot_t0) / SBT_1MS;
	rasmem_st.boot_test_msec = ms;
	/* The boot test's shares become the map's "previous pass". */
	rasmem_map_fold_shares();
	if (!rasmem_boot_abort)
	{
		rasmem_st.boot_status = RASMEM_BOOT_COMPLETE;
	}
	else if (rasmem_st.boot_status != RASMEM_BOOT_ABORTED)
	{
		rasmem_st.boot_status = RASMEM_BOOT_INTERRUPTED;
	}
	mib = ptoa(rasmem_st.boot_pages_tested) >> 20;
	RAS_LOG("boot test %s: global address test over %ju MiB, %ju MiB pattern-tested, %ju MiB skipped (in use), %u error event(s), %ju.%03ju s\n", rasmem_st.boot_status == RASMEM_BOOT_COMPLETE ? "complete" : rasmem_st.boot_status == RASMEM_BOOT_ABORTED ? "aborted from the console" : "interrupted", (uintmax_t)(ptoa(rasmem_st.global_pages) >> 20), (uintmax_t)mib, (uintmax_t)(ptoa(rasmem_st.boot_pages_skipped) >> 20), rasmem_st.errors_boot, (uintmax_t)(ms / 1000), (uintmax_t)(ms % 1000));
	for (i = 0; i < n; i++)
	{
		free(w[i].fails, M_RASMEM);
	}
	free(w, M_RASMEM);
	free(rasmem_gm, M_RASMEM);
	free(rasmem_gnp, M_RASMEM);
	free(rasmem_gbad, M_RASMEM);
	rasmem_gm = NULL;
	rasmem_gnp = NULL;
	rasmem_gbad = NULL;
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	rasmem_policy_check();
}

/*
 * Console input for the boot test.  Polled, as in shutdown_panic(): before
 * init(8) starts nobody else reads the console.  cngrab() switches keyboard
 * consoles to polled mode for the duration.
 */
static bool rasmem_cons_key(void)
{

	return (cncheckc() != -1);
}

/*
 * Wait for the boot workers.  With console set, a key press aborts the test:
 * the workers stop at their next chunk, the global address test releases
 * the memory it holds, and the periodic scan covers the rest later.
 */
static void rasmem_boot_wait(bool console)
{
	sbintime_t next_report;
	uint64_t done, total;
	int n, pct, last;
	bool key;

	printf("Testing Memory ...\n");
	if (console)
	{
		cngrab();
		/* Type-ahead from before the test does not count. */
		for (n = 0; n < 256 && rasmem_cons_key(); n++)
		{
		}
		RAS_LOG("press any key to abort the memory test\n");
	}
	last = -1;
	next_report = sbinuptime() + 2 * SBT_1S;
	mtx_lock(&rasmem_mtx);
	while (rasmem_boot_running > 0)
	{
		mtx_sleep(&rasmem_boot_running, &rasmem_mtx, 0, "rasmboot", console ? MAX(hz / 10, 1) : 2 * hz);
		if (rasmem_boot_running == 0)
		{
			break;
		}
		if (console && !rasmem_boot_abort)
		{
			mtx_unlock(&rasmem_mtx);
			key = rasmem_cons_key();
			mtx_lock(&rasmem_mtx);
			if (key)
			{
				rasmem_boot_abort = 1;
				rasmem_st.boot_status = RASMEM_BOOT_ABORTED;
				wakeup(&rasmem_bar_gen);
				mtx_unlock(&rasmem_mtx);
				for (n = 0; n < 256 && rasmem_cons_key(); n++)
				{
				}
				RAS_LOG("boot test aborted from the console, releasing test memory\n");
				mtx_lock(&rasmem_mtx);
				continue;
			}
		}
		if (sbinuptime() < next_report)
		{
			continue;
		}
		next_report = sbinuptime() + 2 * SBT_1S;
		if (rasmem_boot_abort)
		{
			continue;
		}
		if (rasmem_st.phase == RASMEM_PHASE_GLOBAL)
		{
			if (RAS_VERBOSE())
			{
				printf("rasmem: global address test: %ju MiB held\n", (uintmax_t)(ptoa(rasmem_st.global_pages) >> 20));
			}
			continue;
		}
		total = MAX(rasmem_st.boot_chunks_total, 1);
		done = MIN(rasmem_st.boot_chunks_done, total);
		pct = (int)(done * 100 / total);
		if (pct / 10 != last / 10 || RAS_VERBOSE())
		{
			mtx_unlock(&rasmem_mtx);
			printf("rasmem: boot test %d%% (%ju/%ju MiB, %u error(s))%s\n", pct, (uintmax_t)(ptoa(rasmem_st.boot_pages_tested) >> 20), (uintmax_t)(ptoa(rasmem_st.phys_pages) >> 20), rasmem_st.errors_boot, console ? ", press any key to abort" : "");
			mtx_lock(&rasmem_mtx);
			last = pct;
		}
	}
	mtx_unlock(&rasmem_mtx);
	if (console)
	{
		cnungrab();
	}
	rasmem_boot_finish();
}

static void	rasmem_main(void *);

static void rasmem_phase2(void *dummy __unused)
{
	int error, mode;

	if (!rasmem_inited)
	{
		return;
	}
	rasmem_hw_check();
	rasmem_import_vm_blacklist();
	mtx_lock(&rasmem_mtx);
	rasmem_health_eval();
	mtx_unlock(&rasmem_mtx);

	/*
	 * The main thread is created first: it keeps the "rasmem" process
	 * alive while boot workers come and go.
	 */
	rasmem_main_running = 1;
	error = kproc_kthread_add(rasmem_main, NULL, &rasmem_proc, NULL, 0, 0, "rasmem", "rasmem main");
	if (error != 0)
	{
		rasmem_main_running = 0;
		RAS_LOG("cannot create the rasmem process: %d; only boot-time testing is available\n", error);
	}

	mode = rasmem_boot_test;
	rasmem_st.boot_status = RASMEM_BOOT_OFF;
	if (mode == 0)
	{
		return;
	}
	if (!rasmem_at_boot)
	{
		/*
		 * Loaded with kldload on a running system: the boot test is
		 * a boot-time feature only.  Memory is covered by the
		 * periodic sweep instead.
		 */
		RAS_LOG("loaded at runtime: boot test skipped, memory is covered by the periodic sweep\n");
		return;
	}
	if (mp_ncpus > 1 && !smp_started)
	{
		/* Kernel without EARLY_AP_STARTUP: wait for the APs. */
		rasmem_boot_global = 0;
		if (rasmem_main_running)
		{
			rasmem_boot_deferred = true;
			RAS_LOG("APs not started yet, boot test deferred\n");
		}
		return;
	}
	if (mode == 2 && rasmem_boot_global)
	{
		/* Holding all memory while userland starts is not safe. */
		RAS_LOG("global address test needs boot_test=1, skipped\n");
		rasmem_boot_global = 0;
	}
	rasmem_boot_start();
	if (mode == 1 || !rasmem_main_running)
	{
		rasmem_boot_wait(rasmem_boot_abort_key != 0);
	}
}
/* Before kick_init (SI_ORDER_MIDDLE): no userland, root not mounted yet. */
SYSINIT(rasmem_phase2, SI_SUB_KTHREAD_INIT, SI_ORDER_FIRST, rasmem_phase2, NULL);

/* ------------------------------------------------------------------------ */
/* Phase 3: the rasmem process                                              */
/* ------------------------------------------------------------------------ */

/*
 * Periodic scan position.  A pass visits every 8 MiB slot once, in slot
 * order rasmem_pass_order: by address, or spread (bit-reversed slot
 * numbers: 0, 1/2, 1/4, 3/4, ...), so the first minutes of a pass already
 * sample all of RAM and a large faulty region is found early instead of
 * when a sequential scan reaches it.  Within a slot pages go in order.
 */
static uint64_t rasmem_cursor;		/* linear page: next to scan */
static uint64_t rasmem_slot_iter;	/* index into the slot order */
static uint64_t rasmem_slot_off;	/* pages done in the current slot */
static uint64_t rasmem_pass_done;	/* pages of this pass done */
static int rasmem_pass_order;
static uint64_t rasmem_retry_cell;	/* retry search position (map cell) */
static struct rasmem_window rasmem_win;

/* The periodic interval in milliseconds, at least RASMEM_MIN_INTERVAL. */
#define	RASMEM_MIN_INTERVAL	10
static uint64_t rasmem_interval_ms(void)
{

	return ((uint64_t)MAX(rasmem_interval, RASMEM_MIN_INTERVAL));
}

/* Pages per hour the periodic sweep has to cover. */
static uint64_t rasmem_pages_per_hour(void)
{
	uint64_t rate, sweep;

	if (rasmem_pages > 0)
	{
		return ((uint64_t)rasmem_pages * 3600000 / rasmem_interval_ms());
	}
	rate = (uint64_t)MAX(rasmem_scan_mb_per_hour, 0) * (1024 * 1024 / PAGE_SIZE);
	sweep = rasmem_sweep_hours > 0 ? rasmem_segs_pages() / (uint64_t)rasmem_sweep_hours : 0;
	return (MAX(MAX(rate, sweep), 1));
}

/* Nominal pages per run, for statistics and the start message. */
static uint64_t rasmem_run_pages(void)
{
	uint64_t pph, pages;

	pph = rasmem_pages_per_hour();
	pages = MAX(pph * rasmem_interval_ms() / 3600000, 1);
	rasmem_st.scan_pages_per_run = pages;
	rasmem_st.scan_bytes_per_hour = ptoa(pph);
	return (pages);
}

/* Largest power of two <= n that pa is aligned to (<= RASMEM_SUB_PAGES). */
static u_int rasmem_aligned_step(vm_paddr_t pa, uint64_t n)
{
	u_int a, step;

	a = (u_int)(atop(pa) & (RASMEM_SUB_PAGES - 1));
	step = a == 0 ? RASMEM_SUB_PAGES : 1u << (ffs(a) - 1);
	while (step > n)
	{
		step >>= 1;
	}
	return (step);
}

static void rasmem_win_flush(uint32_t patterns, int hold_ms, int src, uint64_t *tested, uint64_t *bytes)
{

	*tested += rasmem_win_run(&rasmem_win, patterns, MIN(MAX(hold_ms, 0), 10000), rasmem_hold_patterns & RASMEM_PAT_ALL, src, bytes);
}

/*
 * Collect [pa, pa + n) in aligned pieces, testing whenever full.  Stops
 * early when the run's allocator budget is spent; returns the pages it went
 * through (taken or found in use).
 */
static uint64_t rasmem_collect_range(vm_paddr_t pa, uint64_t n, int dom, uint32_t patterns, int hold_ms, int src, uint64_t *tested, uint64_t *bytes)
{
	uint64_t done;
	u_int step;

	for (done = 0; done < n && !rasmem_stop; done += step)
	{
		if (rasmem_win_spent(&rasmem_win))
		{
			break;
		}
		step = rasmem_aligned_step(pa, n - done);
		if (rasmem_win.npages + step > rasmem_win.maxpages)
		{
			rasmem_win_flush(patterns, hold_ms, src, tested, bytes);
		}
		rasmem_win_collect(&rasmem_win, pa, step, dom);
		pa += ptoa(step);
	}
	return (done);
}

static void rasmem_win_stats(uint64_t tested, uint64_t bytes, uint64_t skipped0, uint64_t held0, uint64_t breaks0)
{

	atomic_add_64(&rasmem_st.pages_tested, tested);
	atomic_add_64(&rasmem_st.bytes_tested, bytes);
	atomic_add_64(&rasmem_st.pages_skipped, rasmem_win.skipped - skipped0);
	rasmem_st.held_pages += rasmem_win.held - held0;
	rasmem_st.reserv_breaks += rasmem_win.breaks - breaks0;
}

/*
 * May the scan break the partly used reservations in [lin, lin + n)?  With
 * hw.rasmem.break_reserv=1 only where the previous pass found free memory
 * held there too: a reservation still partly used after a pass (an hour or
 * more) is unlikely to fill up, so its owner loses little.
 */
static bool rasmem_may_break(uint64_t lin, uint64_t n)
{
	uint64_t c, c1;

	if (rasmem_break_reserv >= 2)
	{
		return (true);
	}
	if (rasmem_break_reserv != 1 || rasmem_map == NULL || n == 0)
	{
		return (false);
	}
	c1 = MIN((lin + n - 1) >> rasmem_map_shift, rasmem_map_cells - 1);
	for (c = lin >> rasmem_map_shift; c <= c1; c++)
	{
		if (rasmem_map[c] & RASMEM_MAP_PREV_HELD)
		{
			return (true);
		}
	}
	return (false);
}

/*
 * March C- and the retention hold are too expensive for every page on every
 * pass, so each pass applies them to a rotating 1/N of memory.  Memory is
 * divided into fixed slots by linear page index.  The slot visited k-th in
 * a pass (its key, see rasmem_slot_key()) gets March C- on passes where
 * (k + pass) % march_every == 0 and the hold where
 * (k + pass + hold_every / 2) % hold_every == 0.  Every slot therefore gets
 * each exactly once every N passes, independent of run sizes and timing,
 * and every N-th slot visited gets each, so the expensive tests are spread
 * evenly over the pass in time.  (Keying by slot number instead would
 * clump them: the spread order visits only even slots in the first half
 * of a pass.)
 */
#define	RASMEM_SLOT_PAGES	2048	/* 8 MiB */

/*
 * Failed allocator calls allowed per run.  Each one costs a free list search
 * under the domain's free page lock and adds to the page daemon's deficit
 * (see rasmem_test.c), so a run that keeps hitting memory the hints call
 * free but the allocator does not have stops early instead of disturbing the
 * system.  The pages it did not reach are not counted as in use: the next
 * run continues there, so the scan only gets slower.  The retries of busy
 * blocks get half as many.
 */
#define	RASMEM_RUN_FAILS	16

/*
 * The rate (hw.rasmem.scan_mb_per_hour, hw.rasmem.sweep_hours) is an
 * amount of memory tested.  Memory the hints show in use is passed over at 1/RASMEM_SKIP_DIV
 * of the cost of testing it: deciding costs one page structure read per
 * 256 KiB, no allocator call.  So a busy machine spends its testing time on
 * the memory that is free, and its passes are shorter; a run walks at most
 * RASMEM_SKIP_DIV times its quota.  Without the hints every skipped piece
 * costs an allocator call and counts in full.
 */
#define	RASMEM_SKIP_DIV		16

static void rasmem_slot_policy(uint64_t slot, uint64_t pass, uint32_t *patterns, int *hold)
{
	uint64_t me, he;

	me = (uint64_t)MAX(rasmem_march_every, 1);
	he = (uint64_t)MAX(rasmem_hold_every, 1);
	*patterns = rasmem_periodic_patterns & RASMEM_PAT_ALL;
	if (me > 1 && (slot + pass) % me != 0)
	{
		*patterns &= ~RASMEM_PAT_MARCH;
	}
	*hold = (he == 1 || (slot + pass + he / 2) % he == 0) ? rasmem_hold_ms : 0;
}

static sbintime_t rasmem_last_scan;	/* previous periodic run */
static uint64_t rasmem_scan_carry;	/* fractional pages (x 3600000) */
static uint64_t rasmem_scan_debt;	/* pages tested beyond the quota */
static time_t rasmem_sweep_start;
static uint64_t rasmem_lowmem_skips;
static time_t rasmem_lowmem_log;

static uint64_t rasmem_bitrev(uint64_t v, u_int bits)
{
	uint64_t r;
	u_int i;

	for (r = 0, i = 0; i < bits; i++, v >>= 1)
	{
		r = (r << 1) | (v & 1);
	}
	return (r);
}

/*
 * The next pages to scan in this pass: *lin and how many are left in the
 * slot.  False when the pass is complete.
 */
static bool rasmem_scan_pos(uint64_t total, uint64_t *lin, uint64_t *left)
{
	uint64_t nslots, niter, slot, start, len;
	u_int bits;

	nslots = howmany(total, RASMEM_SLOT_PAGES);
	bits = nslots > 1 ? flsll(nslots - 1) : 0;
	niter = rasmem_pass_order != 0 ? (uint64_t)1 << bits : nslots;
	for (; rasmem_slot_iter < niter; rasmem_slot_iter++, rasmem_slot_off = 0)
	{
		slot = rasmem_pass_order != 0 ? rasmem_bitrev(rasmem_slot_iter, bits) : rasmem_slot_iter;
		if (slot >= nslots)
		{
			continue;
		}
		start = slot * RASMEM_SLOT_PAGES;
		len = MIN(RASMEM_SLOT_PAGES, total - start);
		if (rasmem_slot_off < len)
		{
			*lin = start + rasmem_slot_off;
			*left = len - rasmem_slot_off;
			return (true);
		}
	}
	return (false);
}

/*
 * Position of a slot in this pass's visit order.  Bit reversal is its own
 * inverse, so for the spread order the key is the reversed slot number.
 */
static uint64_t rasmem_slot_key(uint64_t slot)
{
	uint64_t nslots;
	u_int bits;

	if (rasmem_pass_order == 0)
	{
		return (slot);
	}
	nslots = howmany(rasmem_segs_pages(), RASMEM_SLOT_PAGES);
	bits = nslots > 1 ? flsll(nslots - 1) : 0;
	return (rasmem_bitrev(slot, bits));
}

/* What one run did, for statistics and the verbose log. */
struct rasmem_run
{
	uint32_t	patterns;	/* policy of the open window */
	int		hold;
	uint64_t	march_pages;
	uint64_t	hold_pages;
	uint64_t	bytes;
};

/*
 * Test [lin, lin + n) (inside one slot and one segment) with the slot's
 * policy and record it in the coverage map.  Returns how much of it was
 * scanned, less than n if the run's allocator budget ran out; *skp is set to
 * the pages of that part that could not be taken.
 */
static uint64_t rasmem_scan_piece(struct rasmem_run *rr, uint64_t lin, vm_paddr_t pa, uint64_t n, int dom, uint64_t *tested, uint16_t extra, uint64_t *skp)
{
	uint64_t sk, held;
	uint32_t spat;
	int shold;
	uint16_t mbits;

	rasmem_slot_policy(rasmem_slot_key(lin / RASMEM_SLOT_PAGES), rasmem_st.periodic_sweeps, &spat, &shold);
	if (spat != rr->patterns || shold != rr->hold)
	{
		/* The window is tested with one policy at a time. */
		rasmem_win_flush(rr->patterns, rr->hold, RASMEM_SRC_PERIODIC, tested, &rr->bytes);
		rr->patterns = spat;
		rr->hold = shold;
	}
	sk = rasmem_win.skipped;
	held = rasmem_win.held;
	rasmem_win.may_break = rasmem_may_break(lin, n);
	n = rasmem_collect_range(pa, n, dom, rr->patterns, rr->hold, RASMEM_SRC_PERIODIC, tested, &rr->bytes);
	rasmem_win.may_break = false;
	*skp = sk = rasmem_win.skipped - sk;
	held = rasmem_win.held - held;
	if (n == 0)
	{
		return (0);
	}
	mbits = RASMEM_MAP_VISITED | extra | (sk < n ? RASMEM_MAP_TESTED : 0) | (sk > 0 ? RASMEM_MAP_SKIPPED : 0) | (held > 0 ? RASMEM_MAP_HELD : 0);
	if (sk < n && (rr->patterns & RASMEM_PAT_MARCH))
	{
		mbits |= RASMEM_MAP_MARCH;
		rr->march_pages += n - sk;
	}
	if (sk < n && rr->hold > 0 && (rasmem_hold_patterns & rr->patterns) != 0)
	{
		mbits |= RASMEM_MAP_HOLD;
		rr->hold_pages += n - sk;
	}
	rasmem_map_mark(lin, n, mbits);
	if ((extra & RASMEM_MAP_RETRIED) == 0)
	{
		rasmem_map_count(lin, n, n - sk);
	}
	return (n);
}

static void rasmem_pass_complete(uint64_t total)
{

	rasmem_map_new_pass();
	rasmem_st.periodic_sweeps++;
	rasmem_st.last_sweep_tested = rasmem_st.sweep_tested;
	rasmem_st.last_sweep_secs = time_uptime - rasmem_sweep_start;
	RAS_LOG("full pass #%ju over all memory complete in %ju min: %ju%% of pages tested\n", (uintmax_t)rasmem_st.periodic_sweeps, (uintmax_t)(rasmem_st.last_sweep_secs / 60), (uintmax_t)(rasmem_st.sweep_tested * 100 / MAX(total, 1)));
	rasmem_st.sweep_tested = 0;
	rasmem_sweep_start = time_uptime;
	rasmem_slot_iter = rasmem_slot_off = rasmem_pass_done = 0;
	rasmem_pass_order = rasmem_scan_order;
	rasmem_retry_cell = 0;
}

/*
 * Retry blocks of this pass that were partly in use when the scan passed
 * them: memory is freed and reused all the time, so many are free now.
 * A block whose retry took every page counts as completely tested.
 */
static uint64_t rasmem_retry_skipped(struct rasmem_run *rr, uint64_t budget, uint64_t total, uint64_t *tested)
{
	vm_paddr_t pa;
	uint64_t c, lin0, len, off, n, got, sk, psk, done, looked, cell;
	u_int run;
	int dom;
	uint16_t v;

	if (rasmem_map == NULL || budget == 0)
	{
		return (0);
	}
	cell = (uint64_t)1 << rasmem_map_shift;
	done = 0;
	for (looked = 0; done < budget && !rasmem_stop && looked < MIN(rasmem_map_cells, 65536); looked++)
	{
		c = rasmem_retry_cell;
		rasmem_retry_cell = (c + 1) % rasmem_map_cells;
		v = rasmem_map[c];
		if ((v & (RASMEM_MAP_VISITED | RASMEM_MAP_SKIPPED | RASMEM_MAP_RETRIED | RASMEM_MAP_FAILED)) != (RASMEM_MAP_VISITED | RASMEM_MAP_SKIPPED))
		{
			continue;
		}
		lin0 = c * cell;
		len = MIN(cell, total - lin0);
		if (rasmem_win_spent(&rasmem_win))
		{
			/* Out of allocator budget: this cell next time. */
			rasmem_retry_cell = c;
			break;
		}
		atomic_set_16(&rasmem_map[c], RASMEM_MAP_RETRIED);
		sk = 0;
		for (off = 0; off < len && !rasmem_stop; off += got)
		{
			if (!rasmem_lin_to_pa(lin0 + off, &pa, &run, &dom))
			{
				break;
			}
			n = MIN(MIN(run, len - off), RASMEM_CHUNK_PAGES);
			n = MIN(n, RASMEM_SLOT_PAGES - (lin0 + off) % RASMEM_SLOT_PAGES);
			got = rasmem_scan_piece(rr, lin0 + off, pa, n, dom, tested, RASMEM_MAP_RETRIED, &psk);
			sk += psk;
			if (got < n)
			{
				break;
			}
		}
		if (off < len && rasmem_win_spent(&rasmem_win))
		{
			/*
			 * Cut short by the budget: the cell keeps its
			 * retry, the next run starts again with it.
			 */
			atomic_clear_16(&rasmem_map[c], RASMEM_MAP_RETRIED);
			rasmem_retry_cell = c;
			break;
		}
		if (off == len && sk == 0)
		{
			atomic_clear_16(&rasmem_map[c], RASMEM_MAP_SKIPPED);
		}
		/* The retry tested the whole cell again: keep the better. */
		if (off == len && len - sk > rasmem_map_cnt[c])
		{
			rasmem_map_cnt[c] = (uint16_t)(len - sk);
		}
		done += len;
	}
	return (done);
}

/*
 * One periodic run.  The amount is derived from the time since the last
 * run and the hourly rate, so the rate holds however long runs take;
 * expensive work (March C-, the retention hold) is spread over runs.
 */
static void rasmem_periodic_scan(void)
{
	struct rasmem_run rr;
	vm_paddr_t pa;
	sbintime_t nowsbt;
	uint64_t want, done, walked, total, tested, rtested, n, got, sk;
	uint64_t dtms, acc, nominal, s0, h0, b0, lin, left;
	struct rasmem_tm tm;
	u_int run;
	int dom;

	if ((rasmem_periodic_patterns & RASMEM_PAT_ALL) == 0)
	{
		return;
	}

	/* How much is due since the last run. */
	nowsbt = sbinuptime();
	nominal = rasmem_run_pages();
	dtms = rasmem_last_scan == 0 ? rasmem_interval_ms() : (uint64_t)((nowsbt - rasmem_last_scan) / SBT_1MS);
	rasmem_last_scan = nowsbt;
	acc = rasmem_pages_per_hour() * dtms + rasmem_scan_carry;
	want = acc / 3600000;
	rasmem_scan_carry = acc % 3600000;
	total = rasmem_segs_pages();
	/* Do not try to catch up more than ten runs after a stall. */
	want = MIN(want, 10 * nominal);
	want = MIN(want, total);
	/*
	 * Runs take whole 256 KiB pieces, so with a short interval a run can
	 * test more than its quota: the next runs make up for it.
	 */
	if (rasmem_scan_debt >= want)
	{
		rasmem_scan_debt -= want;
		return;
	}
	want -= rasmem_scan_debt;
	rasmem_scan_debt = 0;
	if (!rasmem_mem_ok(want))
	{
		/* Memory is short: skip, and do not owe the pages later. */
		rasmem_scan_carry = 0;
		rasmem_lowmem_skips++;
		if (time_uptime >= rasmem_lowmem_log)
		{
			RAS_LOG("periodic scan paused: free memory is near the page daemon target (%ju run(s) skipped)\n", (uintmax_t)rasmem_lowmem_skips);
			rasmem_lowmem_log = time_uptime + 600;
		}
		return;
	}

	rasmem_tm_start(&tm);
	rasmem_st.phase = RASMEM_PHASE_PERIODIC;
	/* Reservations are broken only explicitly (rasmem_grab_break()). */
	rasmem_win.reqx = VM_ALLOC_NORECLAIM;
	rasmem_win_budget(&rasmem_win, RASMEM_RUN_FAILS);
	s0 = rasmem_win.skipped;
	h0 = rasmem_win.held;
	b0 = rasmem_win.breaks;
	if (rasmem_sweep_start == 0)
	{
		rasmem_sweep_start = time_uptime;
		rasmem_pass_order = rasmem_scan_order;
	}

	bzero(&rr, sizeof(rr));
	tested = rtested = walked = 0;
	for (done = 0; done < want && !rasmem_stop && walked < MIN(RASMEM_SKIP_DIV * want, total);)
	{
		if (!rasmem_scan_pos(total, &lin, &left))
		{
			/* A full pass over all memory is complete. */
			rasmem_win_flush(rr.patterns, rr.hold, RASMEM_SRC_PERIODIC, &tested, &rr.bytes);
			rasmem_st.sweep_tested += tested;
			atomic_add_64(&rasmem_st.pages_tested, tested);
			tested = 0;
			rasmem_pass_complete(total);
			got = 0;
			continue;
		}
		if (!rasmem_lin_to_pa(lin, &pa, &run, &dom))
		{
			/* Cannot happen: lin < total.  Skip the slot. */
			rasmem_slot_off += left;
			got = 0;
			continue;
		}
		/*
		 * Whole 256 KiB pieces, also at the end of the quota: small
		 * pieces would mean small allocator requests.
		 */
		n = MIN(MIN(run, roundup2(want - done, RASMEM_SUB_PAGES)), MIN(left, RASMEM_CHUNK_PAGES));
		got = rasmem_scan_piece(&rr, lin, pa, n, dom, &tested, 0, &sk);
		walked += got;
		done += rasmem_hints_enabled() ? got - sk + howmany(sk, RASMEM_SKIP_DIV) : got;
		rasmem_slot_off += got;
		rasmem_pass_done += got;
		rasmem_cursor = lin + got;
		if (got < n)
		{
			/* Allocator budget spent: continue here next run. */
			rasmem_st.budget_stops++;
			break;
		}
	}
	rasmem_win_flush(rr.patterns, rr.hold, RASMEM_SRC_PERIODIC, &tested, &rr.bytes);
	if (done > want)
	{
		rasmem_scan_debt = done - want;
	}

	/* Then a little extra for blocks that were busy when scanned. */
	if (rasmem_retry_pct > 0 && !rasmem_stop)
	{
		rasmem_win_budget(&rasmem_win, RASMEM_RUN_FAILS / 2);
		(void)rasmem_retry_skipped(&rr, want * (uint64_t)MIN(rasmem_retry_pct, 100) / 100, total, &rtested);
		rasmem_win_flush(rr.patterns, rr.hold, RASMEM_SRC_PERIODIC, &rtested, &rr.bytes);
		rasmem_st.retry_pages += rtested;
	}

	if (rasmem_scan_pos(total, &lin, &left))
	{
		rasmem_cursor = lin;
		if (rasmem_lin_to_pa(lin, &pa, &run, &dom))
		{
			rasmem_st.periodic_cursor = pa;
		}
	}
	rasmem_st.sweep_pos = rasmem_pass_done;
	rasmem_st.sweep_tested += tested;
	rasmem_st.periodic_runs++;
	rasmem_win_stats(tested + rtested, rr.bytes, s0, h0, b0);
	rasmem_st.last_run_usec = rasmem_tm_stop(&tm, &rasmem_st.busy_periodic_usec);
	rasmem_st.last_run_pages = tested + rtested;
	rasmem_st.last_run_ts = time_second;
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	RAS_VLOG("periodic run: %ju page(s) tested (%ju with March C-, %ju with retention hold, %ju retried), %ju in use (%ju of them free but held by the VM), %ju reservation(s) broken, %ju walked, next 0x%016jx\n", (uintmax_t)(tested + rtested), (uintmax_t)rr.march_pages, (uintmax_t)rr.hold_pages, (uintmax_t)rtested, (uintmax_t)(rasmem_win.skipped - s0), (uintmax_t)(rasmem_win.held - h0), (uintmax_t)(rasmem_win.breaks - b0), (uintmax_t)walked, (uintmax_t)rasmem_st.periodic_cursor);
}

/*
 * Faults cluster (rows, columns, banks), so after a new bad page test the
 * free part of its physical neighbourhood thoroughly.
 */
static void rasmem_neighbor_scan(void)
{
	vm_paddr_t pa, lo, hi, sstart, send, span;
	uint64_t tested, bytes, s0, h0, b0;
	struct rasmem_tm tm;
	uint32_t patterns;
	int dom;

	patterns = rasmem_retest_patterns & RASMEM_PAT_ALL;
	span = ptoa((vm_paddr_t)MIN(MAX(rasmem_neighbor_pages, 0), 4096));
	rasmem_win.reqx = VM_ALLOC_NORECLAIM;
	s0 = rasmem_win.skipped;
	h0 = rasmem_win.held;
	b0 = rasmem_win.breaks;
	tested = bytes = 0;
	rasmem_tm_start(&tm);
	for (;;)
	{
		mtx_lock(&rasmem_mtx);
		if (rasmem_nbq_n == 0 || rasmem_stop)
		{
			mtx_unlock(&rasmem_mtx);
			break;
		}
		pa = rasmem_nbq[--rasmem_nbq_n];
		mtx_unlock(&rasmem_mtx);
		if (patterns == 0 || span == 0 || !rasmem_pa_seg(pa, &sstart, &send))
		{
			continue;
		}
		if (!rasmem_mem_ok(atop(2 * span)))
		{
			/* Memory is short: put it back and try later. */
			mtx_lock(&rasmem_mtx);
			rasmem_nbq_push(pa);
			mtx_unlock(&rasmem_mtx);
			break;
		}
		rasmem_st.phase = RASMEM_PHASE_NEIGHBOR;
		lo = pa > span ? pa - span : 0;
		lo = MAX(rounddown2(lo, ptoa(RASMEM_SUB_PAGES)), sstart);
		hi = MIN(roundup2(pa + PAGE_SIZE + span, ptoa(RASMEM_SUB_PAGES)), send);
		dom = rasmem_pa_domain(pa);
		RAS_VLOG("neighbourhood retest 0x%016jx-0x%016jx\n", (uintmax_t)lo, (uintmax_t)hi);
		rasmem_win_budget(&rasmem_win, RASMEM_RUN_FAILS);
		(void)rasmem_collect_range(lo, atop(hi - lo), dom, patterns, rasmem_hold_ms, RASMEM_SRC_NEIGHBOR, &tested, &bytes);
		rasmem_win_flush(patterns, rasmem_hold_ms, RASMEM_SRC_NEIGHBOR, &tested, &bytes);
		rasmem_st.neighbor_tests++;
	}
	rasmem_win_stats(tested, bytes, s0, h0, b0);
	if (tested > 0)
	{
		rasmem_tm_stop(&tm, &rasmem_st.busy_neighbor_usec);
	}
	rasmem_st.phase = RASMEM_PHASE_IDLE;
}

/*
 * Retest every page nobody else can touch (held or boot-blacklisted) with
 * all patterns and the retention hold, update the records and classify.
 * Known bad pages still in use are evacuated (their data moved off) and
 * quarantined first.
 */
static void rasmem_retest_all(void)
{
	struct rasmem_span *sp;
	struct rasmem_fail *f;
	struct rasmem_region *r;
	vm_page_t m, rel;
	vm_paddr_t pa, apa;
	uint64_t bytes;
	time_t now;
	u_int i, j, n, ns, patterns, fails, tested, first;
	u_int *idx;
	struct rasmem_tm tm;
	int dom, oldclass;
	bool bad, drop, movable;

	patterns = rasmem_retest_patterns & RASMEM_PAT_ALL;
	if (patterns == 0)
	{
		return;
	}
	rasmem_st.phase = RASMEM_PHASE_RETEST;
	rasmem_tm_start(&tm);
	idx = malloc(rasmem_win.maxpages * sizeof(*idx), M_RASMEM, M_WAITOK);
	tested = fails = 0;
	bytes = 0;

	mtx_lock(&rasmem_mtx);
	n = rasmem_nrec;
	mtx_unlock(&rasmem_mtx);
	for (first = 0; first < n && !rasmem_stop; first = i)
	{
		/* Build a batch of single-page spans. */
		ns = 0;
		for (i = first; i < n && ns < rasmem_win.maxpages; i++)
		{
			mtx_lock(&rasmem_mtx);
			pa = rasmem_recs[i].r.start_addr;
			m = rasmem_recs[i].m;
			j = rasmem_recs[i].r.state;
			mtx_unlock(&rasmem_mtx);
			if (j == RASMEM_ST_INUSE && (dom = rasmem_pa_domain(pa)) >= 0)
			{
				/* Evacuate its data, then quarantine it. */
				m = rasmem_grab(pa, 1, dom, 0);
				if (m == NULL && rasmem_evacuate && rasmem_mem_ok(4 * RASMEM_MINI_PAGES))
				{
					apa = rounddown2(pa, ptoa(RASMEM_MINI_PAGES));
					(void)rasmem_used_mask(apa, RASMEM_MINI_PAGES, &movable);
					if (movable && rasmem_evacuate_range(apa, RASMEM_MINI_PAGES, dom))
					{
						m = rasmem_grab(pa, 1, dom, 0);
					}
				}
				if (m != NULL)
				{
					mtx_lock(&rasmem_mtx);
					rasmem_recs[i].m = m;
					rasmem_recs[i].r.state = j = RASMEM_ST_HELD;
					rasmem_dirty = 1;
					rec_recount();
					mtx_unlock(&rasmem_mtx);
					RAS_LOG("known bad page 0x%016jx evacuated and quarantined\n", (uintmax_t)pa);
				}
			}
			if (j != RASMEM_ST_HELD && j != RASMEM_ST_BLACKLISTED)
			{
				continue;
			}
			sp = &rasmem_win.spans[ns];
			bzero(sp, sizeof(*sp));
			sp->pa = pa;
			sp->m = m;
			sp->npages = 1;
			sp->fidx = ns;
			idx[ns++] = i;
		}
		if (ns == 0)
		{
			continue;
		}

		rasmem_test_spans(rasmem_win.spans, ns, patterns, MIN(MAX(rasmem_hold_ms, 0), 10000), rasmem_hold_patterns & RASMEM_PAT_ALL, true, rasmem_win.fails, &bytes);
		now = time_second;
		tested += ns;

		if (rasmem_stop)
		{
			break;		/* results of an interrupted batch are void */
		}
		for (j = 0; j < ns; j++)
		{
			f = &rasmem_win.fails[j];
			bad = f->nbad != 0;
			rel = NULL;
			drop = false;
			mtx_lock(&rasmem_mtx);
			r = &rasmem_recs[idx[j]].r;
			r->retests++;
			r->last_test_ts = now;
			if (bad)
			{
				fails++;
				r->retest_fails++;
				r->errors++;
				r->last_error_ts = now;
				r->bad_bits |= f->xor_or;
				r->last_xor = f->last_xor;
				r->bad_offset = f->first_off;
				r->pattern = f->pattern;
				r->consecutive_pass = 0;
			}
			else
			{
				r->consecutive_pass++;
			}
			oldclass = r->class;
			rasmem_classify(r);
			if (r->flags & RASMEM_RF_UNVERIFIED)
			{
				if (bad)
				{
					r->flags &= ~RASMEM_RF_UNVERIFIED;
					RAS_LOG("page 0x%016jx confirmed bad on the new configuration\n", (uintmax_t)r->start_addr);
				}
				else if (r->retests >= (u_int)MAX(rasmem_classify_retests, 1))
				{
					drop = true;
				}
			}
			if (!drop && r->class == RASMEM_CLASS_TRANSIENT && rasmem_release_transient && r->state == RASMEM_ST_HELD)
			{
				rel = rasmem_recs[idx[j]].m;
				rasmem_recs[idx[j]].m = NULL;
				r->state = RASMEM_ST_RELEASED;
			}
			if (drop)
			{
				rel = rasmem_recs[idx[j]].m;
				rasmem_recs[idx[j]].m = NULL;
				/* Marked; removed after the batch. */
				r->state = RASMEM_ST_RELEASED;
				r->class = RASMEM_CLASS_TRANSIENT;
				r->source = RASMEM_SRC_DB;
				r->reserved = 1;
			}
			rasmem_dirty = 1;
			if (r->class != oldclass || drop)
			{
				rasmem_urgent_save = 1;
			}
			pa = r->start_addr;
			mtx_unlock(&rasmem_mtx);

			if (bad)
			{
				RAS_VLOG("retest: page 0x%016jx failed again (xor 0x%016jx, pattern %s)\n", (uintmax_t)pa, (uintmax_t)f->xor_or, rasmem_pattern_name(f->pattern));
			}
			if (drop)
			{
				RAS_LOG("page 0x%016jx passed re-verification, record dropped\n", (uintmax_t)pa);
			}
			else if (r->class != oldclass)
			{
				RAS_LOG("page 0x%016jx classified %s (%u/%u retests failed)\n", (uintmax_t)pa, CLASS_NAME(r->class), r->retest_fails, r->retests);
			}
			if (rel != NULL)
			{
				rasmem_release(rel, 1);
				if (!drop)
				{
					RAS_LOG("page 0x%016jx released back to the VM system (transient)\n", (uintmax_t)pa);
				}
			}
		}
		maybe_yield();
	}
	free(idx, M_RASMEM);

	/* Remove records dropped by re-verification (marked reserved=1). */
	mtx_lock(&rasmem_mtx);
	for (i = 0; i < rasmem_nrec;)
	{
		if (rasmem_recs[i].r.reserved == 1 && rasmem_recs[i].m == NULL)
		{
			rec_remove(&rasmem_recs[i]);
			continue;
		}
		i++;
	}
	rec_recount();
	mtx_unlock(&rasmem_mtx);

	rasmem_st.retests += tested;
	atomic_add_64(&rasmem_st.bytes_tested, bytes);
	rasmem_tm_stop(&tm, &rasmem_st.busy_retest_usec);
	rasmem_st.phase = RASMEM_PHASE_IDLE;
	rasmem_policy_check();
	if (tested > 0)
	{
		RAS_VLOG("retest: %u bad page(s) retested, %u failed\n", tested, fails);
	}
}

/* Testing aid: quarantine some free page and pretend it failed. */
static void rasmem_do_inject(bool corrupt)
{
	struct rasmem_fail f;
	vm_page_t m;

	m = rasmem_alloc_page();
	if (m == NULL)
	{
		return;
	}
	bzero(&f, sizeof(f));
	f.nbad = 1;
	f.first_off = 0x40;
	f.xor_or = f.last_xor = 1ULL << (arc4random() % 64);
	f.pattern = 0;
	rasmem_report(VM_PAGE_TO_PHYS(m), m, &f, corrupt ? RASMEM_SRC_RECLAIM : RASMEM_SRC_INJECT);
}

/* Drop a record (administrator request via hw.rasmem.forget). */
static void rasmem_do_forget(vm_paddr_t pa)
{
	struct rasmem_rec *r;
	vm_page_t m;
	int st;

	m = NULL;
	mtx_lock(&rasmem_mtx);
	r = rec_find(trunc_page(pa));
	if (r == NULL)
	{
		mtx_unlock(&rasmem_mtx);
		RAS_LOG("forget: no record for 0x%016jx\n", (uintmax_t)pa);
		return;
	}
	m = r->m;
	st = r->r.state;
	rec_remove(r);
	rasmem_dirty = 1;
	rasmem_urgent_save = 1;
	rec_recount();
	mtx_unlock(&rasmem_mtx);
	if (m != NULL)
	{
		rasmem_release(m, 1);
	}
	RAS_LOG("forget: record for 0x%016jx removed%s\n", (uintmax_t)pa, st == RASMEM_ST_BLACKLISTED ? " (stays blacklisted until reboot)" : "");
	rasmem_policy_check();
}

static void rasmem_fix_timestamps(void)
{
	u_int i;
	time_t now;

	/* Errors found before the RTC was read have bogus times. */
	now = time_second;
	mtx_lock(&rasmem_mtx);
	if (!rasmem_time_valid(rasmem_st.load_ts))
	{
		rasmem_st.load_ts = now;
	}
	if (rasmem_st.last_error_ts > 0 && !rasmem_time_valid(rasmem_st.last_error_ts))
	{
		rasmem_st.last_error_ts = now;
	}
	for (i = 0; i < rasmem_nrec; i++)
	{
		if (rasmem_recs[i].r.first_error_ts > 0 && !rasmem_time_valid(rasmem_recs[i].r.first_error_ts))
		{
			rasmem_recs[i].r.first_error_ts = now;
		}
		if (rasmem_recs[i].r.last_error_ts > 0 && !rasmem_time_valid(rasmem_recs[i].r.last_error_ts))
		{
			rasmem_recs[i].r.last_error_ts = now;
		}
		if (rasmem_recs[i].r.last_test_ts > 0 && !rasmem_time_valid(rasmem_recs[i].r.last_test_ts))
		{
			rasmem_recs[i].r.last_test_ts = now;
		}
	}
	rasmem_health_eval();
	mtx_unlock(&rasmem_mtx);
}

static void rasmem_policy_tick(time_t now)
{
	char why[96], dimm[96];
	u_int c, inuse;
	uint32_t reasons;
	int error;

	c = rasmem_st.corrupt_boot;
	if (rasmem_st.reboot_required && now >= rasmem_next_warn)
	{
		printf("rasmem: *** %u live-data memory corruption event(s) since boot (threshold %d): data in RAM may be corrupted, REBOOT this machine. ***\n", c, rasmem_warn_threshold);
		rasmem_notify("REBOOT_REQUIRED", "corruption=%u errors=%u", c, rasmem_st.errors_boot);
		rasmem_next_warn = now + MAX(rasmem_warn_interval, 1);
	}
	reasons = rasmem_st.replace_reasons;
	inuse = rasmem_st.bad_pages_inuse;
	if ((reasons != 0 || inuse != 0) && now >= rasmem_next_replace_warn)
	{
		mtx_lock(&rasmem_mtx);
		rasmem_dimm_names(rasmem_suspect_mask, dimm, sizeof(dimm));
		mtx_unlock(&rasmem_mtx);
		if (reasons != 0)
		{
			rasmem_reasons_str(reasons, why, sizeof(why));
			printf("rasmem: *** MEMORY IS FAILING (%s): %u bad page(s), %u new in %d day(s), worst data bit %d (%u pages); REPLACE module(s): %s ***\n", why, rasmem_st.active_pages, rasmem_st.trend_pages, rasmem_trend_days, rasmem_st.lane_bit, rasmem_st.lane_max_pages, dimm);
			rasmem_notify("REPLACE_MEMORY", "reasons=0x%x pages=%u dimm=%s", reasons, rasmem_st.active_pages, dimm);
		}
		if (inuse != 0)
		{
			printf("rasmem: *** %u known bad page(s) are in use and cannot be isolated ***\n", inuse);
		}
		rasmem_next_replace_warn = now + MAX(rasmem_replace_warn_interval, 60);
	}

	if (!rasmem_st.panic_pending)
	{
		return;
	}
	error = 0;
	if (rasmem_dirty)
	{
		error = rasmem_save("panic pending");
	}
	if (!rasmem_dirty || now - rasmem_panic_since >= MAX(rasmem_panic_save_timeout, 0))
	{
		panic("rasmem: %u live-data memory corruption event(s) since boot (panic threshold %d, ro_action %d): memory is corrupted", c, rasmem_panic_threshold, rasmem_ro_action);
	}
	if ((now - rasmem_panic_since) % 10 == 0)
	{
		RAS_LOG("panic pending, waiting to save the database (error %d, %jd s left)\n", error, (intmax_t)(rasmem_panic_since + rasmem_panic_save_timeout - now));
	}
}

static void rasmem_main(void *arg __unused)
{
	time_t now, start, next_retest, next_ro, next_save;
	time_t next_try, next_eval;
	sbintime_t next_sbt, rem;
	bool started, ts_fixed;
	u_int ninject;
	int error, slp;

	rasmem_main_started = true;
	rasmem_win_init(&rasmem_win, (u_int)MIN(MAX(rasmem_window_mb, 1), 4096) * (1024 * 1024 / PAGE_SIZE));
	started = ts_fixed = false;
	start = time_uptime + MAX(rasmem_start_delay, 0);
	next_retest = next_ro = next_save = next_try = 0;
	next_sbt = 0;
	next_eval = 0;

	while (!rasmem_stop)
	{
		now = time_uptime;

		if (rasmem_boot_deferred && smp_started)
		{
			rasmem_boot_deferred = false;
			rasmem_boot_start();
		}
		if (atomic_load_int(&rasmem_boot_running) == 0 && rasmem_workers != NULL)
		{
			rasmem_boot_finish();
		}
		if (!ts_fixed && rasmem_time_valid(time_second))
		{
			rasmem_fix_timestamps();
			ts_fixed = true;
		}
		if (rasmem_want_rebaseline)
		{
			rasmem_want_rebaseline = 0;
			if (rasmem_ro_crc != NULL && !rasmem_ro_patching_active())
			{
				rasmem_ro_baseline();
				RAS_LOG("read-only checksum baseline recomputed\n");
			}
		}
		if (rasmem_want_forget)
		{
			rasmem_do_forget(rasmem_forget_pa);
			rasmem_want_forget = 0;
		}
		for (ninject = atomic_readandclear_int(&rasmem_want_inject); ninject > 0; ninject--)
		{
			rasmem_do_inject(false);
		}
		for (ninject = atomic_readandclear_int(&rasmem_want_inject_corrupt); ninject > 0; ninject--)
		{
			rasmem_do_inject(true);
		}

		if (atomic_load_int(&rasmem_boot_running) == 0 && !rasmem_boot_deferred && now >= start)
		{
			if (!started)
			{
				started = true;
				next_retest = next_ro = now;
				next_sbt = sbinuptime();
				(void)rasmem_run_pages();
				RAS_LOG("periodic testing started: %ju KiB every %ju ms (%ju GiB/h of free memory, a pass at most every ~%ju min), March C- on 1/%d and a %d ms retention hold on 1/%d of memory per pass\n", (uintmax_t)(ptoa(rasmem_st.scan_pages_per_run) >> 10), (uintmax_t)rasmem_interval_ms(), (uintmax_t)(rasmem_st.scan_bytes_per_hour >> 30), (uintmax_t)(rasmem_segs_pages() * 60 / MAX(rasmem_pages_per_hour(), 1)), rasmem_march_every, rasmem_hold_ms, rasmem_hold_every);
				RAS_LOG("scan order %s, %d%% extra for retrying blocks that were in use, partly used superpage reservations broken %s\n", rasmem_scan_order ? "spread over all memory" : "by address", MAX(rasmem_retry_pct, 0), rasmem_break_reserv >= 2 ? "always" : rasmem_break_reserv == 1 ? "after a pass" : "never");
			}
			rasmem_neighbor_scan();
			if (rasmem_want_scan || (rasmem_enable && rasmem_interval > 0 && sbinuptime() >= next_sbt))
			{
				rasmem_want_scan = 0;
				next_sbt = sbinuptime() + (sbintime_t)rasmem_interval_ms() * SBT_1MS;
				rasmem_periodic_scan();
			}
			if (rasmem_retest_interval > 0 && now >= next_retest)
			{
				rasmem_retest_all();
				next_retest = now + rasmem_retest_interval;
			}
			if (rasmem_ro_interval > 0 && now >= next_ro)
			{
				rasmem_ro_verify();
				next_ro = now + rasmem_ro_interval;
			}
		}

		if (now >= next_eval)
		{
			/* The trend window slides. */
			rasmem_policy_check();
			next_eval = now + 60;
		}
		rasmem_policy_tick(now);

		/* Persist: immediately after new errors, else periodically. */
		if (rasmem_want_save || (rasmem_dirty && rootvnode != NULL && ((rasmem_urgent_save && now >= next_try) || now >= next_save)))
		{
			rasmem_want_save = 0;
			error = rasmem_save("periodic");
			next_save = now + MAX(rasmem_save_interval, 10);
			/* Root may still be read-only during boot. */
			next_try = error != 0 ? now + 30 : now;
		}

		/* Sleep until the next periodic run is due (at most 1 s). */
		slp = hz;
		if (started && rasmem_enable && rasmem_interval > 0)
		{
			rem = next_sbt - sbinuptime();
			slp = rem <= 0 ? 1 : (int)MIN(rem / tick_sbt + 1, hz);
		}
		/* Pending scan work only counts once periodic work started. */
		mtx_lock(&rasmem_mtx);
		if (!rasmem_stop && !rasmem_want_save && !rasmem_want_inject && !rasmem_want_inject_corrupt && !rasmem_want_forget && !(started && (rasmem_want_scan || rasmem_nbq_n > 0)))
		{
			mtx_sleep(&rasmem_main_chan, &rasmem_mtx, 0, "rasmem", slp);
		}
		mtx_unlock(&rasmem_mtx);
	}

	/* Unloading: wait for boot workers, release pages, final save. */
	rasmem_boot_abort = 1;
	mtx_lock(&rasmem_mtx);
	wakeup(&rasmem_bar_gen);
	while (rasmem_boot_running > 0)
	{
		mtx_sleep(&rasmem_boot_running, &rasmem_mtx, 0, "rasmexit", hz / 10);
	}
	mtx_unlock(&rasmem_mtx);
	rasmem_boot_finish();
	rasmem_transfer_held();
	if (rasmem_save("unload") != 0)
	{
		RAS_LOG("could not save %s at unload\n", rasmem_db_path);
	}
	rasmem_win_fini(&rasmem_win);

	mtx_lock(&rasmem_mtx);
	rasmem_main_running = 0;
	rasmem_st.phase = RASMEM_PHASE_STOPPED;
	wakeup(&rasmem_main_running);
	mtx_unlock(&rasmem_mtx);
	kthread_exit();
}

/* Ask the rasmem process to save and wait for the result. */
static int rasmem_request_save(int timo)
{
	u_int gen;
	int error;

	mtx_lock(&rasmem_mtx);
	if (!rasmem_main_running)
	{
		mtx_unlock(&rasmem_mtx);
		return (ESRCH);
	}
	gen = rasmem_save_gen;
	rasmem_want_save = 1;
	wakeup(&rasmem_main_chan);
	error = 0;
	while (rasmem_save_gen == gen && error == 0)
	{
		error = mtx_sleep(&rasmem_save_gen, &rasmem_mtx, 0, "rasmsav", timo);
	}
	if (error == 0)
	{
		error = rasmem_st.last_save_error;
	}
	mtx_unlock(&rasmem_mtx);
	return (error);
}

/* ------------------------------------------------------------------------ */
/* sysctl handlers                                                          */
/* ------------------------------------------------------------------------ */

static int sysctl_rasmem_regions(SYSCTL_HANDLER_ARGS)
{
	struct rasmem_region *buf;
	u_int i, n, cap;
	int error;

	mtx_lock(&rasmem_mtx);
	n = rasmem_inited ? rasmem_nrec : 0;
	mtx_unlock(&rasmem_mtx);
	cap = n + 16;
	if (req->oldptr == NULL)
	{
		return (SYSCTL_OUT(req, NULL, cap * sizeof(*buf)));
	}
	buf = malloc(cap * sizeof(*buf), M_RASMEM, M_WAITOK | M_ZERO);
	mtx_lock(&rasmem_mtx);
	n = rasmem_inited ? MIN(rasmem_nrec, cap) : 0;
	for (i = 0; i < n; i++)
	{
		buf[i] = rasmem_recs[i].r;
	}
	mtx_unlock(&rasmem_mtx);
	error = SYSCTL_OUT(req, buf, n * sizeof(*buf));
	free(buf, M_RASMEM);
	return (error);
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, regions, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_rasmem_regions, "S,rasmem_region", "Bad page records: struct rasmem_region[]");

static int sysctl_rasmem_stats(SYSCTL_HANDLER_ARGS)
{
	struct rasmem_stats s;

	mtx_lock(&rasmem_mtx);
	s = rasmem_st;
	mtx_unlock(&rasmem_mtx);
	s.alloc_fails = rasmem_alloc_failures();
	return (SYSCTL_OUT(req, &s, sizeof(s)));
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, stats, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_rasmem_stats, "S,rasmem_stats", "Statistics: struct rasmem_stats");

static int sysctl_rasmem_dimms(SYSCTL_HANDLER_ARGS)
{
	struct rasmem_dimm_info *d;
	const struct rasmem_region *r;
	uint32_t mask;
	u_int i;
	int n, k, error;

	d = malloc(32 * sizeof(*d), M_RASMEM, M_WAITOK | M_ZERO);
	mtx_lock(&rasmem_mtx);
	n = rasmem_inited ? MIN(rasmem_dimm_count(), 32) : 0;
	for (k = 0; k < n; k++)
	{
		rasmem_dimm_get(k, &d[k]);
	}
	for (i = 0; n > 0 && i < rasmem_nrec; i++)
	{
		r = &rasmem_recs[i].r;
		if (!rec_active(r) || (mask = r->dimm_mask) == 0)
		{
			continue;
		}
		if (powerof2(mask) && ffs(mask) - 1 < n)
		{
			d[ffs(mask) - 1].bad_pages++;
		}
		for (k = 0; k < n && k < 32; k++)
		{
			if (mask & (1u << k))
			{
				d[k].shared_bad_pages++;
			}
		}
	}
	mtx_unlock(&rasmem_mtx);
	error = SYSCTL_OUT(req, d, n * sizeof(*d));
	free(d, M_RASMEM);
	return (error);
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, dimm_info, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_rasmem_dimms, "S,rasmem_dimm_info", "Memory modules: struct rasmem_dimm_info[]");

static int sysctl_rasmem_map(SYSCTL_HANDLER_ARGS)
{
	struct rasmem_map_header *h;
	struct rasmem_map_seg *sg;
	uint64_t c, ncells;
	uint8_t *share;
	size_t len;
	char *buf;
	int i, nsegs, error;

	mtx_lock(&rasmem_mtx);
	ncells = rasmem_map != NULL ? rasmem_map_cells : 0;
	nsegs = rasmem_inited ? rasmem_segs_count() : 0;
	mtx_unlock(&rasmem_mtx);
	len = sizeof(*h) + nsegs * sizeof(*sg) + ncells * (sizeof(*rasmem_map) + 2);
	if (req->oldptr == NULL)
	{
		return (SYSCTL_OUT(req, NULL, len));
	}
	buf = malloc(len, M_RASMEM, M_WAITOK | M_ZERO);
	h = (struct rasmem_map_header *)buf;
	sg = (struct rasmem_map_seg *)(h + 1);
	mtx_lock(&rasmem_mtx);
	if (!rasmem_inited || rasmem_map == NULL || rasmem_map_cells != ncells || rasmem_segs_count() != nsegs)
	{
		mtx_unlock(&rasmem_mtx);
		free(buf, M_RASMEM);
		return (rasmem_inited ? EAGAIN : ENOENT);
	}
	h->version = RASMEM_MAP_VERSION;
	h->cell_pages = 1u << rasmem_map_shift;
	h->nsegs = nsegs;
	h->page_size = PAGE_SIZE;
	h->ncells = ncells;
	h->total_pages = rasmem_segs_pages();
	h->cursor = rasmem_cursor;
	h->passes = rasmem_st.periodic_sweeps;
	h->pass_done = rasmem_pass_done;
	h->order = rasmem_pass_order;
	for (i = 0; i < nsegs; i++)
	{
		rasmem_seg_get(i, &sg[i]);
	}
	memcpy(sg + nsegs, rasmem_map, ncells * sizeof(*rasmem_map));
	share = (uint8_t *)(sg + nsegs) + ncells * sizeof(*rasmem_map);
	for (c = 0; c < ncells; c++)
	{
		share[c] = rasmem_map_share(c);
	}
	memcpy(share + ncells, rasmem_map_pshare, ncells);
	mtx_unlock(&rasmem_mtx);
	error = SYSCTL_OUT(req, buf, len);
	free(buf, M_RASMEM);
	return (error);
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, map, CTLTYPE_OPAQUE | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0, sysctl_rasmem_map, "S,rasmem_map", "Coverage map: struct rasmem_map_header, segments, cells");

enum { ACT_SAVE, ACT_SCAN, ACT_REBASELINE, ACT_RESET, ACT_INJECT, ACT_INJECT_CORRUPT };

static int sysctl_rasmem_action(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL || val <= 0)
	{
		return (error);
	}
	if (!rasmem_inited)
	{
		return (ENXIO);
	}
	switch (arg2)
	{
	case ACT_SAVE:
		return (rasmem_request_save(30 * hz));
	case ACT_SCAN:
		rasmem_want_scan = 1;
		break;
	case ACT_REBASELINE:
		rasmem_want_rebaseline = 1;
		break;
	case ACT_RESET:
		mtx_lock(&rasmem_mtx);
		if (!rasmem_inited)
		{
			mtx_unlock(&rasmem_mtx);
			return (ENXIO);
		}
		rasmem_st.errors_boot = 0;
		rasmem_st.corrupt_boot = 0;
		rasmem_st.reboot_required = 0;
		rasmem_health_eval();
		mtx_unlock(&rasmem_mtx);
		RAS_LOG("boot error counters reset by administrator\n");
		return (0);
	case ACT_INJECT:
	case ACT_INJECT_CORRUPT:
		if (!rasmem_allow_inject)
		{
			return (EPERM);
		}
		atomic_add_int(arg2 == ACT_INJECT ? &rasmem_want_inject : &rasmem_want_inject_corrupt, MIN(val, 64));
		break;
	default:
		return (EINVAL);
	}
	rasmem_wakeup_main();
	return (0);
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, save, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_SAVE, sysctl_rasmem_action, "I", "Write 1: save the database now");
SYSCTL_PROC(_hw_rasmem, OID_AUTO, scan_now, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_SCAN, sysctl_rasmem_action, "I", "Write 1: run a periodic scan now");
SYSCTL_PROC(_hw_rasmem, OID_AUTO, ro_rebaseline, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_REBASELINE, sysctl_rasmem_action, "I", "Write 1: recompute read-only checksums");
SYSCTL_PROC(_hw_rasmem, OID_AUTO, reset, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_RESET, sysctl_rasmem_action, "I", "Write 1: clear this boot's error counters and reboot-required state");
SYSCTL_PROC(_hw_rasmem, OID_AUTO, inject, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_INJECT, sysctl_rasmem_action, "I", "Write N: fake N bad cells in free memory (needs allow_inject)");
SYSCTL_PROC(_hw_rasmem, OID_AUTO, inject_corrupt, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, ACT_INJECT_CORRUPT, sysctl_rasmem_action, "I", "Write N: fake N live-data corruption events (needs allow_inject)");

static int sysctl_rasmem_forget(SYSCTL_HANDLER_ARGS)
{
	uint64_t pa;
	int error;

	pa = 0;
	error = sysctl_handle_64(oidp, &pa, 0, req);
	if (error != 0 || req->newptr == NULL)
	{
		return (error);
	}
	if (!rasmem_inited || !rasmem_main_running)
	{
		return (ENXIO);
	}
	if (rasmem_want_forget)
	{
		return (EBUSY);
	}
	rasmem_forget_pa = pa;
	rasmem_want_forget = 1;
	rasmem_wakeup_main();
	return (0);
}
SYSCTL_PROC(_hw_rasmem, OID_AUTO, forget, CTLTYPE_U64 | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0, sysctl_rasmem_forget, "QU", "Write a physical address: drop its record from the database");

/* Plain numeric views of the most useful counters. */
SYSCTL_NODE(_hw_rasmem, OID_AUTO, stat, CTLFLAG_RD | CTLFLAG_MPSAFE, 0, "Counters");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, health, CTLFLAG_RD, &rasmem_st.health, 0, "0 ok, 1 degraded, 2 reboot, 3 replace memory");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, replace_reasons, CTLFLAG_RD, &rasmem_st.replace_reasons, 0, "RASMEM_RR_* bits");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, corrupt_boot, CTLFLAG_RD, &rasmem_st.corrupt_boot, 0, "Live-data corruption events this boot");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, errors_boot, CTLFLAG_RD, &rasmem_st.errors_boot, 0, "All new error events this boot");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, active_pages, CTLFLAG_RD, &rasmem_st.active_pages, 0, "Verified non-transient bad pages");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, bad_pages, CTLFLAG_RD, &rasmem_st.bad_pages, 0, "Bad page records");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, bad_pages_inuse, CTLFLAG_RD, &rasmem_st.bad_pages_inuse, 0, "Known bad pages not quarantined");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, ro_mismatch, CTLFLAG_RD, &rasmem_st.ro_mismatch, 0, "Read-only checksum mismatches");
SYSCTL_U32(_hw_rasmem_stat, OID_AUTO, reboot_required, CTLFLAG_RD, &rasmem_st.reboot_required, 0, "Corruption threshold reached");
SYSCTL_U64(_hw_rasmem_stat, OID_AUTO, pages_tested, CTLFLAG_RD, &rasmem_st.pages_tested, 0, "Page tests, all phases");
SYSCTL_U64(_hw_rasmem_stat, OID_AUTO, bytes_tested, CTLFLAG_RD, &rasmem_st.bytes_tested, 0, "Bytes verified, all pattern passes");
SYSCTL_U64(_hw_rasmem_stat, OID_AUTO, full_passes, CTLFLAG_RD, &rasmem_st.periodic_sweeps, 0, "Complete periodic passes over all RAM");
SYSCTL_U64(_hw_rasmem_stat, OID_AUTO, last_pass_tested, CTLFLAG_RD, &rasmem_st.last_sweep_tested, 0, "Pages tested in the last full pass");
SYSCTL_U64(_hw_rasmem_stat, OID_AUTO, scan_bytes_per_hour, CTLFLAG_RD, &rasmem_st.scan_bytes_per_hour, 0, "Effective periodic scan rate");

/* ------------------------------------------------------------------------ */
/* Module glue                                                              */
/* ------------------------------------------------------------------------ */

static void rasmem_shutdown(void *arg __unused, int howto __unused)
{

	if (KERNEL_PANICKED() || !rasmem_inited || !rasmem_dirty)
	{
		return;
	}
	if (rasmem_request_save(10 * hz) != 0)
	{
		RAS_LOG("could not save %s at shutdown\n", rasmem_db_path);
	}
}

static void rasmem_phase3_hooks(void *dummy __unused)
{

	if (rasmem_inited)
	{
		rasmem_shutdown_tag = EVENTHANDLER_REGISTER(shutdown_pre_sync, rasmem_shutdown, NULL, SHUTDOWN_PRI_FIRST);
	}
}
SYSINIT(rasmem_hooks, SI_SUB_KTHREAD_INIT, SI_ORDER_SECOND, rasmem_phase3_hooks, NULL);

static int rasmem_unload(void)
{
	struct rasmem_rec *recs;
	uint16_t *map, *cnt;
	uint8_t *pshare;

	if (!rasmem_inited)
	{
		return (0);
	}
	if (rasmem_shutdown_tag != NULL)
	{
		EVENTHANDLER_DEREGISTER(shutdown_pre_sync, rasmem_shutdown_tag);
		rasmem_shutdown_tag = NULL;
	}

	/* The main thread stops the workers, moves pages, saves, exits. */
	mtx_lock(&rasmem_mtx);
	rasmem_stop = 1;
	rasmem_boot_abort = 1;
	wakeup(&rasmem_main_chan);
	wakeup(&rasmem_bar_gen);
	wakeup(&rasmem_hold_chan);
	while (rasmem_main_running || rasmem_boot_running > 0)
	{
		mtx_sleep(&rasmem_main_running, &rasmem_mtx, 0, "rasmunl", hz / 10);
	}
	rasmem_inited = false;
	mtx_unlock(&rasmem_mtx);
	/* Let exiting threads leave the module text. */
	pause("rasmunl", hz / 5);

	if (!rasmem_main_started)
	{
		/* No main thread ever ran: do its exit work here. */
		rasmem_boot_finish();
		rasmem_transfer_held();
		rasmem_save("unload");
	}

	/* Sysctl handlers may still run; they check rasmem_inited locked. */
	mtx_lock(&rasmem_mtx);
	recs = rasmem_recs;
	rasmem_recs = NULL;
	rasmem_nrec = 0;
	rasmem_rec_cap = 0;
	rasmem_smbios_fini();		/* free() does not sleep */
	map = rasmem_map;
	rasmem_map = NULL;
	cnt = rasmem_map_cnt;
	rasmem_map_cnt = NULL;
	pshare = rasmem_map_pshare;
	rasmem_map_pshare = NULL;
	mtx_unlock(&rasmem_mtx);
	free(map, M_RASMEM);
	free(cnt, M_RASMEM);
	free(pshare, M_RASMEM);
	free(recs, M_RASMEM);
	free(rasmem_ro_crc, M_RASMEM);
	rasmem_ro_crc = NULL;
	rasmem_segs_fini();
	if (rasmem_nuntracked > 0)
	{
		RAS_LOG("unloaded; %u bad page(s) without a record stay allocated\n", rasmem_nuntracked);
	}
	else
	{
		RAS_LOG("unloaded\n");
	}
	return (0);
}

static int rasmem_modevent(module_t mod __unused, int type, void *data __unused)
{

	switch (type)
	{
	case MOD_LOAD:
		return (0);	/* work is done by the SYSINITs */
	case MOD_UNLOAD:
		return (rasmem_unload());
	case MOD_SHUTDOWN:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t rasmem_mod = {
	"rasmem",
	rasmem_modevent,
	NULL
};
DECLARE_MODULE(rasmem, rasmem_mod, SI_SUB_KLD, SI_ORDER_ANY);
MODULE_VERSION(rasmem, 1);
