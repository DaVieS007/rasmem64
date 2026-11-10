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
 * Shared kernel/userland ABI: the binary layout of the hw.rasmem.regions,
 * hw.rasmem.stats and hw.rasmem.dimm_info sysctls and of the persistent
 * database file.  All structures are fixed-size and naturally aligned; do not
 * reorder fields without bumping RASMEM_ABI_VERSION.
 */

#ifndef _DEV_RASMEM_RASMEM_H_
#define	_DEV_RASMEM_RASMEM_H_

#include <sys/types.h>

/* Release of the kernel module and rasmemstat (beta test suite). */
#define	RASMEM_VERSION		"0.1.0"
#define	RASMEM_STAGE		"beta"

#define	RASMEM_ABI_VERSION	3	/* sysctl structures */
#define	RASMEM_DB_VERSION	2	/* database file format */

/* Test pattern bits (hw.rasmem.*_patterns). */
#define	RASMEM_PAT_ZERO		0x01	/* all zeroes                       */
#define	RASMEM_PAT_ONES		0x02	/* all ones                         */
#define	RASMEM_PAT_CHECKER	0x04	/* 0x55.., then 0xAA..              */
#define	RASMEM_PAT_ADDR		0x08	/* address-in-address, then inverse */
#define	RASMEM_PAT_WALK1	0x10	/* walking one, 64 passes           */
#define	RASMEM_PAT_WALK0	0x20	/* walking zero, 64 passes          */
#define	RASMEM_PAT_RANDOM	0x40	/* pseudo-random, new seed each run */
#define	RASMEM_PAT_MARCH	0x80	/* March C-, ascending + descending */
#define	RASMEM_PAT_ALL		0xff
#define	RASMEM_PAT_NBITS	8

/* struct rasmem_region.class: what kind of fault this looks like. */
#define	RASMEM_CLASS_NEW		0 /* failed, not retested enough yet  */
#define	RASMEM_CLASS_TRANSIENT		1 /* never failed again: random flip  */
#define	RASMEM_CLASS_INTERMITTENT	2 /* fails some of the time           */
#define	RASMEM_CLASS_HARD		3 /* fails (almost) always: bad cell  */
#define	RASMEM_CLASS_RO_CORRUPT		4 /* kernel read-only page checksum   */

/* struct rasmem_region.state: who owns the page right now. */
#define	RASMEM_ST_HELD		0 /* allocated and held by rasmem             */
#define	RASMEM_ST_BLACKLISTED	1 /* in vm.page_blacklist (removed at boot)   */
#define	RASMEM_ST_INUSE		2 /* known bad, but owned by someone else     */
#define	RASMEM_ST_RELEASED	3 /* transient: given back to the VM system   */
#define	RASMEM_ST_KERNEL	4 /* kernel image page, cannot be quarantined */

/* struct rasmem_region.source: how the page was first found bad. */
#define	RASMEM_SRC_DB		0 /* loaded from the persistent database    */
#define	RASMEM_SRC_EARLY	1 /* phase 1: early boot test               */
#define	RASMEM_SRC_BOOT		2 /* phase 2: per-chunk SMP test            */
#define	RASMEM_SRC_PERIODIC	3 /* phase 3: periodic scan of free memory  */
#define	RASMEM_SRC_RO		4 /* read-only checksum verification        */
#define	RASMEM_SRC_BLACKLIST	5 /* found in vm.blacklist / ram_blacklist  */
#define	RASMEM_SRC_INJECT	6 /* synthetic, via hw.rasmem.inject        */
#define	RASMEM_SRC_RECLAIM	7 /* held live data (old records, inject) */
#define	RASMEM_SRC_NEIGHBOR	8 /* neighbourhood retest of a bad page     */
#define	RASMEM_SRC_GLOBAL	9 /* phase 2: global address-line test      */

/* struct rasmem_region.flags */
#define	RASMEM_RF_UNVERIFIED	0x01 /* hardware changed; being re-verified  */
#define	RASMEM_RF_CORRUPTION	0x02 /* failure hit live data (counted)      */

/*
 * One bad page.  Exported as an array through hw.rasmem.regions and stored
 * as-is in the database file.  Times are UTC seconds (time_t).
 */
struct rasmem_region
{
	uint64_t	start_addr;	/* physical address, inclusive        */
	uint64_t	end_addr;	/* physical address, exclusive        */
	uint32_t	errors;		/* failed tests: detections + retests */
	uint32_t	retests;	/* retests performed                  */
	uint32_t	retest_fails;	/* retests that failed                */
	uint32_t	consecutive_pass; /* retests passed since last fail  */
	int64_t		first_error_ts;
	int64_t		last_error_ts;
	int64_t		last_test_ts;
	uint64_t	bad_bits;	/* OR of all XOR masks (flipped bits) */
	uint64_t	last_xor;	/* XOR mask of the last failure       */
	uint32_t	bad_offset;	/* offset in page of last bad word    */
	uint8_t		class;		/* RASMEM_CLASS_*                     */
	uint8_t		state;		/* RASMEM_ST_*                        */
	uint8_t		source;		/* RASMEM_SRC_*                       */
	uint8_t		pattern;	/* pattern bit index of last failure  */
	uint32_t	dimm_mask;	/* DIMMs (dimm_info index) that may   */
					/* contain the page; 0 = unknown      */
	uint32_t	flags;		/* RASMEM_RF_*                        */
	uint64_t	reserved;
};

/* Overall health (struct rasmem_stats.health), worst condition wins. */
#define	RASMEM_HEALTH_OK	0 /* no bad memory known                      */
#define	RASMEM_HEALTH_DEGRADED	1 /* bad cells known and isolated (aging)     */
#define	RASMEM_HEALTH_REBOOT	2 /* live data was hit this boot: reboot      */
#define	RASMEM_HEALTH_REPLACE	3 /* memory is failing: replace the DIMM(s)   */

/* struct rasmem_stats.replace_reasons */
#define	RASMEM_RR_PAGES		0x01 /* too many distinct bad pages        */
#define	RASMEM_RR_TREND		0x02 /* too many new bad pages recently    */
#define	RASMEM_RR_LANE		0x04 /* same data bit fails on many pages  */
#define	RASMEM_RR_DIMM		0x08 /* too many bad pages on one DIMM     */

/* Current activity (struct rasmem_stats.phase). */
#define	RASMEM_PHASE_IDLE	0
#define	RASMEM_PHASE_EARLY	1
#define	RASMEM_PHASE_BOOT	2
#define	RASMEM_PHASE_PERIODIC	3
#define	RASMEM_PHASE_RETEST	4
#define	RASMEM_PHASE_RO		5
#define	RASMEM_PHASE_SAVE	6
#define	RASMEM_PHASE_STOPPED	7
#define	RASMEM_PHASE_GLOBAL	8
#define	RASMEM_PHASE_NEIGHBOR	9

/* Outcome of the phase 2 boot test (struct rasmem_stats.boot_status). */
#define	RASMEM_BOOT_UNKNOWN	0 /* not reported (older module)              */
#define	RASMEM_BOOT_OFF		1 /* disabled, or module loaded at runtime    */
#define	RASMEM_BOOT_RUNNING	2
#define	RASMEM_BOOT_COMPLETE	3
#define	RASMEM_BOOT_SKIPPED	4 /* (unused, reserved)                       */
#define	RASMEM_BOOT_ABORTED	5 /* key pressed while the test was running   */
#define	RASMEM_BOOT_INTERRUPTED	6 /* stopped by module unload / shutdown      */

/* Global counters and state, exported through hw.rasmem.stats. */
struct rasmem_stats
{
	uint32_t	abi_version;
	uint32_t	phase;		/* RASMEM_PHASE_*                     */
	uint64_t	phys_pages;	/* pages managed by the VM system     */
	uint64_t	pages_tested;	/* page tests, all phases             */
	uint64_t	bytes_tested;	/* bytes verified (all pattern passes) */
	uint64_t	pages_skipped;	/* wanted, but not obtainable         */
	uint64_t	early_pages_tested;
	uint64_t	boot_pages_tested;
	uint64_t	boot_pages_skipped;
	uint64_t	boot_chunks_total;
	uint64_t	boot_chunks_done;
	uint64_t	boot_test_msec;
	uint64_t	periodic_runs;
	uint64_t	periodic_sweeps; /* full passes over all memory       */
	uint64_t	periodic_cursor; /* physical address of next window   */
	uint64_t	retests;
	uint64_t	ro_pages;	/* kernel read-only pages checksummed */
	uint64_t	ro_checks;	/* verification runs                  */
	uint64_t	ro_skipped;	/* runs skipped (DTrace/kdb active)   */
	uint32_t	ro_mismatch;	/* checksum mismatches found          */
	uint32_t	bad_pages;	/* number of records                  */
	uint32_t	bad_pages_held;	/* HELD + BLACKLISTED                 */
	uint32_t	bad_pages_inuse; /* INUSE: known bad but not isolated */
	uint32_t	errors_boot;	/* all new error events this boot     */
	uint32_t	reboot_required; /* corruption warn threshold reached */
	int64_t		load_ts;	/* module start time                  */
	int64_t		last_error_ts;
	int64_t		last_save_ts;
	int32_t		last_save_error; /* errno of last save, 0 = ok        */
	uint32_t	panic_pending;	/* panic threshold reached            */
	/* --- ABI 2 --- */
	uint32_t	health;		/* RASMEM_HEALTH_*                    */
	uint32_t	replace_reasons; /* RASMEM_RR_*                       */
	uint32_t	corrupt_boot;	/* live-data corruption events (boot) */
	uint32_t	active_pages;	/* verified, non-transient bad pages  */
	uint32_t	trend_pages;	/* new bad pages within trend window  */
	uint32_t	unverified_pages; /* awaiting re-verification         */
	uint32_t	lane_max_pages;	/* pages sharing the worst data bit   */
	int32_t		lane_bit;	/* that bit (0-63), -1 if none        */
	int32_t		worst_dimm;	/* dimm_info index, -1 if unknown     */
	uint32_t	worst_dimm_pages;
	uint32_t	ndimms;		/* DIMMs found in SMBIOS              */
	uint32_t	hw_changed;	/* memory configuration changed       */
	uint64_t	hw_fingerprint;
	uint64_t	scan_pages_per_run; /* effective periodic window      */
	uint64_t	scan_bytes_per_hour; /* effective periodic rate       */
	uint64_t	reserv_breaks;	/* superpage reservations broken      */
	uint64_t	held_pages;	/* free pages the VM held (refused)   */
	uint64_t	unused0;
	uint64_t	neighbor_tests;	/* neighbourhood retests run          */
	uint64_t	global_pages;	/* pages covered by the global test   */
	uint64_t	global_msec;
	uint64_t	sweep_pos;	/* pages into the current sweep      */
	uint64_t	sweep_tested;	/* pages tested in the current sweep */
	uint64_t	last_sweep_tested; /* pages tested in the last sweep */
	uint64_t	last_sweep_secs; /* duration of the last sweep       */
	/* --- ABI 3: where the time goes (microseconds, since load) --- */
	uint64_t	busy_periodic_usec; /* periodic runs, without holds  */
	uint64_t	busy_neighbor_usec; /* neighbourhood retests         */
	uint64_t	busy_retest_usec; /* bad page retests                */
	uint64_t	busy_ro_usec;	/* read-only checksum verification   */
	uint64_t	hold_usec;	/* sleeping in retention holds       */
	uint64_t	last_run_usec;	/* duration of the last periodic run */
	uint64_t	last_run_pages;	/* pages tested by the last run      */
	int64_t		last_run_ts;	/* end of the last periodic run      */
	/* --- ABI 3, carved from reserved space (0 from older modules) --- */
	uint32_t	boot_status;	/* RASMEM_BOOT_*                      */
	uint32_t	boot_pad;
	uint64_t	retry_pages;	/* pages tested by retries of blocks  */
					/* that were in use when scanned      */
	uint64_t	alloc_fails;	/* failed allocator calls (cost)      */
	uint64_t	budget_stops;	/* runs stopped by that budget        */
};

/* One memory module from SMBIOS, exported through hw.rasmem.dimm_info. */
#define	RASMEM_DIMM_RANGES	4
struct rasmem_dimm_info
{
	char		locator[32];	/* e.g. "DIMM_B2"                     */
	char		bank[32];	/* e.g. "P0 CHANNEL B"                */
	char		manufacturer[32];
	char		serial[32];
	char		part[32];
	uint32_t	size_mb;
	uint32_t	bad_pages;	/* active bad pages only on this DIMM */
	uint32_t	shared_bad_pages; /* pages possibly on this DIMM      */
	uint32_t	nranges;	/* SMBIOS type 20 ranges              */
	uint64_t	range_start[RASMEM_DIMM_RANGES];
	uint64_t	range_end[RASMEM_DIMM_RANGES];	/* exclusive */
};

/* Database file (hw.rasmem.db_path): header followed by records. */
#define	RASMEM_DB_MAGIC		"RASMEMDB"
struct rasmem_db_header
{
	char		magic[8];	/* RASMEM_DB_MAGIC, not NUL terminated */
	uint32_t	version;	/* 1 .. RASMEM_DB_VERSION              */
	uint32_t	count;		/* number of records                   */
	uint32_t	rec_size;	/* sizeof(struct rasmem_region)        */
	uint32_t	crc;		/* CRC32C of the records               */
	int64_t		saved_ts;
	uint64_t	hw_fingerprint;	/* v2: memory configuration identity   */
	uint64_t	reserved;
};

/*
 * Coverage map, exported through hw.rasmem.map: a struct rasmem_map_header,
 * nsegs struct rasmem_map_seg, ncells uint16_t cells (flags below), then
 * ncells uint8_t "tested share" of the current pass and ncells uint8_t of
 * the previous pass (0 = nothing tested, 255 = every page tested).  The
 * flags say what happened in a cell; the shares say how much of it: the
 * rest was in use.  Memory is
 * indexed by linear page number (managed RAM only, holes removed); a cell
 * covers cell_pages pages.
 *
 * The scan visits memory in 8 MiB slots, in address order or spread out
 * (hw.rasmem.scan_order), so "where the scan has been in this pass" is the
 * VISITED bit, not a range below the cursor.
 *
 * CUR_* describe the current periodic pass, PREV_* the previous pass (or,
 * before the first pass completes, the boot test).  DONE_* accumulate since
 * load: a test type is done for a cell once one pass applied it to the
 * whole cell (no page skipped) without an error.  A cell is "fully tested"
 * when all DONE_* bits are set.  The current pass is folded into PREV_* and
 * DONE_* when it completes.
 */
#define	RASMEM_MAP_VERSION	4
#define	RASMEM_MAP_TESTED	0x0001 /* pages of the cell were tested      */
#define	RASMEM_MAP_SKIPPED	0x0002 /* pages were in use, not obtainable  */
#define	RASMEM_MAP_HELD		0x0004 /* free, but held by the VM (refused) */
#define	RASMEM_MAP_MARCH	0x0008 /* tested with March C-               */
#define	RASMEM_MAP_HOLD		0x0010 /* tested with a retention hold       */
#define	RASMEM_MAP_FAILED	0x0020 /* a test failed in this cell         */
#define	RASMEM_MAP_VISITED	0x0040 /* the scan has been here this pass   */
#define	RASMEM_MAP_RETRIED	0x0080 /* skipped pages were retried         */
#define	RASMEM_MAP_CUR_MASK	0x00ff
#define	RASMEM_MAP_PREV_TESTED	0x0100
#define	RASMEM_MAP_PREV_SKIPPED	0x0200
#define	RASMEM_MAP_PREV_HELD	0x0400
#define	RASMEM_MAP_DONE_BASIC	0x1000 /* pattern test, whole cell, clean    */
#define	RASMEM_MAP_DONE_MARCH	0x2000 /* March C-, whole cell, clean        */
#define	RASMEM_MAP_DONE_HOLD	0x4000 /* retention test, whole cell, clean  */
#define	RASMEM_MAP_DONE_ALL	0x7000

struct rasmem_map_header
{
	uint32_t	version;	/* RASMEM_MAP_VERSION                 */
	uint32_t	cell_pages;	/* pages per cell (power of two)      */
	uint32_t	nsegs;
	uint32_t	page_size;
	uint64_t	ncells;
	uint64_t	total_pages;	/* linear pages                       */
	uint64_t	cursor;		/* linear page of the next scan       */
	uint64_t	passes;		/* completed periodic passes          */
	uint64_t	pass_done;	/* pages of the current pass done     */
	uint32_t	order;		/* scan order of this pass (0 seq.)   */
	uint32_t	reserved;
};

struct rasmem_map_seg
{
	uint64_t	start;		/* physical, page aligned             */
	uint64_t	end;
	uint64_t	lin_first;	/* linear page number of start        */
	uint32_t	domain;
	uint32_t	reserved;
};

#ifdef __cplusplus
#define	RASMEM_STATIC_ASSERT	static_assert
#else
#define	RASMEM_STATIC_ASSERT	_Static_assert
#endif
RASMEM_STATIC_ASSERT(sizeof(struct rasmem_region) == 96, "rasmem_region ABI");
RASMEM_STATIC_ASSERT(sizeof(struct rasmem_db_header) == 48, "rasmem_db ABI");
RASMEM_STATIC_ASSERT(sizeof(struct rasmem_dimm_info) == 240, "dimm_info ABI");
RASMEM_STATIC_ASSERT(sizeof(struct rasmem_map_header) == 64, "map ABI");
RASMEM_STATIC_ASSERT(sizeof(struct rasmem_map_seg) == 32, "map seg ABI");

#endif /* !_DEV_RASMEM_RASMEM_H_ */
