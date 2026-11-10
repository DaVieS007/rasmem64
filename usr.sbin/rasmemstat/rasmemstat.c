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
 * rasmemstat - real-time view of the rasmem RAS memory tester.
 *
 *   rasmemstat                    live display, 1 s refresh
 *   rasmemstat -1                 one snapshot
 *   rasmemstat -d                 memory modules
 *   rasmemstat -J                 one JSON document
 *   rasmemstat -1 -V map          the coverage map, once
 *   rasmemstat -J -w 10           JSON stream, one compact object per line
 *   rasmemstat -f /boot/rasmem.db offline database dump (text or -J)
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <dev/rasmem/rasmem.h>

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

static const char *class_names[] = {
	"new", "transient", "intermittent", "hard", "ro-corrupt"
};
static const char *state_names[] = {
	"held", "blacklisted", "IN USE", "released", "kernel"
};
static const char *state_keys[] = {
	"held", "blacklisted", "in_use", "released", "kernel"
};
static const char *src_names[] = {
	"database", "early", "boot", "periodic", "ro-check", "blacklist",
	"inject", "live-data", "neighbour", "global"
};
static const char *phase_names[] = {
	"idle", "early test", "boot test", "periodic scan", "retest",
	"read-only verify", "saving", "stopped", "global address test",
	"neighbour retest"
};
static const char *health_keys[] = {
	"ok", "degraded", "reboot", "replace"
};
static const char *health_titles[] = {
	"OK", "DEGRADED", "REBOOT REQUIRED", "REPLACE MEMORY"
};
static const char *health_texts[] = {
	"no bad memory known",
	"bad cells known and isolated (aging)",
	"live data was hit by bad memory this boot",
	"memory is failing"
};
static const char *boot_status_keys[] = {
	"unknown", "off", "running", "complete", "skipped", "aborted",
	"interrupted"
};
static const char *boot_status_texts[] = {
	"unknown",
	"not run (disabled, or module loaded after boot)",
	"running",
	"complete",
	"skipped",
	"ABORTED from the console while running",
	"interrupted (module unloaded)"
};

static const char *boot_status_name(uint32_t st)
{

	return (st < nitems(boot_status_keys) ? boot_status_keys[st] : "unknown");
}

static const char *boot_status_text(uint32_t st)
{

	return (st < nitems(boot_status_texts) ? boot_status_texts[st] : "unknown");
}

static const char *pat_names[RASMEM_PAT_NBITS] = {
	"zero", "ones", "checker", "addr", "walk1", "walk0", "random", "march"
};
static const struct
{
	uint32_t	bit;
	const char	*key;
	const char	*text;
} reason_tab[] = {
	{ RASMEM_RR_PAGES, "too_many_pages", "too many bad pages" },
	{ RASMEM_RR_TREND, "new_pages_trend", "new bad pages keep appearing" },
	{ RASMEM_RR_LANE, "data_bit", "same data bit fails on many pages" },
	{ RASMEM_RR_DIMM, "one_module", "bad pages concentrated on one module" },
};

#define	NAME(tab, i)	((size_t)(i) < nitems(tab) ? (tab)[(i)] : "?")

/* ------------------------------------------------------------------------ */
/* Options and state                                                        */
/* ------------------------------------------------------------------------ */

static volatile sig_atomic_t quit;
static FILE *out;			/* stdout, or the frame being built */
#define	oputc(c)	fputc((c), out)
static bool opt_merge;
static char opt_sort = 'e';		/* e: errors, a: address, t: time */
static double opt_avg = 60.0;		/* rate averaging window (s) */
static bool use_color;
static bool tui;			/* interactive full-screen mode */
static bool opt_legend = true;
static int pagesize;

static struct rasmem_dimm_info *dimms;
static size_t ndimms;

/* One display row: a page, or a merged run of adjacent pages. */
struct row
{
	struct rasmem_region	r;
	uint64_t		npages;
};

static void onsig(int sig __unused)
{

	quit = 1;
}

static void usage(void)
{

	fprintf(stderr, "rasmemstat %s (%s) - RAS memory test suite statistics\n\n"
	    "usage: rasmemstat [-m] [-V view] [-a secs] [-s e|a|t] [-w secs] [--no-color]\n"
	    "       rasmemstat -1 [-dFm] [-V view] [-n rows] [-s e|a|t]\n"
	    "       rasmemstat -J [-w secs]\n"
	    "       rasmemstat -f dbfile [-Jm] [-s e|a|t]\n"
	    "\n"
	    "  On a terminal rasmemstat is interactive: keys 1-5 switch views\n"
	    "  (overview, map, bad pages, modules, details), ? shows all keys.\n"
	    "\n"
	    "  -1, --once          print once and exit (overview + bad pages)\n"
	    "  -V, --view VIEW     overview, map, pages, modules, details or all\n"
	    "  -F, --full          everything (same as -V all)\n"
	    "  -d, --modules       memory modules (same as -V modules)\n"
	    "  -J, --json          JSON output (one document; with -w a stream\n"
	    "                      of one compact object per line)\n"
	    "  -f, --file FILE     read a database file instead of the kernel\n"
	    "  -m, --merge         merge adjacent bad pages into ranges\n"
	    "  -n, --rows N        show at most N bad pages\n"
	    "  -s, --sort e|a|t    sort by errors, address or last error\n"
	    "  -w, --wait SECS     refresh interval (default 1)\n"
	    "  -a, --avg SECS      rate averaging window (default 60)\n"
	    "  -v, --version       print the versions and exit\n"
	    "      --no-color      no ANSI colors (also: NO_COLOR set)\n", RASMEM_VERSION, RASMEM_STAGE);
	exit(1);
}

/* ------------------------------------------------------------------------ */
/* Colors                                                                   */
/* ------------------------------------------------------------------------ */

#define	C_RESET		"\033[0m"
#define	C_BOLD		"\033[1m"
#define	C_DIM		"\033[2m"
#define	C_RED		"\033[1;31m"
#define	C_GREEN		"\033[1;32m"
#define	C_YELLOW	"\033[1;33m"
#define	C_WARN		"\033[33m"
#define	C_INV		"\033[1;7m"
/* Map colours: the 16 the FreeBSD console (vt) can show, no "dim". */
#define	C_FULL		"\033[1;32m"	/* fully tested: bright green */
#define	C_FULL_OLD	"\033[32m"	/* same, not reached this pass: green */
#define	C_PASS		"\033[1;37m"	/* tested this pass: white */
/* In use: orange (256-colour; the FreeBSD console shows its nearest). */
/* Partly tested (the rest was in use): darker = less of it tested. */
#define	C_MOST		"\033[38;5;222m"	/* 50-90%: pale orange */
#define	C_PART		"\033[38;5;208m"	/* 10-50%: orange */
#define	C_BUSY		"\033[38;5;130m"	/* under 10%: dark orange */
#define	C_PREV		"\033[1;30m"	/* tested last pass: grey */
#define	C_HELD		"\033[38;5;135m"	/* free, held by the VM: purple */

static const char *col(const char *c)
{

	return (use_color ? c : "");
}

static const char *health_color(uint32_t h)
{

	switch (h)
	{
	case RASMEM_HEALTH_OK:
		return (col(C_GREEN));
	case RASMEM_HEALTH_DEGRADED:
		return (col(C_YELLOW));
	default:
		return (col(C_RED));
	}
}

/* ------------------------------------------------------------------------ */
/* Data sources                                                             */
/* ------------------------------------------------------------------------ */

static int fetch_stats(struct rasmem_stats *s)
{
	size_t len;

	len = sizeof(*s);
	if (sysctlbyname("hw.rasmem.stats", s, &len, NULL, 0) != 0)
	{
		return (-1);
	}
	if (len < sizeof(*s) || s->abi_version != RASMEM_ABI_VERSION)
	{
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static void *fetch_array(const char *name, size_t elsize, size_t *n)
{
	void *p;
	size_t len;
	int tries;

	*n = 0;
	for (tries = 0; tries < 5; tries++)
	{
		len = 0;
		if (sysctlbyname(name, NULL, &len, NULL, 0) != 0)
		{
			return (NULL);
		}
		p = malloc(len + elsize);
		if (p == NULL)
		{
			err(1, "malloc");
		}
		if (sysctlbyname(name, p, &len, NULL, 0) == 0)
		{
			*n = len / elsize;
			return (p);
		}
		free(p);
		if (errno != ENOMEM)
		{
			return (NULL);
		}
	}
	return (NULL);
}

static void fetch_dimms(void)
{

	free(dimms);
	dimms = fetch_array("hw.rasmem.dimm_info", sizeof(*dimms), &ndimms);
}

/* Release of the loaded kernel module ("?" if it does not say). */
static const char *module_version(void)
{
	static char v[32];
	size_t len;

	len = sizeof(v) - 1;
	if (v[0] == '\0' && sysctlbyname("hw.rasmem.version", v, &len, NULL, 0) != 0)
	{
		strlcpy(v, "?", sizeof(v));
	}
	v[sizeof(v) - 1] = '\0';
	return (v);
}

static bool version_mismatch(void)
{

	return (strcmp(module_version(), RASMEM_VERSION) != 0);
}

static int get_int(const char *name, int def)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
	{
		return (def);
	}
	return (v);
}

/* Software CRC32C, same as the kernel's calculate_crc32c(). */
static uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
	static uint32_t table[256];
	const uint8_t *p;
	uint32_t c;
	int i, j;

	if (table[1] == 0)
	{
		for (i = 0; i < 256; i++)
		{
			c = i;
			for (j = 0; j < 8; j++)
			{
				c = (c & 1) ? (c >> 1) ^ 0x82F63B78 : c >> 1;
			}
			table[i] = c;
		}
	}
	for (p = buf; len > 0; len--, p++)
	{
		crc = table[(crc ^ *p) & 0xff] ^ (crc >> 8);
	}
	return (crc);
}

static struct rasmem_region *read_db(const char *path, size_t *n, struct rasmem_db_header *hdr, bool *crc_ok)
{
	struct rasmem_region *r;
	struct stat st;
	char *buf;
	ssize_t got;
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0)
	{
		err(1, "%s", path);
	}
	if (fstat(fd, &st) != 0)
	{
		err(1, "%s", path);
	}
	if (st.st_size < (off_t)sizeof(*hdr) || st.st_size > 64 << 20)
	{
		errx(1, "%s: bad size", path);
	}
	if ((buf = malloc(st.st_size)) == NULL)
	{
		err(1, "malloc");
	}
	got = read(fd, buf, st.st_size);
	if (got != st.st_size)
	{
		err(1, "%s: short read", path);
	}
	close(fd);

	memcpy(hdr, buf, sizeof(*hdr));
	if (memcmp(hdr->magic, RASMEM_DB_MAGIC, sizeof(hdr->magic)) != 0)
	{
		errx(1, "%s: not a rasmem database", path);
	}
	if (hdr->version < 1 || hdr->version > RASMEM_DB_VERSION || hdr->rec_size != sizeof(struct rasmem_region))
	{
		errx(1, "%s: unsupported version %u (record size %u)", path, hdr->version, hdr->rec_size);
	}
	if (hdr->count > (st.st_size - sizeof(*hdr)) / sizeof(*r))
	{
		errx(1, "%s: truncated", path);
	}
	r = malloc((hdr->count + 1) * sizeof(*r));
	if (r == NULL)
	{
		err(1, "malloc");
	}
	memcpy(r, buf + sizeof(*hdr), hdr->count * sizeof(*r));
	free(buf);
	*crc_ok = crc32c(~0U, r, hdr->count * sizeof(*r)) == hdr->crc;
	*n = hdr->count;
	return (r);
}

/* ------------------------------------------------------------------------ */
/* Rate averaging                                                           */
/* ------------------------------------------------------------------------ */

/*
 * Sliding window of samples.  The kernel tests in bursts (a few
 * milliseconds every hw.rasmem.interval milliseconds), so a rate or an activity
 * snapshot between two refreshes is mostly 0 or "idle"; average the
 * counters over opt_avg seconds instead.
 */
enum { A_PERIODIC, A_NEIGHBOR, A_RETEST, A_RO, A_HOLD, A_N };
static const char *act_names[A_N] = {
	"periodic", "neighbour", "retest", "read-only", "hold"
};

struct sample
{
	double		t;
	uint64_t	bytes;
	uint64_t	usec[A_N];
};

/* What the window (or the time since load) says. */
struct window
{
	bool		ok;		/* enough data */
	double		span;		/* seconds covered */
	double		rate;		/* bytes verified per second */
	double		pct[A_N];	/* share of wall time per activity */
	double		busy_pct;	/* all active work (no holds) */
};

#define	RATE_MAXSAMPLES	4096
static struct sample rate_ring[RATE_MAXSAMPLES];
static size_t rate_head, rate_n;

static void sample_of(const struct rasmem_stats *s, double t, struct sample *x)
{

	x->t = t;
	x->bytes = s->bytes_tested;
	x->usec[A_PERIODIC] = s->busy_periodic_usec;
	x->usec[A_NEIGHBOR] = s->busy_neighbor_usec;
	x->usec[A_RETEST] = s->busy_retest_usec;
	x->usec[A_RO] = s->busy_ro_usec;
	x->usec[A_HOLD] = s->hold_usec;
}

static void rate_add(const struct rasmem_stats *s, double t)
{
	size_t tail;

	/* A counter going backwards means the module was reloaded. */
	if (rate_n > 0 && s->bytes_tested < rate_ring[(rate_head + RATE_MAXSAMPLES - 1) % RATE_MAXSAMPLES].bytes)
	{
		rate_n = 0;
	}
	sample_of(s, t, &rate_ring[rate_head]);
	rate_head = (rate_head + 1) % RATE_MAXSAMPLES;
	if (rate_n < RATE_MAXSAMPLES)
	{
		rate_n++;
	}
	/* Drop samples older than the window, keep at least two. */
	while (rate_n > 2)
	{
		tail = (rate_head + RATE_MAXSAMPLES - rate_n) % RATE_MAXSAMPLES;
		if (t - rate_ring[(tail + 1) % RATE_MAXSAMPLES].t < opt_avg)
		{
			break;
		}
		rate_n--;
	}
}

static void window_between(const struct sample *a, const struct sample *b, struct window *w)
{
	int k;

	memset(w, 0, sizeof(*w));
	w->span = b->t - a->t;
	if (w->span <= 0)
	{
		return;
	}
	w->ok = true;
	w->rate = (b->bytes - a->bytes) / w->span;
	for (k = 0; k < A_N; k++)
	{
		w->pct[k] = (b->usec[k] - a->usec[k]) / (w->span * 1e4);
		if (k != A_HOLD)
		{
			w->busy_pct += w->pct[k];
		}
	}
}

/* Averages over the sliding window. */
static void window_get(struct window *w)
{

	memset(w, 0, sizeof(*w));
	if (rate_n < 2)
	{
		return;
	}
	window_between(&rate_ring[(rate_head + RATE_MAXSAMPLES - rate_n) % RATE_MAXSAMPLES], &rate_ring[(rate_head + RATE_MAXSAMPLES - 1) % RATE_MAXSAMPLES], w);
}

/* Averages since the module was loaded. */
static void window_since_load(const struct rasmem_stats *s, time_t now, struct window *w)
{
	struct sample a, b;

	memset(&a, 0, sizeof(a));
	sample_of(s, (double)now, &b);
	a.t = (double)s->load_ts;
	if (s->load_ts <= 0)
	{
		memset(w, 0, sizeof(*w));
	}
	else
	{
		window_between(&a, &b, w);
	}
}

static double monotime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec + ts.tv_nsec / 1e9);
}

/* ------------------------------------------------------------------------ */
/* Formatting helpers                                                       */
/* ------------------------------------------------------------------------ */

static const char *fmt_bytes(uint64_t b, char *buf, size_t len)
{
	static const char u[] = "BKMGTPE";
	double v;
	int i;

	v = b;
	for (i = 0; v >= 1024 && i < 6; i++)
	{
		v /= 1024;
	}
	if (i == 0)
	{
		snprintf(buf, len, "%ju B", (uintmax_t)b);
	}
	else
	{
		snprintf(buf, len, "%.1f %ciB", v, u[i]);
	}
	return (buf);
}

/* Compact size for the table: 4K, 2M, 1.5G ... */
static const char *fmt_size(uint64_t b, char *buf, size_t len)
{
	static const char u[] = "BKMGTPE";
	int i;

	for (i = 0; b >= 1024 && (b % 1024) == 0 && i < 6; i++)
	{
		b /= 1024;
	}
	snprintf(buf, len, "%ju%c", (uintmax_t)b, i ? u[i] : 'B');
	return (buf);
}

/* 1234567 -> "1,234,567" */
static const char *fmt_count(uint64_t v, char *buf, size_t len)
{
	char tmp[32];
	size_t i, j, n;

	n = snprintf(tmp, sizeof(tmp), "%ju", (uintmax_t)v);
	for (i = j = 0; i < n && j + 2 < len; i++)
	{
		if (i > 0 && (n - i) % 3 == 0)
		{
			buf[j++] = ',';
		}
		buf[j++] = tmp[i];
	}
	buf[j] = '\0';
	return (buf);
}

static const char *fmt_msec(uint64_t ms, char *buf, size_t len)
{

	if (ms < 1000)
	{
		snprintf(buf, len, "%ju ms", (uintmax_t)ms);
	}
	else if (ms < 120000)
	{
		snprintf(buf, len, "%.1f s", ms / 1000.0);
	}
	else
	{
		snprintf(buf, len, "%ju min", (uintmax_t)(ms / 60000));
	}
	return (buf);
}

static const char *fmt_secs(uint64_t sec, char *buf, size_t len)
{

	if (sec < 120)
	{
		snprintf(buf, len, "%ju s", (uintmax_t)sec);
	}
	else if (sec < 7200)
	{
		snprintf(buf, len, "%ju min", (uintmax_t)(sec / 60));
	}
	else
	{
		snprintf(buf, len, "%juh %02jum", (uintmax_t)(sec / 3600), (uintmax_t)(sec / 60 % 60));
	}
	return (buf);
}

static u_int pct(uint64_t part, uint64_t whole)
{

	return (whole ? (u_int)(MIN(part, whole) * 100 / whole) : 0);
}

static const char *fmt_age(int64_t ts, time_t now, char *buf, size_t len)
{
	int64_t d;

	if (ts <= 0)
	{
		snprintf(buf, len, "never");
		return (buf);
	}
	d = now - ts;
	if (d < 0)
	{
		d = 0;
	}
	if (d < 120)
	{
		snprintf(buf, len, "%jds ago", (intmax_t)d);
	}
	else if (d < 7200)
	{
		snprintf(buf, len, "%jdm ago", (intmax_t)(d / 60));
	}
	else if (d < 172800)
	{
		snprintf(buf, len, "%jdh ago", (intmax_t)(d / 3600));
	}
	else
	{
		snprintf(buf, len, "%jdd ago", (intmax_t)(d / 86400));
	}
	return (buf);
}

static const char *fmt_patterns(int mask, char *buf, size_t len)
{
	size_t pos;
	int i;

	buf[0] = '\0';
	for (i = 0, pos = 0; i < RASMEM_PAT_NBITS && pos < len; i++)
	{
		if (mask & (1 << i))
		{
			pos += snprintf(buf + pos, len - pos, "%s%s", pos ? "," : "", pat_names[i]);
		}
	}
	if (pos == 0)
	{
		snprintf(buf, len, "none");
	}
	return (buf);
}

/* Module names for a dimm_mask ("?" if unknown). */
static const char *fmt_dimms(uint32_t mask, char *buf, size_t len)
{
	size_t i, pos;

	if (mask == 0 || ndimms == 0)
	{
		snprintf(buf, len, "?");
		return (buf);
	}
	buf[0] = '\0';
	for (i = pos = 0; i < ndimms && i < 32 && pos < len; i++)
	{
		if (mask & (1u << i))
		{
			pos += snprintf(buf + pos, len - pos, "%s%s", pos ? "|" : "", dimms[i].locator);
		}
	}
	return (buf);
}

/* Section title: "TESTING -----------..." */
static void section(const char *title)
{
	int i;

	fprintf(out, "\n%s%s%s ", col(C_BOLD), title, col(C_RESET));
	for (i = (int)strlen(title) + 1; i < 78; i++)
	{
		fputs(use_color ? "\xe2\x94\x80" : "-", out);
	}
	fprintf(out, "\n");
}

/* "  label         value..." */
static void	kv(const char *label, const char *fmt, ...) __printflike(2, 3);

static void kv(const char *label, const char *fmt, ...)
{
	va_list ap;

	fprintf(out, "  %-14s", label);
	va_start(ap, fmt);
	vfprintf(out, fmt, ap);
	va_end(ap);
	fprintf(out, "\n");
}

/* ------------------------------------------------------------------------ */
/* Rows                                                                     */
/* ------------------------------------------------------------------------ */

static int cmp_rows(const void *a, const void *b)
{
	const struct row *x = a, *y = b;

	switch (opt_sort)
	{
	case 't':
		if (x->r.last_error_ts != y->r.last_error_ts)
		{
			return (x->r.last_error_ts > y->r.last_error_ts ? -1 : 1);
		}
		break;
	case 'e':
		if (x->r.errors != y->r.errors)
		{
			return (x->r.errors > y->r.errors ? -1 : 1);
		}
		break;
	}
	return (x->r.start_addr < y->r.start_addr ? -1 : x->r.start_addr > y->r.start_addr);
}

static int cmp_addr(const void *a, const void *b)
{
	const struct rasmem_region *x = a, *y = b;

	return (x->start_addr < y->start_addr ? -1 : x->start_addr > y->start_addr);
}

/* Build display rows; with -m merge adjacent pages of equal class/state. */
static struct row *make_rows(struct rasmem_region *r, size_t n, size_t *nrows)
{
	struct row *rows, *cur;
	size_t i, k;

	rows = calloc(n + 1, sizeof(*rows));
	if (rows == NULL)
	{
		err(1, "calloc");
	}
	if (n > 0)
	{
		qsort(r, n, sizeof(*r), cmp_addr);
	}
	for (i = k = 0; i < n; i++)
	{
		cur = k > 0 ? &rows[k - 1] : NULL;
		if (opt_merge && cur != NULL && cur->r.end_addr == r[i].start_addr && cur->r.class == r[i].class && cur->r.state == r[i].state)
		{
			cur->r.end_addr = r[i].end_addr;
			cur->r.errors += r[i].errors;
			cur->r.retests += r[i].retests;
			cur->r.retest_fails += r[i].retest_fails;
			cur->r.bad_bits |= r[i].bad_bits;
			cur->r.dimm_mask |= r[i].dimm_mask;
			cur->r.flags |= r[i].flags;
			if (r[i].first_error_ts > 0 && (cur->r.first_error_ts == 0 || r[i].first_error_ts < cur->r.first_error_ts))
			{
				cur->r.first_error_ts = r[i].first_error_ts;
			}
			if (r[i].last_error_ts > cur->r.last_error_ts)
			{
				cur->r.last_error_ts = r[i].last_error_ts;
			}
			cur->npages++;
			continue;
		}
		rows[k].r = r[i];
		rows[k].npages = 1;
		k++;
	}
	if (k > 0)
	{
		qsort(rows, k, sizeof(*rows), cmp_rows);
	}
	*nrows = k;
	return (rows);
}

static const char *class_color(uint8_t c)
{

	switch (c)
	{
	case RASMEM_CLASS_HARD:
	case RASMEM_CLASS_RO_CORRUPT:
		return (col(C_RED));
	case RASMEM_CLASS_INTERMITTENT:
	case RASMEM_CLASS_NEW:
		return (col(C_YELLOW));
	default:
		return (col(C_DIM));
	}
}

/*
 * Explain the CLASS, STATE and FLAG values that appear in the table (only
 * those, to keep it short).
 */
static void legend(const char *key, const char *fmt, ...) __printflike(2, 3);

static void legend(const char *key, const char *fmt, ...)
{
	va_list ap;

	fprintf(out, "%s    %-13s ", col(C_DIM), key);
	va_start(ap, fmt);
	vfprintf(out, fmt, ap);
	va_end(ap);
	fprintf(out, "%s\n", col(C_RESET));
}

static void print_legend(const struct row *rows, size_t n)
{
	char ivl[32];
	u_int classes, states, flags;
	size_t i;
	int every, judge;

	classes = states = flags = 0;
	for (i = 0; i < n; i++)
	{
		classes |= 1u << MIN(rows[i].r.class, 31);
		states |= 1u << MIN(rows[i].r.state, 31);
		flags |= rows[i].r.flags;
	}
	every = get_int("hw.rasmem.retest_interval", 600);
	judge = MAX(get_int("hw.rasmem.classify_retests", 8), 1);
	if (every <= 0)
	{
		snprintf(ivl, sizeof(ivl), "retests are off");
	}
	else if (every % 60 == 0)
	{
		snprintf(ivl, sizeof(ivl), "retested every %d min", every / 60);
	}
	else
	{
		snprintf(ivl, sizeof(ivl), "retested every %d s", every);
	}

	fprintf(out, "\n%s  Legend%s\n", col(C_DIM), col(C_RESET));
	if (classes & (1u << RASMEM_CLASS_NEW))
	{
		legend("new", "failed once, not judged yet: %s, judged after %d retest(s)", ivl, judge);
	}
	if (classes & (1u << RASMEM_CLASS_TRANSIENT))
	{
		legend("transient", "passed all %d+ retests: a random bit flip, the cell is fine (not counted as a fault)", judge);
	}
	if (classes & (1u << RASMEM_CLASS_INTERMITTENT))
	{
		legend("intermittent", "fails some retests: a weak cell (timing, temperature, neighbours)");
	}
	if (classes & (1u << RASMEM_CLASS_HARD))
	{
		legend("hard", "fails (almost) every retest: a broken cell");
	}
	if (classes & (1u << RASMEM_CLASS_RO_CORRUPT))
	{
		legend("ro-corrupt", "a read-only kernel page changed (checksum); not retested");
	}
	if (states & (1u << RASMEM_ST_HELD))
	{
		legend("held", "isolated: rasmem keeps the page, nothing else can use it");
	}
	if (states & (1u << RASMEM_ST_BLACKLISTED))
	{
		legend("blacklisted", "isolated: removed by the kernel at boot (ram_blacklist)");
	}
	if (states & (1u << RASMEM_ST_INUSE))
	{
		legend("IN USE", "not isolated: owned by someone else, cannot be retested until rasmem gets it");
	}
	if (states & (1u << RASMEM_ST_RELEASED))
	{
		legend("released", "given back to the system (transient, or the memory is gone)");
	}
	if (states & (1u << RASMEM_ST_KERNEL))
	{
		legend("kernel", "part of the kernel image, cannot be isolated");
	}
	legend("RETESTS", "failed/total");
	if (flags & RASMEM_RF_CORRUPTION)
	{
		legend("FLAG C", "the error hit live data (counts toward \"reboot required\")");
	}
	if (flags & RASMEM_RF_UNVERIFIED)
	{
		legend("FLAG U", "being re-verified: the memory modules changed since the database was written");
	}
}

static void print_rows(struct row *rows, size_t n, size_t maxrows, time_t now)
{
	char sz[16], last[16], dm[24], fl[4], rt[16];
	const struct rasmem_region *r;
	size_t i;

	if (n == 0)
	{
		fprintf(out, "  none\n");
		return;
	}
	fprintf(out, "%s  %-18s %5s  %-12s %-11s %-10s %6s %9s  %-10s %-9s %-4s  %-18s%s\n", col(C_DIM), "ADDRESS", "SIZE", "CLASS", "STATE", "MODULE", "ERRORS", "RETESTS", "LAST ERROR", "FOUND BY", "FLAG", "FLIPPED BITS", col(C_RESET));
	for (i = 0; i < n && i < maxrows; i++)
	{
		r = &rows[i].r;
		fmt_size(r->end_addr - r->start_addr, sz, sizeof(sz));
		snprintf(rt, sizeof(rt), "%u/%u", r->retest_fails, r->retests);
		snprintf(fl, sizeof(fl), "%s%s", r->flags & RASMEM_RF_CORRUPTION ? "C" : "", r->flags & RASMEM_RF_UNVERIFIED ? "U" : "");
		fprintf(out, "  0x%016jx %5s  %s%-12s%s %s%-11s%s %-10.10s %6u %9s  %-10s %-9s %-4s  0x%016jx\n", (uintmax_t)r->start_addr, sz, class_color(r->class), NAME(class_names, r->class), col(C_RESET), r->state == RASMEM_ST_INUSE ? col(C_YELLOW) : "", NAME(state_names, r->state), r->state == RASMEM_ST_INUSE ? col(C_RESET) : "", fmt_dimms(r->dimm_mask, dm, sizeof(dm)), r->errors, rt, fmt_age(r->last_error_ts, now, last, sizeof(last)), NAME(src_names, r->source), fl, (uintmax_t)r->bad_bits);
	}
	if (i < n)
	{
		fprintf(out, "  ... %zu more (-n N or a taller terminal)\n", n - i);
	}
	if (opt_legend)
	{
		print_legend(rows, MIN(n, maxrows));
	}
}

/* ------------------------------------------------------------------------ */
/* Text output                                                              */
/* ------------------------------------------------------------------------ */

static void print_health(const struct rasmem_stats *s)
{
	char dm[64];
	size_t i;
	bool first;

	fprintf(out, "\n  %s%s%s  %s\n", health_color(s->health), NAME(health_titles, s->health), col(C_RESET), NAME(health_texts, s->health));
	if (s->replace_reasons != 0)
	{
		fprintf(out, "  %-14s", "why");
		first = true;
		for (i = 0; i < nitems(reason_tab); i++)
		{
			if (s->replace_reasons & reason_tab[i].bit)
			{
				fprintf(out, "%s%s", first ? "" : "; ", reason_tab[i].text);
				first = false;
			}
		}
		fprintf(out, "\n");
	}
	if (s->worst_dimm >= 0 && s->worst_dimm_pages > 0)
	{
		kv("suspect", "module %s (%u bad pages)", fmt_dimms(1u << s->worst_dimm, dm, sizeof(dm)), s->worst_dimm_pages);
	}
	if (s->panic_pending)
	{
		kv("PANIC PENDING", "%sthe kernel will panic once the database is saved%s", col(C_RED), col(C_RESET));
	}

	section("EVIDENCE");
	kv("this boot", "%u live-data corruption event(s), %u error event(s)", s->corrupt_boot, s->errors_boot);
	kv("bad pages", "%u verified, %u new in the last %d days, %u awaiting re-verification", s->active_pages, s->trend_pages, get_int("hw.rasmem.trend_days", 7), s->unverified_pages);
	if (s->lane_bit >= 0)
	{
		kv("data bit", "bit %d fails on %u page(s)", s->lane_bit, s->lane_max_pages);
	}
	kv("isolation", "%u recorded, %u isolated, %s%u in use%s", s->bad_pages, s->bad_pages_held, s->bad_pages_inuse ? col(C_YELLOW) : "", s->bad_pages_inuse, s->bad_pages_inuse ? col(C_RESET) : "");
}

static void print_activity(const struct rasmem_stats *s, const struct window *w, const char *what, time_t now)
{
	char b1[32], b2[32], b3[32], parts[160];
	size_t pos;
	int k;

	if (!w->ok)
	{
		kv("activity", "measuring...");
		return;
	}
	pos = 0;
	parts[0] = '\0';
	for (k = 0; k < A_HOLD; k++)
	{
		if (w->pct[k] >= 0.05)
		{
			pos += snprintf(parts + pos, sizeof(parts) - pos, "%s%s %.1f%%", pos ? ", " : "", act_names[k], w->pct[k]);
		}
	}
	kv("activity", "%sbusy %.1f%%%s of the time %s%s%s%s", col(C_BOLD), w->busy_pct, col(C_RESET), what, pos ? " (" : "", parts, pos ? ")" : "");
	kv("", "memory held for retention tests %.1f%% of the time; right now: %s", w->pct[A_HOLD], NAME(phase_names, s->phase));
	if (s->last_run_ts > 0)
	{
		kv("last run", "%s: %s pages (%s) in %s", fmt_age(s->last_run_ts, now, b1, sizeof(b1)), fmt_count(s->last_run_pages, b2, sizeof(b2)), fmt_bytes(s->last_run_pages * (uint64_t)pagesize, b3, sizeof(b3)), s->last_run_usec < 10000 ? (snprintf(parts, sizeof(parts), "%.1f ms", s->last_run_usec / 1000.0), parts) : fmt_msec(s->last_run_usec / 1000, parts, sizeof(parts)));
	}
}

static void print_status(const struct rasmem_stats *s, const struct window *win, time_t now)
{
	struct window load;
	char b1[32], b2[32], b3[32], b4[64], b5[16], host[64], tbuf[32];
	uint64_t chunk_ms;
	int ivl, sweep_h;

	if (!tui)
	{
		gethostname(host, sizeof(host));
		strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
		fprintf(out, "%srasmem %s%s (%s) on %s   %s   module loaded %s\n", col(C_BOLD), RASMEM_VERSION, col(C_RESET), RASMEM_STAGE, host, tbuf, fmt_age(s->load_ts, now, b1, sizeof(b1)));
	}

	print_health(s);

	section("MEMORY");
	kv("size", "%s (%s pages), %u module(s)", fmt_bytes(s->phys_pages * (uint64_t)pagesize, b1, sizeof(b1)), fmt_count(s->phys_pages, b2, sizeof(b2)), s->ndimms);
	kv("fingerprint", "%016jx%s", (uintmax_t)s->hw_fingerprint, s->hw_changed ? "  (CHANGED since the database was written)" : "");

	section("TESTING");
	window_since_load(s, now, &load);
	if (win != NULL)
	{
		snprintf(b3, sizeof(b3), "over the last %.0f s", win->span);
		print_activity(s, win, b3, now);
	}
	else
	{
		print_activity(s, &load, "since load", now);
	}
	if (win == NULL || !win->ok)
	{
		snprintf(b4, sizeof(b4), "%s", win == NULL ? "-" : "measuring...");
	}
	else
	{
		snprintf(b4, sizeof(b4), "%s/s over %.0f s", fmt_bytes((uint64_t)win->rate, b1, sizeof(b1)), win->span);
	}
	kv("rate", "%s   (%s/s since load)", b4, load.ok ? fmt_bytes((uint64_t)load.rate, b2, sizeof(b2)) : "-");
	kv("verified", "%s in %s page tests, %s page(s) not obtainable", fmt_bytes(s->bytes_tested, b1, sizeof(b1)), fmt_count(s->pages_tested, b2, sizeof(b2)), fmt_count(s->pages_skipped, b3, sizeof(b3)));
	ivl = get_int("hw.rasmem.interval", 1000);
	if (ivl % 1000 == 0)
	{
		snprintf(b5, sizeof(b5), "%d s", ivl / 1000);
	}
	else
	{
		snprintf(b5, sizeof(b5), "%d ms", MAX(ivl, 10));
	}
	sweep_h = s->scan_bytes_per_hour ? (int)(s->phys_pages * (uint64_t)pagesize / s->scan_bytes_per_hour) : 0;
	kv("full passes", "%s%ju%s complete over all RAM;  current pass %u%% (%u%% of RAM tested so far)", col(C_BOLD), (uintmax_t)s->periodic_sweeps, col(C_RESET), pct(s->sweep_pos, s->phys_pages), pct(s->sweep_tested, s->phys_pages));
	if (s->periodic_sweeps > 0)
	{
		kv("", "last pass took %s and tested %u%% of RAM (the rest was not obtainable)", fmt_secs(s->last_sweep_secs, b1, sizeof(b1)), pct(s->last_sweep_tested, s->phys_pages));
	}
	kv("periodic", "%s%s/h tested = %s every %s, a pass every ~%d h or less; %s run(s)", get_int("hw.rasmem.enable", 1) ? "" : "DISABLED, ", fmt_bytes(s->scan_bytes_per_hour, b1, sizeof(b1)), fmt_bytes(s->scan_pages_per_run * (uint64_t)pagesize, b2, sizeof(b2)), b5, MAX(sweep_h, 1), fmt_count(s->periodic_runs, b3, sizeof(b3)));
	kv("", "patterns %s", fmt_patterns(get_int("hw.rasmem.periodic_patterns", 0), b4, sizeof(b4)));
	{
		int me = MAX(get_int("hw.rasmem.march_every", 1), 1);
		int he = MAX(get_int("hw.rasmem.hold_every", 1), 1);
		double pass_h = s->scan_bytes_per_hour ? (double)s->phys_pages * pagesize / s->scan_bytes_per_hour : 0;

		kv("", "March C- on 1/%d and %d ms retention hold on 1/%d of RAM per pass, rotating:", me, get_int("hw.rasmem.hold_ms", 0), he);
		kv("", "all RAM gets March C- every %d pass(es) (~%.0f h) and the hold every %d (~%.0f h)", me, me * pass_h, he, he * pass_h);
	}
	kv("", "order: %s", get_int("hw.rasmem.scan_order", 1) ? "spread over all RAM (8 MiB slots, bit-reversed)" : "by address");
	kv("in-use pages", "skipped, never moved; retries: %d%% extra, %s page(s) tested", get_int("hw.rasmem.retry_pct", 0), fmt_count(s->retry_pages, b1, sizeof(b1)));
	kv("held memory", "%s seen free but held by the VM, %s reservation(s) broken (break_reserv=%d)", fmt_bytes(s->held_pages * (uint64_t)pagesize, b1, sizeof(b1)), fmt_count(s->reserv_breaks, b2, sizeof(b2)), get_int("hw.rasmem.break_reserv", 1));
	kv("allocator", "%s failed call(s) since load, %s run(s) hit the limit", fmt_count(s->alloc_fails, b1, sizeof(b1)), fmt_count(s->budget_stops, b2, sizeof(b2)));
	kv("retests", "%s bad-page retest(s), %ju neighbourhood retest(s)", fmt_count(s->retests, b1, sizeof(b1)), (uintmax_t)s->neighbor_tests);
	kv("kernel image", "%ju read-only pages, %ju check(s), %ju skipped, %s%u mismatch(es)%s", (uintmax_t)s->ro_pages, (uintmax_t)s->ro_checks, (uintmax_t)s->ro_skipped, s->ro_mismatch ? col(C_RED) : "", s->ro_mismatch, s->ro_mismatch ? col(C_RESET) : "");

	section("BOOT");
	chunk_ms = s->boot_test_msec > s->global_msec ? s->boot_test_msec - s->global_msec : 0;
	if (s->boot_status != RASMEM_BOOT_UNKNOWN)
	{
		bool warn = s->boot_status == RASMEM_BOOT_SKIPPED || s->boot_status == RASMEM_BOOT_ABORTED || s->boot_status == RASMEM_BOOT_INTERRUPTED;
		kv("full test", "%s%s%s", warn ? col(C_YELLOW) : "", boot_status_text(s->boot_status), warn ? col(C_RESET) : "");
	}
	kv("early test", "%s page(s)", fmt_count(s->early_pages_tested, b1, sizeof(b1)));
	kv("address test", "%s in %s", fmt_bytes(s->global_pages * (uint64_t)pagesize, b1, sizeof(b1)), fmt_msec(s->global_msec, b2, sizeof(b2)));
	kv("chunk test", "%s in %s (%ju/%ju chunks), %s skipped", fmt_bytes(s->boot_pages_tested * (uint64_t)pagesize, b1, sizeof(b1)), fmt_msec(chunk_ms, b2, sizeof(b2)), (uintmax_t)s->boot_chunks_done, (uintmax_t)s->boot_chunks_total, fmt_bytes(s->boot_pages_skipped * (uint64_t)pagesize, b3, sizeof(b3)));

	section("DATABASE");
	if (s->last_save_error != 0)
	{
		kv("last save", "%sFAILED: %s%s (last good save %s)", col(C_RED), strerror(s->last_save_error), col(C_RESET), fmt_age(s->last_save_ts, now, b1, sizeof(b1)));
	}
	else
	{
		kv("last save", "%s", fmt_age(s->last_save_ts, now, b1, sizeof(b1)));
	}
}

static void print_dimms(void)
{
	char b[32];
	size_t i;
	u_int k;

	if (ndimms == 0)
	{
		fprintf(out, "  no module inventory (SMBIOS) available\n");
		return;
	}
	fprintf(out, "%s  %-3s %-14s %-16s %9s  %-12s %-18s %-16s %4s %6s%s\n", col(C_DIM), "#", "MODULE", "BANK", "SIZE", "VENDOR", "PART", "SERIAL", "BAD", "SHARED", col(C_RESET));
	for (i = 0; i < ndimms; i++)
	{
		fmt_bytes((uint64_t)dimms[i].size_mb << 20, b, sizeof(b));
		fprintf(out, "  %-3zu %-14.14s %-16.16s %9s  %-12.12s %-18.18s %-16.16s %s%4u%s %6u\n", i, dimms[i].locator, dimms[i].bank, b, dimms[i].manufacturer, dimms[i].part, dimms[i].serial, dimms[i].bad_pages ? col(C_RED) : "", dimms[i].bad_pages, dimms[i].bad_pages ? col(C_RESET) : "", dimms[i].shared_bad_pages);
		for (k = 0; k < dimms[i].nranges && k < RASMEM_DIMM_RANGES; k++)
		{
			fprintf(out, "      address range 0x%012jx-0x%012jx\n", (uintmax_t)dimms[i].range_start[k], (uintmax_t)dimms[i].range_end[k]);
		}
	}
	fprintf(out, "%s  BAD = bad pages only on this module, SHARED = bad pages that may be on it (interleaving)%s\n", col(C_DIM), col(C_RESET));
}

static const char *sort_name(void)
{

	return (opt_sort == 'a' ? "address" : opt_sort == 't' ? "last error" : "errors");
}

/* ------------------------------------------------------------------------ */
/* JSON output                                                              */
/* ------------------------------------------------------------------------ */

static bool jpretty;
static int jdepth;
static bool jfirst[16];

static void jnewline(void)
{
	int i;

	if (!jpretty)
	{
		return;
	}
	oputc('\n');
	for (i = 0; i < jdepth; i++)
	{
		fputs("  ", out);
	}
}

static void jsep(void)
{

	if (!jfirst[jdepth])
	{
		oputc(',');
	}
	jfirst[jdepth] = false;
	jnewline();
}

static void jescape(const char *s)
{
	const unsigned char *p;

	oputc('"');
	for (p = (const unsigned char *)s; *p != '\0'; p++)
	{
		if (*p == '"' || *p == '\\')
		{
			fprintf(out, "\\%c", *p);
		}
		else if (*p < 0x20 || *p >= 0x7f)
		{
			fprintf(out, "\\u%04x", *p);
		}
		else
		{
			oputc(*p);
		}
	}
	oputc('"');
}

static void jkey(const char *k)
{

	jsep();
	jescape(k);
	fputs(jpretty ? ": " : ":", out);
}

/* Open an object/array, as a member (k != NULL) or array element. */
static void jopen(const char *k, char c)
{

	if (k != NULL)
	{
		jkey(k);
	}
	else if (jdepth > 0)
	{
		jsep();
	}
	oputc(c);
	jdepth++;
	jfirst[jdepth] = true;
}

static void jclose(char c)
{
	bool empty;

	empty = jfirst[jdepth];
	jdepth--;
	if (!empty)
	{
		jnewline();
	}
	oputc(c);
}

static void jstr(const char *k, const char *v)
{

	jkey(k);
	jescape(v);
}

static void jstrv(const char *v)
{

	jsep();
	jescape(v);
}

static void juint(const char *k, uintmax_t v)
{

	jkey(k);
	fprintf(out, "%ju", v);
}

static void jint(const char *k, intmax_t v)
{

	jkey(k);
	fprintf(out, "%jd", v);
}

static void jbool(const char *k, bool v)
{

	jkey(k);
	fputs(v ? "true" : "false", out);
}

static void jnull(const char *k)
{

	jkey(k);
	fputs("null", out);
}

static void jhex(const char *k, uint64_t v)
{
	char b[24];

	snprintf(b, sizeof(b), "0x%016jx", (uintmax_t)v);
	jstr(k, b);
}

/* Timestamp as seconds, or null if never. */
static void jtime(const char *k, int64_t ts)
{

	if (ts > 0)
	{
		jint(k, ts);
	}
	else
	{
		jnull(k);
	}
}

static void jpatterns(const char *k, int mask)
{
	int i;

	jopen(k, '[');
	for (i = 0; i < RASMEM_PAT_NBITS; i++)
	{
		if (mask & (1 << i))
		{
			jstrv(pat_names[i]);
		}
	}
	jclose(']');
}

static void json_regions(struct rasmem_region *r, size_t n)
{
	size_t i;

	jopen("bad_pages", '[');
	for (i = 0; i < n; i++)
	{
		jopen(NULL, '{');
		jhex("address", r[i].start_addr);
		juint("size", r[i].end_addr - r[i].start_addr);
		jstr("class", NAME(class_names, r[i].class));
		jstr("state", NAME(state_keys, r[i].state));
		jstr("found_by", NAME(src_names, r[i].source));
		juint("errors", r[i].errors);
		juint("retests", r[i].retests);
		juint("retest_fails", r[i].retest_fails);
		jhex("flipped_bits", r[i].bad_bits);
		jhex("last_xor", r[i].last_xor);
		juint("dimm_mask", r[i].dimm_mask);
		jbool("hit_live_data", r[i].flags & RASMEM_RF_CORRUPTION);
		jbool("unverified", r[i].flags & RASMEM_RF_UNVERIFIED);
		jtime("first_error", r[i].first_error_ts);
		jtime("last_error", r[i].last_error_ts);
		jtime("last_test", r[i].last_test_ts);
		jclose('}');
	}
	jclose(']');
}

static void json_dimms(void)
{
	size_t i;
	u_int k;

	jopen("modules", '[');
	for (i = 0; i < ndimms; i++)
	{
		jopen(NULL, '{');
		juint("index", i);
		jstr("locator", dimms[i].locator);
		jstr("bank", dimms[i].bank);
		jstr("manufacturer", dimms[i].manufacturer);
		jstr("part", dimms[i].part);
		jstr("serial", dimms[i].serial);
		juint("size_mb", dimms[i].size_mb);
		juint("bad_pages", dimms[i].bad_pages);
		juint("shared_bad_pages", dimms[i].shared_bad_pages);
		jopen("address_ranges", '[');
		for (k = 0; k < dimms[i].nranges && k < RASMEM_DIMM_RANGES; k++)
		{
			jopen(NULL, '{');
			jhex("start", dimms[i].range_start[k]);
			jhex("end", dimms[i].range_end[k]);
			jclose('}');
		}
		jclose(']');
		jclose('}');
	}
	jclose(']');
}

static void json_window(const char *k, const struct window *w)
{
	int a;

	if (!w->ok)
	{
		jnull(k);
		return;
	}
	jopen(k, '{');
	jint("seconds", (intmax_t)w->span);
	juint("bytes_per_sec", (uintmax_t)w->rate);
	jkey("busy_pct");
	fprintf(out, "%.2f", w->busy_pct);
	for (a = 0; a < A_N; a++)
	{
		char key[32];

		snprintf(key, sizeof(key), "%s_pct", a == A_NEIGHBOR ? "neighbour" : a == A_RO ? "read_only" : act_names[a]);
		jkey(key);
		fprintf(out, "%.2f", w->pct[a]);
	}
	jclose('}');
}

static void json_live(const struct rasmem_stats *s, struct rasmem_region *r, size_t n, const struct window *win, time_t now)
{
	struct window load;
	char host[64];
	size_t i;

	gethostname(host, sizeof(host));
	jdepth = 0;
	jfirst[0] = true;
	jopen(NULL, '{');
	jstr("version", RASMEM_VERSION);
	jstr("module_version", module_version());
	juint("abi_version", s->abi_version);
	jstr("host", host);
	jint("time", now);

	jopen("health", '{');
	jstr("state", NAME(health_keys, s->health));
	juint("code", s->health);
	jopen("reasons", '[');
	for (i = 0; i < nitems(reason_tab); i++)
	{
		if (s->replace_reasons & reason_tab[i].bit)
		{
			jstrv(reason_tab[i].key);
		}
	}
	jclose(']');
	jbool("reboot_required", s->reboot_required);
	jbool("panic_pending", s->panic_pending);
	if (s->worst_dimm >= 0 && (size_t)s->worst_dimm < ndimms)
	{
		jstr("suspected_module", dimms[s->worst_dimm].locator);
	}
	else
	{
		jnull("suspected_module");
	}
	jclose('}');

	jopen("evidence", '{');
	juint("corruption_events_boot", s->corrupt_boot);
	juint("error_events_boot", s->errors_boot);
	juint("verified_bad_pages", s->active_pages);
	juint("new_bad_pages_in_trend", s->trend_pages);
	jint("trend_days", get_int("hw.rasmem.trend_days", 7));
	juint("unverified_pages", s->unverified_pages);
	if (s->lane_bit >= 0)
	{
		jint("worst_data_bit", s->lane_bit);
	}
	else
	{
		jnull("worst_data_bit");
	}
	juint("worst_data_bit_pages", s->lane_max_pages);
	juint("worst_module_pages", s->worst_dimm_pages);
	juint("recorded", s->bad_pages);
	juint("isolated", s->bad_pages_held);
	juint("in_use", s->bad_pages_inuse);
	jtime("last_error", s->last_error_ts);
	jclose('}');

	jopen("memory", '{');
	juint("bytes", s->phys_pages * (uint64_t)pagesize);
	juint("pages", s->phys_pages);
	juint("modules", s->ndimms);
	jhex("fingerprint", s->hw_fingerprint);
	jbool("config_changed", s->hw_changed);
	jclose('}');

	jopen("testing", '{');
	jstr("current_phase", NAME(phase_names, s->phase));
	juint("bytes_verified", s->bytes_tested);
	juint("page_tests", s->pages_tested);
	juint("pages_not_obtainable", s->pages_skipped);
	jtime("loaded", s->load_ts);
	if (win != NULL)
	{
		json_window("window", win);
	}
	else
	{
		jnull("window");
	}
	window_since_load(s, now, &load);
	json_window("since_load", &load);
	jopen("last_run", '{');
	jtime("time", s->last_run_ts);
	juint("pages", s->last_run_pages);
	juint("usec", s->last_run_usec);
	jclose('}');
	jopen("busy_usec_total", '{');
	juint("periodic", s->busy_periodic_usec);
	juint("neighbour", s->busy_neighbor_usec);
	juint("retest", s->busy_retest_usec);
	juint("read_only", s->busy_ro_usec);
	juint("hold", s->hold_usec);
	jclose('}');
	jclose('}');

	jopen("periodic", '{');
	jbool("enabled", get_int("hw.rasmem.enable", 1));
	jint("interval_ms", get_int("hw.rasmem.interval", 1000));
	juint("bytes_per_hour", s->scan_bytes_per_hour);
	juint("pages_per_run", s->scan_pages_per_run);
	juint("runs", s->periodic_runs);
	juint("full_passes", s->periodic_sweeps);
	juint("current_pass_pct", pct(s->sweep_pos, s->phys_pages));
	juint("current_pass_tested_pages", s->sweep_tested);
	if (s->periodic_sweeps > 0)
	{
		juint("last_pass_tested_pages", s->last_sweep_tested);
		juint("last_pass_coverage_pct", pct(s->last_sweep_tested, s->phys_pages));
		juint("last_pass_secs", s->last_sweep_secs);
	}
	else
	{
		jnull("last_pass_tested_pages");
		jnull("last_pass_coverage_pct");
		jnull("last_pass_secs");
	}
	jhex("next_address", s->periodic_cursor);
	jstr("order", get_int("hw.rasmem.scan_order", 1) ? "spread" : "address");
	jint("retry_pct", get_int("hw.rasmem.retry_pct", 0));
	juint("retry_pages", s->retry_pages);
	juint("allocator_failures", s->alloc_fails);
	juint("allocator_budget_stops", s->budget_stops);
	juint("held_pages", s->held_pages);
	juint("reservations_broken", s->reserv_breaks);
	jint("break_reserv", get_int("hw.rasmem.break_reserv", 1));
	jint("march_every", get_int("hw.rasmem.march_every", 1));
	jint("hold_ms", get_int("hw.rasmem.hold_ms", 0));
	jint("hold_every", get_int("hw.rasmem.hold_every", 1));
	jpatterns("patterns", get_int("hw.rasmem.periodic_patterns", 0));
	jclose('}');

	jopen("retests", '{');
	juint("bad_page_retests", s->retests);
	juint("neighbourhood_retests", s->neighbor_tests);
	jclose('}');

	jopen("kernel_image", '{');
	juint("pages", s->ro_pages);
	juint("checks", s->ro_checks);
	juint("skipped", s->ro_skipped);
	juint("mismatches", s->ro_mismatch);
	jclose('}');

	jopen("boot", '{');
	jstr("status", boot_status_name(s->boot_status));
	juint("early_pages", s->early_pages_tested);
	juint("address_test_bytes", s->global_pages * (uint64_t)pagesize);
	juint("address_test_ms", s->global_msec);
	juint("chunk_test_bytes", s->boot_pages_tested * (uint64_t)pagesize);
	juint("chunk_test_skipped_bytes", s->boot_pages_skipped * (uint64_t)pagesize);
	juint("chunks_done", s->boot_chunks_done);
	juint("chunks_total", s->boot_chunks_total);
	juint("total_ms", s->boot_test_msec);
	jclose('}');

	jopen("database", '{');
	jtime("last_save", s->last_save_ts);
	jint("last_save_error", s->last_save_error);
	jclose('}');

	json_dimms();
	json_regions(r, n);
	jclose('}');
	oputc('\n');
}

static void json_db(const char *path, const struct rasmem_db_header *h, bool crc_ok, struct rasmem_region *r, size_t n)
{

	jdepth = 0;
	jfirst[0] = true;
	jopen(NULL, '{');
	jstr("file", path);
	juint("version", h->version);
	juint("records", h->count);
	jtime("saved", h->saved_ts);
	if (h->version >= 2)
	{
		jhex("fingerprint", h->hw_fingerprint);
	}
	else
	{
		jnull("fingerprint");
	}
	jbool("crc_ok", crc_ok);
	json_regions(r, n);
	jclose('}');
	oputc('\n');
}

/* ------------------------------------------------------------------------ */
/* Snapshot of everything the views show                                    */
/* ------------------------------------------------------------------------ */

struct snap
{
	bool			ok;		/* stats valid */
	int			err;		/* errno if not */
	struct rasmem_stats	s;
	struct rasmem_region	*r;
	size_t			n;
	struct window		win;
	time_t			now;
	/* coverage map */
	void			*mapbuf;
	bool			map_ok;
	int			map_err;
	struct rasmem_map_header mh;
	const struct rasmem_map_seg *segs;
	const uint16_t		*cells;
	const uint8_t		*share;		/* tested share, this pass */
	const uint8_t		*pshare;	/* tested share, last pass */
};

static void fetch_map(struct snap *x)
{
	const struct rasmem_map_header *h;
	size_t len, need;
	int tries;

	free(x->mapbuf);
	x->mapbuf = NULL;
	x->map_ok = false;
	x->map_err = 0;
	for (tries = 0; tries < 5; tries++)
	{
		len = 0;
		if (sysctlbyname("hw.rasmem.map", NULL, &len, NULL, 0) != 0)
		{
			x->map_err = errno;
			return;
		}
		if ((x->mapbuf = malloc(len + 1)) == NULL)
		{
			err(1, "malloc");
		}
		if (sysctlbyname("hw.rasmem.map", x->mapbuf, &len, NULL, 0) == 0)
		{
			break;
		}
		x->map_err = errno;
		free(x->mapbuf);
		x->mapbuf = NULL;
		if (errno != ENOMEM && errno != EAGAIN)
		{
			return;
		}
	}
	if (x->mapbuf == NULL)
	{
		return;
	}
	h = x->mapbuf;
	if (len < sizeof(*h) || h->version != RASMEM_MAP_VERSION || h->cell_pages == 0 || h->ncells == 0)
	{
		x->map_err = EPROTO;
		return;
	}
	need = sizeof(*h) + h->nsegs * sizeof(struct rasmem_map_seg) + h->ncells * (sizeof(uint16_t) + 2);
	if (len < need)
	{
		x->map_err = EPROTO;
		return;
	}
	x->mh = *h;
	x->segs = (const void *)(h + 1);
	x->cells = (const void *)(x->segs + h->nsegs);
	x->share = (const uint8_t *)(x->cells + h->ncells);
	x->pshare = x->share + h->ncells;
	x->map_ok = true;
}

static void fetch_snap(struct snap *x)
{

	free(x->r);
	x->r = NULL;
	x->n = 0;
	x->now = time(NULL);
	if (fetch_stats(&x->s) != 0)
	{
		x->ok = false;
		x->err = errno;
		return;
	}
	x->ok = true;
	rate_add(&x->s, monotime());
	window_get(&x->win);
	fetch_dimms();
	x->r = fetch_array("hw.rasmem.regions", sizeof(*x->r), &x->n);
	fetch_map(x);
}

/* Linear page <-> physical address through the map's segment list. */
static uint64_t map_lin_to_pa(const struct snap *x, uint64_t lin)
{
	uint32_t i;

	for (i = x->mh.nsegs; i-- > 0; )
	{
		if (lin >= x->segs[i].lin_first)
		{
			return (x->segs[i].start + (lin - x->segs[i].lin_first) * x->mh.page_size);
		}
	}
	return (0);
}

static bool map_pa_to_lin(const struct snap *x, uint64_t pa, uint64_t *lin)
{
	uint32_t i;

	for (i = 0; i < x->mh.nsegs; i++)
	{
		if (pa >= x->segs[i].start && pa < x->segs[i].end)
		{
			*lin = x->segs[i].lin_first + (pa - x->segs[i].start) / x->mh.page_size;
			return (true);
		}
	}
	return (false);
}

/* ------------------------------------------------------------------------ */
/* Coverage map                                                             */
/* ------------------------------------------------------------------------ */


/*
 * Test types done for a cell: what earlier passes credited, plus the
 * current pass where the scan has already been and covered the whole cell
 * without an error.
 */
static uint16_t cell_done(const struct snap *x, uint64_t c)
{
	uint16_t v, d;

	v = x->cells[c];
	d = v & RASMEM_MAP_DONE_ALL;
	if ((v & RASMEM_MAP_VISITED) != 0 && (v & (RASMEM_MAP_TESTED | RASMEM_MAP_SKIPPED | RASMEM_MAP_FAILED)) == RASMEM_MAP_TESTED)
	{
		d |= RASMEM_MAP_DONE_BASIC;
		if (v & RASMEM_MAP_MARCH)
		{
			d |= RASMEM_MAP_DONE_MARCH;
		}
		if (v & RASMEM_MAP_HOLD)
		{
			d |= RASMEM_MAP_DONE_HOLD;
		}
	}
	return (d);
}

static bool cell_full(const struct snap *x, uint64_t c)
{

	return ((cell_done(x, c) & RASMEM_MAP_DONE_ALL) == RASMEM_MAP_DONE_ALL);
}

/* Fully tested share of RAM, in percent. */
static u_int map_full_pct(const struct snap *x)
{
	uint64_t c, n;

	for (c = n = 0; c < x->mh.ncells; c++)
	{
		n += cell_full(x, c);
	}
	return (pct(n, x->mh.ncells));
}

/* Map states: one '#' in different colors, letters without colors. */
enum { S_FULL, S_FULL_OLD, S_PASS, S_MOST, S_PART, S_BUSY, S_HELD, S_PREV, S_NONE, S_CURSOR, S_BAD, S_BAD_INUSE, S_N };
static const struct
{
	const char	*color;
	char		ch;		/* with colors */
	char		plain;		/* without */
} sym_tab[S_N] = {
	[S_FULL] =	{ C_FULL,	'#', '#' },
	[S_FULL_OLD] =	{ C_FULL_OLD,	'#', '#' },
	[S_PASS] =	{ C_PASS,	'#', '+' },
	[S_MOST] =	{ C_MOST,	'#', '=' },
	[S_PART] =	{ C_PART,	'#', '~' },
	[S_BUSY] =	{ C_BUSY,	'#', '-' },
	[S_HELD] =	{ C_HELD,	'#', 'h' },
	[S_PREV] =	{ C_PREV,	'#', ':' },
	[S_NONE] =	{ C_PREV,	'.', '.' },
	[S_CURSOR] =	{ C_INV,	'@', '@' },
	[S_BAD] =	{ C_RED,	'X', 'X' },
	[S_BAD_INUSE] =	{ C_YELLOW,	'!', '!' },
};

/*
 * A block that was only partly tested (the rest was in use) is shaded by
 * how much was tested, so that memory tested in many small pieces still
 * shows.  share is 0-255.
 */
static int share_state(uint64_t share)
{

	if (share >= 128)
	{
		return (S_MOST);
	}
	if (share >= 26)
	{
		return (S_PART);
	}
	return (S_BUSY);
}

/*
 * One character covers cells [c0, c1).  Where the current pass has been,
 * it decides; elsewhere the previous pass (or the boot test) does.  The
 * colour comes from how much of the memory was actually tested: the rest
 * was in use.  Majority rules for the per-cell states.
 */
static int map_state(const struct snap *x, uint64_t c0, uint64_t c1, uint8_t bad, bool cursor)
{
	uint64_t c, nc, vis, full, known, share, held;
	uint16_t v;

	if (bad == 2)
	{
		return (S_BAD_INUSE);
	}
	if (bad == 1)
	{
		return (S_BAD);
	}
	if (cursor)
	{
		return (S_CURSOR);
	}
	nc = c1 - c0;
	vis = full = known = share = held = 0;
	for (c = c0; c < c1; c++)
	{
		v = x->cells[c];
		vis += (v & RASMEM_MAP_VISITED) != 0;
		full += cell_full(x, c);
	}
	if (vis * 2 >= nc && vis > 0)
	{
		/* Visited by the current pass: tested share of that. */
		for (c = c0; c < c1; c++)
		{
			v = x->cells[c];
			if ((v & RASMEM_MAP_VISITED) == 0)
			{
				continue;
			}
			share += x->share[c];
			held += (v & RASMEM_MAP_HELD) != 0;
		}
		share /= vis;			/* 0-255 */
		/*
		 * Memory in use now is shown as in use, even if it was fully
		 * tested earlier: green only where this pass could test it.
		 */
		if (share >= 230)
		{
			return (full * 2 >= nc ? S_FULL : S_PASS);
		}
		if (held * 2 >= vis)
		{
			return (S_HELD);
		}
		return (share_state(share));
	}
	for (c = c0; c < c1; c++)
	{
		v = x->cells[c];
		if ((v & (RASMEM_MAP_PREV_TESTED | RASMEM_MAP_PREV_SKIPPED)) == 0)
		{
			continue;
		}
		known++;
		share += x->pshare[c];
		held += (v & RASMEM_MAP_PREV_HELD) != 0;
	}
	if (known * 2 < nc || known == 0)
	{
		return (full * 2 >= nc && full > 0 ? S_FULL_OLD : S_NONE);
	}
	if (share / known >= 230)
	{
		return (full * 2 >= nc ? S_FULL_OLD : S_PREV);
	}
	if (held * 2 >= known)
	{
		return (S_HELD);
	}
	return (share_state(share / known));
}

/* Of the memory the current pass has visited: share tested, in percent. */
static u_int map_pass_tested_pct(const struct snap *x)
{
	uint64_t c, cp, last, vis, tested;

	cp = x->mh.cell_pages;
	vis = tested = 0;
	for (c = 0; c < x->mh.ncells; c++)
	{
		if ((x->cells[c] & RASMEM_MAP_VISITED) == 0)
		{
			continue;
		}
		last = MIN(cp, x->mh.total_pages - MIN(c * cp, x->mh.total_pages));
		vis += last;
		tested += last * x->share[c] / 255;
	}
	return (pct(tested, vis));
}

/* Short physical address for row labels: "512M", "15.50G". */
static const char *fmt_addr_short(uint64_t pa, char *buf, size_t len)
{

	if (pa < (1ULL << 30))
	{
		snprintf(buf, len, "%juM", (uintmax_t)(pa >> 20));
	}
	else
	{
		snprintf(buf, len, "%.2fG", pa / 1073741824.0);
	}
	return (buf);
}

/*
 * Draw the map as a grid of at most width x height characters.  One
 * character covers k map cells, k a power of two.  Returns k.
 */
static uint64_t map_grid(const struct snap *x, int width, int height, bool labels)
{
	char b[24];
	uint8_t *bad;
	uint64_t k, ndisp, d, lin, c0, c1, cur_d, rows, row;
	const char *last;
	size_t i;
	int w, col_i, st;

	w = labels ? width - 9 : width;
	w = MAX(w, 8);
	height = MAX(height, 1);
	for (k = 1; howmany(x->mh.ncells, k) > (uint64_t)w * height; k <<= 1)
	{
	}
	ndisp = howmany(x->mh.ncells, k);
	if ((bad = calloc(ndisp, 1)) == NULL)
	{
		err(1, "calloc");
	}
	for (i = 0; i < x->n; i++)
	{
		if (x->r[i].state == RASMEM_ST_RELEASED || !map_pa_to_lin(x, x->r[i].start_addr, &lin))
		{
			continue;
		}
		d = lin / x->mh.cell_pages / k;
		if (d < ndisp)
		{
			bad[d] = x->r[i].state == RASMEM_ST_INUSE ? 2 : MAX(bad[d], 1);
		}
	}
	cur_d = x->mh.cursor < x->mh.total_pages ? x->mh.cursor / x->mh.cell_pages / k : UINT64_MAX;
	if (get_int("hw.rasmem.enable", 1) == 0)
	{
		cur_d = UINT64_MAX;
	}
	rows = howmany(ndisp, (uint64_t)w);
	for (row = 0; row < rows; row++)
	{
		if (labels)
		{
			fprintf(out, "%s%8s%s ", col(C_DIM), fmt_addr_short(map_lin_to_pa(x, row * w * k * x->mh.cell_pages), b, sizeof(b)), col(C_RESET));
		}
		else
		{
			fputs("  ", out);
		}
		last = NULL;
		for (col_i = 0; col_i < w; col_i++)
		{
			d = row * w + col_i;
			if (d >= ndisp)
			{
				break;
			}
			c0 = d * k;
			c1 = MIN(c0 + k, x->mh.ncells);
			st = map_state(x, c0, c1, bad[d], d == cur_d);
			if (sym_tab[st].color != last)
			{
				fputs(col(C_RESET), out);
				fputs(col(sym_tab[st].color), out);
				last = sym_tab[st].color;
			}
			oputc(use_color ? sym_tab[st].ch : sym_tab[st].plain);
		}
		fprintf(out, "%s\n", col(C_RESET));
	}
	free(bad);
	return (k);
}

/* "#" in the state's colour (or its letter) and the text, padded. */
static void legend_item(int st, const char *text, int width)
{
	int n;

	fprintf(out, "%s%c%s %s", col(sym_tab[st].color), use_color ? sym_tab[st].ch : sym_tab[st].plain, col(C_RESET), text);
	for (n = 2 + (int)strlen(text); n < width; n++)
	{
		oputc(' ');
	}
}

static void map_legend(void)
{

	fputs("  ", out);
	legend_item(S_FULL, "fully tested: patterns, March C-, retention, no errors", 0);
	fputs("\n  ", out);
	legend_item(S_PASS, "tested this pass (90%+)", 27);
	legend_item(S_PREV, "tested last pass/boot", 27);
	legend_item(S_FULL_OLD, "fully tested earlier", 0);
	fputs("\n  ", out);
	fputs("partly, rest in use: ", out);
	legend_item(S_MOST, "50-90%", 10);
	legend_item(S_PART, "10-50%", 10);
	legend_item(S_BUSY, "under 10%", 13);
	legend_item(S_HELD, "free, held by the VM", 0);
	fputs("\n  ", out);
	legend_item(S_NONE, "not tested", 19);
	legend_item(S_CURSOR, "scanning now", 19);
	legend_item(S_BAD, "bad, isolated", 19);
	legend_item(S_BAD_INUSE, "bad, NOT isolated", 0);
	fputs("\n", out);
}

static void view_map(const struct snap *x, int width, int height)
{
	char b1[32], b2[32];
	uint64_t k;

	if (!x->map_ok)
	{
		fprintf(out, "\n  no coverage map: %s\n", x->map_err == ENOENT ? "the kernel module is older than this rasmemstat" : strerror(x->map_err));
		return;
	}
	fprintf(out, "  pass %ju at %s%u%%%s, %s (at 0x%012jx)   fully tested %s%u%%%s of %s\n", (uintmax_t)x->mh.passes + 1, col(C_BOLD), pct(x->mh.pass_done, x->mh.total_pages), col(C_RESET), x->mh.order ? "spread order" : "by address", (uintmax_t)map_lin_to_pa(x, MIN(x->mh.cursor, x->mh.total_pages - 1)), col(C_FULL), map_full_pct(x), col(C_RESET), fmt_bytes(x->mh.total_pages * x->mh.page_size, b1, sizeof(b1)));
	fprintf(out, "  visited so far: %u%% tested, %u%% in use (not testable now)\n", map_pass_tested_pct(x), 100 - map_pass_tested_pct(x));
	k = map_grid(x, width, MAX(height - 6, 1), true);
	fprintf(out, "%s  1 character = %s; address gaps are left out%s\n", col(C_DIM), fmt_bytes(k * x->mh.cell_pages * (uint64_t)x->mh.page_size, b2, sizeof(b2)), col(C_RESET));
	map_legend();
}

/* ------------------------------------------------------------------------ */
/* Overview                                                                 */
/* ------------------------------------------------------------------------ */

static void	okv(const char *label, const char *fmt, ...) __printflike(2, 3);

static void okv(const char *label, const char *fmt, ...)
{
	va_list ap;

	fprintf(out, "  %s%-10s%s ", col(C_BOLD), label, col(C_RESET));
	va_start(ap, fmt);
	vfprintf(out, fmt, ap);
	va_end(ap);
	fprintf(out, "\n");
}

static void view_overview(const struct snap *x, int width)
{
	const struct rasmem_stats *s = &x->s;
	struct row *rows;
	struct window w;
	char b1[32], b2[32], b3[32], dm[64], why[160];
	u_int cls[5];
	size_t i, nrows, pos;
	double eta_h;
	bool warn;

	/* Health, and why. */
	why[0] = '\0';
	for (i = pos = 0; i < nitems(reason_tab); i++)
	{
		if (s->replace_reasons & reason_tab[i].bit)
		{
			pos += snprintf(why + pos, sizeof(why) - pos, "%s%s", pos ? "; " : " - ", reason_tab[i].text);
		}
	}
	okv("HEALTH", "%s%s%s  %s%s", health_color(s->health), NAME(health_titles, s->health), col(C_RESET), NAME(health_texts, s->health), why);
	if (s->worst_dimm >= 0 && s->worst_dimm_pages > 0)
	{
		okv("", "suspect module %s (%u bad pages)", fmt_dimms(1u << s->worst_dimm, dm, sizeof(dm)), s->worst_dimm_pages);
	}
	if (s->panic_pending)
	{
		okv("", "%sPANIC PENDING: the kernel panics once the database is saved%s", col(C_RED), col(C_RESET));
	}

	/* Bad pages by class. */
	memset(cls, 0, sizeof(cls));
	for (i = 0; i < x->n; i++)
	{
		if (x->r[i].class < nitems(cls))
		{
			cls[x->r[i].class]++;
		}
	}
	pos = 0;
	why[0] = '\0';
	for (i = 0; i < nitems(cls); i++)
	{
		if (cls[i] > 0)
		{
			pos += snprintf(why + pos, sizeof(why) - pos, "%s%u %s", pos ? ", " : " (", cls[i], class_names[i]);
		}
	}
	if (pos > 0)
	{
		snprintf(why + pos, sizeof(why) - pos, ")");
	}
	okv("BAD PAGES", "%u%s: %u isolated, %s%u not isolated%s", s->bad_pages, why, s->bad_pages_held, s->bad_pages_inuse ? col(C_YELLOW) : "", s->bad_pages_inuse, s->bad_pages_inuse ? col(C_RESET) : "");
	okv("THIS BOOT", "%s%u live-data corruption event(s)%s, %u error event(s)", s->corrupt_boot ? col(C_RED) : "", s->corrupt_boot, s->corrupt_boot ? col(C_RESET) : "", s->errors_boot);
	okv("MEMORY", "%s, %u module(s)%s", fmt_bytes(s->phys_pages * (uint64_t)pagesize, b1, sizeof(b1)), s->ndimms, s->hw_changed ? ", configuration CHANGED since the database was written" : "");

	/* Periodic scan. */
	/* Rate: the sliding window, or since load for a one-shot. */
	if (x->win.ok)
	{
		w = x->win;
	}
	else
	{
		window_since_load(s, x->now, &w);
	}
	eta_h = s->scan_bytes_per_hour ? (double)(s->phys_pages - MIN(s->sweep_pos, s->phys_pages)) * pagesize / s->scan_bytes_per_hour : 0;
	if (get_int("hw.rasmem.enable", 1) == 0)
	{
		okv("SCAN", "%sdisabled%s (hw.rasmem.enable=0)", col(C_WARN), col(C_RESET));
	}
	else
	{
		okv("SCAN", "pass %ju at %u%%, done in ~%s (%ju full pass(es) so far)", (uintmax_t)s->periodic_sweeps + 1, pct(s->sweep_pos, s->phys_pages), fmt_secs((uint64_t)(eta_h * 3600), b3, sizeof(b3)), (uintmax_t)s->periodic_sweeps);
		if (x->map_ok)
		{
			okv("", "fully tested %s%u%%%s of RAM (patterns, March C-, retention; builds up over passes)", col(C_FULL), map_full_pct(x), col(C_RESET));
		}
		okv("", "%s/s %s, target %s/h, CPU %.1f%%", w.ok ? fmt_bytes((uint64_t)w.rate, b2, sizeof(b2)) : "-", x->win.ok ? "now" : "average", fmt_bytes(s->scan_bytes_per_hour, b1, sizeof(b1)), w.ok ? w.busy_pct : 0.0);
	}

	/* Boot test. */
	warn = s->boot_status == RASMEM_BOOT_ABORTED || s->boot_status == RASMEM_BOOT_SKIPPED || s->boot_status == RASMEM_BOOT_INTERRUPTED;
	if (s->boot_status == RASMEM_BOOT_OFF || s->boot_status == RASMEM_BOOT_UNKNOWN)
	{
		okv("BOOT TEST", "%s", boot_status_text(s->boot_status));
	}
	else
	{
		okv("BOOT TEST", "%s%s%s, %s tested in %s, %s skipped (in use)", warn ? col(C_WARN) : "", boot_status_name(s->boot_status), warn ? col(C_RESET) : "", fmt_bytes(s->boot_pages_tested * (uint64_t)pagesize, b1, sizeof(b1)), fmt_msec(s->boot_test_msec, b2, sizeof(b2)), fmt_bytes(s->boot_pages_skipped * (uint64_t)pagesize, b3, sizeof(b3)));
	}
	okv("KERNEL", "%ju read-only pages checksummed, %ju check(s), %s%u mismatch(es)%s", (uintmax_t)s->ro_pages, (uintmax_t)s->ro_checks, s->ro_mismatch ? col(C_RED) : "", s->ro_mismatch, s->ro_mismatch ? col(C_RESET) : "");
	if (s->last_save_error != 0)
	{
		okv("DATABASE", "%ssave FAILED: %s%s", col(C_RED), strerror(s->last_save_error), col(C_RESET));
	}
	else
	{
		okv("DATABASE", "saved %s", fmt_age(s->last_save_ts, x->now, b1, sizeof(b1)));
	}

	/* One-line map. */
	if (x->map_ok)
	{
		fprintf(out, "\n  %sMAP%s  (pass at %u%%, %u%% of it in use; %u%% fully tested%s)\n", col(C_BOLD), col(C_RESET), pct(x->mh.pass_done, x->mh.total_pages), 100 - map_pass_tested_pct(x), map_full_pct(x), tui ? "; 2: full map" : "");
		map_grid(x, MIN(width, 100), 1, false);
	}

	/* The worst bad pages. */
	if (x->n > 0)
	{
		fprintf(out, "\n  %sWORST BAD PAGES%s%s\n", col(C_BOLD), col(C_RESET), tui ? "  (press 3 for all)" : "");
		rows = make_rows(x->r, x->n, &nrows);
		fprintf(out, "%s  %-18s %-12s %-11s %6s  %-9s %s%s\n", col(C_DIM), "ADDRESS", "CLASS", "STATE", "ERRORS", "LAST", "MODULE", col(C_RESET));
		for (i = 0; i < nrows && i < 5; i++)
		{
			const struct rasmem_region *r = &rows[i].r;

			fprintf(out, "  0x%016jx %s%-12s%s %s%-11s%s %6u  %-9s %s\n", (uintmax_t)r->start_addr, class_color(r->class), NAME(class_names, r->class), col(C_RESET), r->state == RASMEM_ST_INUSE ? col(C_YELLOW) : "", NAME(state_names, r->state), r->state == RASMEM_ST_INUSE ? col(C_RESET) : "", r->errors, fmt_age(r->last_error_ts, x->now, b1, sizeof(b1)), fmt_dimms(r->dimm_mask, dm, sizeof(dm)));
		}
		if (nrows > 5)
		{
			fprintf(out, "  %s... %zu more%s\n", col(C_DIM), nrows - 5, col(C_RESET));
		}
		free(rows);
	}
}

/* ------------------------------------------------------------------------ */
/* Views                                                                    */
/* ------------------------------------------------------------------------ */

enum { V_OVERVIEW, V_MAP, V_PAGES, V_MODULES, V_DETAILS, V_NVIEWS, V_HELP = V_NVIEWS, V_ALL };
static const char *view_names[V_NVIEWS] = {
	"Overview", "Map", "Bad pages", "Modules", "Details"
};
static const char *view_keys[] = {
	"overview", "map", "pages", "modules", "details", "help", "all"
};

static void view_pages(const struct snap *x, size_t maxrows)
{
	struct row *rows;
	size_t nrows;

	rows = make_rows(x->r, x->n, &nrows);
	fprintf(out, "  %zu bad page record(s), sorted by %s%s\n", x->n, sort_name(), opt_merge ? ", adjacent pages merged" : "");
	print_rows(rows, nrows, maxrows, x->now);
	free(rows);
}

static void view_help(void)
{

	fprintf(out, "  %sKEYS%s\n", col(C_BOLD), col(C_RESET));
	fprintf(out, "    1-5, Tab, Left/Right   switch view\n");
	fprintf(out, "    Up/Down, j/k           scroll a line\n");
	fprintf(out, "    PgUp/PgDn, Space       scroll a page\n");
	fprintf(out, "    Home/End, g/G          top / bottom\n");
	fprintf(out, "    s                      bad pages: sort by errors, address, last error\n");
	fprintf(out, "    m                      bad pages: merge adjacent pages into ranges\n");
	fprintf(out, "    l                      bad pages: legend on/off\n");
	fprintf(out, "    + / -                  refresh slower / faster\n");
	fprintf(out, "    r                      refresh now\n");
	fprintf(out, "    q, Ctrl-C              quit\n\n");
	fprintf(out, "  %sMAP%s  memory in physical address order, one character per block\n", col(C_BOLD), col(C_RESET));
	map_legend();
	fprintf(out, "\n  The scan tests a small window every second, in 8 MiB slots spread over\n  all of RAM (or by address with hw.rasmem.scan_order=0); @ marks where it\n  is now.  Bright colours: done in the current pass; green and grey: earlier.\n"
	    "  March C- and the retention hold reach a rotating 1/10 of RAM per pass,\n  so \"fully tested\" grows over passes (and starts from the boot test).\n");
}

/* Render the body of a view into out. */
static void render_view(const struct snap *x, int view, int width, int height)
{

	switch (view)
	{
	case V_OVERVIEW:
		view_overview(x, width);
		break;
	case V_MAP:
		view_map(x, width, height);
		break;
	case V_PAGES:
		view_pages(x, SIZE_MAX);
		break;
	case V_MODULES:
		print_dimms();
		break;
	case V_DETAILS:
		print_status(&x->s, &x->win, x->now);
		break;
	case V_HELP:
		view_help();
		break;
	}
}

static void term_size(int *rows, int *cols)
{
	struct winsize ws;

	*rows = 24;
	*cols = 80;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0)
	{
		if (ws.ws_row > 0)
		{
			*rows = ws.ws_row;
		}
		if (ws.ws_col > 0)
		{
			*cols = ws.ws_col;
		}
	}
}

/* ------------------------------------------------------------------------ */
/* Interactive mode                                                         */
/* ------------------------------------------------------------------------ */

static struct termios tio_saved;
static bool tio_active;
static volatile sig_atomic_t resized;

static void onwinch(int sig __unused)
{

	resized = 1;
}

static void tui_restore(void)
{

	if (!tio_active)
	{
		return;
	}
	fputs("\033[0m\033[?7h\033[?25h\033[?1049l", stdout);
	fflush(stdout);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio_saved);
	tio_active = false;
}

static bool tui_start(void)
{
	struct termios raw;

	if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &tio_saved) != 0)
	{
		return (false);
	}
	raw = tio_saved;
	raw.c_lflag &= ~(ICANON | ECHO);
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
	{
		return (false);
	}
	tio_active = true;
	atexit(tui_restore);
	/* Alternate screen, no cursor, no line wrap. */
	fputs("\033[?1049h\033[?25l\033[?7l", stdout);
	return (true);
}

enum { K_NONE, K_UP, K_DOWN, K_PGUP, K_PGDN, K_HOME, K_END, K_LEFT, K_RIGHT };

/* Decode one key from buf; returns bytes used, *special for arrows etc. */
static size_t decode_key(const unsigned char *b, size_t n, int *ch, int *special)
{
	static const struct
	{
		const char	*seq;
		int		key;
	} seqs[] = {
		{ "\033[A", K_UP }, { "\033[B", K_DOWN }, { "\033OA", K_UP },
		{ "\033OB", K_DOWN }, { "\033[5~", K_PGUP },
		{ "\033[6~", K_PGDN }, { "\033[H", K_HOME },
		{ "\033[F", K_END }, { "\033OH", K_HOME }, { "\033OF", K_END },
		{ "\033[1~", K_HOME }, { "\033[4~", K_END },
		{ "\033[C", K_RIGHT }, { "\033[D", K_LEFT },
		{ "\033OC", K_RIGHT }, { "\033OD", K_LEFT },
	};
	size_t i, l;

	*ch = 0;
	*special = K_NONE;
	if (b[0] == '\033')
	{
		for (i = 0; i < nitems(seqs); i++)
		{
			l = strlen(seqs[i].seq);
			if (n >= l && memcmp(b, seqs[i].seq, l) == 0)
			{
				*special = seqs[i].key;
				return (l);
			}
		}
		/* Unknown sequence: swallow it. */
		for (l = 1; l < n && !(b[l] >= '@' && b[l] <= '~' && l > 1); l++)
		{
		}
		return (MIN(l + 1, n));
	}
	*ch = b[0];
	return (1);
}

static const double waits[] = { 0.5, 1, 2, 5, 10, 30 };

/*
 * Write a line clipped to cols visible columns: escape sequences take no
 * room, a UTF-8 character takes one column.
 */
static void put_clipped(const char *p, int cols)
{
	const char *start;
	int vis;

	start = p;
	vis = 0;
	while (*p != '\0')
	{
		if (*p == '\033')
		{
			p++;
			if (*p == '[')
			{
				for (p++; *p != '\0' && !(*p >= '@' && *p <= '~'); p++)
				{
				}
			}
			if (*p != '\0')
			{
				p++;
			}
			continue;
		}
		if (vis >= cols)
		{
			break;
		}
		vis++;
		for (p++; ((unsigned char)*p & 0xc0) == 0x80; p++)
		{
		}
	}
	fwrite(start, 1, p - start, stdout);
	/* Keep later escape sequences (colour resets) past the cut. */
	for (; *p != '\0'; p++)
	{
		if (*p == '\033')
		{
			start = p;
			if (*++p == '[')
			{
				for (p++; *p != '\0' && !(*p >= '@' && *p <= '~'); p++)
				{
				}
			}
			if (*p == '\0')
			{
				break;
			}
			fwrite(start, 1, p - start + 1, stdout);
		}
	}
}

static void draw_frame(const struct snap *x, int view, int *offset, double wait)
{
	char host[64], tbuf[16], b1[64], line[512], *buf, *p, *nl;
	size_t len, nlines, i, cap, pos;
	char **lines;
	int rows, cols, body, v, k;
	FILE *f;

	term_size(&rows, &cols);
	body = MAX(rows - 4, 1);

	/* Body first: its length decides the scroll range. */
	if ((f = open_memstream(&buf, &len)) == NULL)
	{
		err(1, "open_memstream");
	}
	out = f;
	if (!x->ok)
	{
		fprintf(out, "\n  rasmem: %s\n", x->err == ENOENT ? "the kernel module is not loaded" : x->err == EPROTO ? "kernel module and rasmemstat versions differ" : strerror(x->err));
	}
	else
	{
		render_view(x, view, cols, body);
	}
	fclose(f);
	out = stdout;
	cap = 64;
	lines = malloc(cap * sizeof(*lines));
	nlines = 0;
	for (p = buf; p != NULL && *p != '\0'; p = nl ? nl + 1 : NULL)
	{
		if ((nl = strchr(p, '\n')) != NULL)
		{
			*nl = '\0';
		}
		if (nlines == cap)
		{
			lines = reallocf(lines, (cap *= 2) * sizeof(*lines));
		}
		if (lines == NULL)
		{
			err(1, "realloc");
		}
		lines[nlines++] = p;
	}
	*offset = MIN(*offset, (int)MAX((int)nlines - body, 0));
	*offset = MAX(*offset, 0);

	/* Header: title and tabs. */
	gethostname(host, sizeof(host));
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&x->now));
	fputs("\033[H", stdout);
	snprintf(line, sizeof(line), "%srasmem %s%s %s%s%s  %s  %s  %s%s%s  loaded %s  refresh %gs", col(C_BOLD), RASMEM_VERSION, col(C_RESET), version_mismatch() ? col(C_YELLOW) : col(C_DIM), version_mismatch() ? "(module differs)" : RASMEM_STAGE, col(C_RESET), host, tbuf, x->ok ? health_color(x->s.health) : col(C_RED), x->ok ? NAME(health_titles, x->s.health) : "NOT RUNNING", col(C_RESET), x->ok ? fmt_age(x->s.load_ts, x->now, b1, sizeof(b1)) : "-", wait);
	put_clipped(line, cols);
	fputs("\033[K\r\n", stdout);
	pos = 0;
	for (v = 0; v < V_NVIEWS; v++)
	{
		k = v == view;
		pos += snprintf(line + pos, sizeof(line) - pos, "%s %d %s", k ? col(C_INV) : col(C_DIM), v + 1, view_names[v]);
		if (v == V_PAGES && x->ok)
		{
			pos += snprintf(line + pos, sizeof(line) - pos, "(%zu)", x->n);
		}
		pos += snprintf(line + pos, sizeof(line) - pos, " %s ", col(C_RESET));
		pos = MIN(pos, sizeof(line) - 1);
	}
	put_clipped(line, cols);
	fputs("\033[K\r\n\033[K\r\n", stdout);

	/* Body. */
	for (i = 0; i < (size_t)body; i++)
	{
		if ((size_t)*offset + i < nlines)
		{
			put_clipped(lines[*offset + i], cols);
		}
		printf("%s\033[K\r\n", col(C_RESET));
	}

	/* Footer. */
	if (nlines > (size_t)body)
	{
		snprintf(b1, sizeof(b1), "lines %d-%zu/%zu  ", *offset + 1, MIN((size_t)*offset + body, nlines), nlines);
	}
	else
	{
		b1[0] = '\0';
	}
	snprintf(line, sizeof(line), "%s %sq quit  ? help  1-5 views  arrows PgUp PgDn scroll  s sort  m merge  l legend  +/- refresh%s", col(C_DIM), b1, col(C_RESET));
	put_clipped(line, cols);
	fputs("\033[K", stdout);
	fflush(stdout);
	free(lines);
	free(buf);
}

static void run_tui(struct snap *x, int view, double wait)
{
	unsigned char kb[64];
	struct pollfd pfd;
	double next, t;
	int offset[V_ALL], ch, special, iw, prev_view, body, rows, cols;
	size_t i, n, used;
	ssize_t got;
	bool redraw;

	memset(offset, 0, sizeof(offset));
	for (iw = 0; iw < (int)nitems(waits) - 1 && waits[iw] < wait; iw++)
	{
	}
	wait = waits[iw];
	prev_view = view;
	signal(SIGWINCH, onwinch);
	signal(SIGTSTP, SIG_IGN);
	next = 0;
	redraw = true;
	while (!quit)
	{
		t = monotime();
		if (t >= next)
		{
			fetch_snap(x);
			next = t + wait;
			redraw = true;
		}
		if (resized)
		{
			resized = 0;
			fputs("\033[2J", stdout);
			redraw = true;
		}
		if (redraw)
		{
			draw_frame(x, view, &offset[view], wait);
			redraw = false;
		}
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;
		t = monotime();
		if (poll(&pfd, 1, (int)MAX((next - t) * 1000, 0) + 1) <= 0)
		{
			continue;
		}
		got = read(STDIN_FILENO, kb, sizeof(kb));
		if (got <= 0)
		{
			continue;
		}
		term_size(&rows, &cols);
		body = MAX(rows - 4, 1);
		n = (size_t)got;
		for (i = 0; i < n; i += used)
		{
			used = decode_key(kb + i, n - i, &ch, &special);
			redraw = true;
			if (special == K_DOWN || ch == 'j')
			{
				offset[view]++;
			}
			else if (special == K_UP || ch == 'k')
			{
				offset[view]--;
			}
			else if (special == K_PGDN || ch == ' ')
			{
				offset[view] += body - 1;
			}
			else if (special == K_PGUP)
			{
				offset[view] -= body - 1;
			}
			else if (special == K_HOME || ch == 'g')
			{
				offset[view] = 0;
			}
			else if (special == K_END || ch == 'G')
			{
				offset[view] = INT_MAX / 2;
			}
			else if (special == K_RIGHT || ch == '\t')
			{
				view = view >= V_NVIEWS - 1 ? 0 : view + 1;
			}
			else if (special == K_LEFT)
			{
				view = view <= 0 || view >= V_NVIEWS ? V_NVIEWS - 1 : view - 1;
			}
			else if (ch >= '1' && ch < '1' + V_NVIEWS)
			{
				view = ch - '1';
			}
			else if (ch == '?' || ch == 'h')
			{
				if (view == V_HELP)
				{
					view = prev_view;
				}
				else
				{
					prev_view = view;
					view = V_HELP;
				}
			}
			else if (ch == 'q' || ch == 'Q' || ch == 3)
			{
				quit = 1;
			}
			else if (ch == 's')
			{
				opt_sort = opt_sort == 'e' ? 'a' : opt_sort == 'a' ? 't' : 'e';
			}
			else if (ch == 'm')
			{
				opt_merge = !opt_merge;
			}
			else if (ch == 'l')
			{
				opt_legend = !opt_legend;
			}
			else if (ch == '+' && iw < (int)nitems(waits) - 1)
			{
				wait = waits[++iw];
				next = 0;
			}
			else if (ch == '-' && iw > 0)
			{
				wait = waits[--iw];
				next = 0;
			}
			else if (ch == 'r')
			{
				next = 0;
			}
			else if (view == V_HELP && ch != 0)
			{
				view = prev_view;
			}
			else
			{
				redraw = false;
			}
			if (view != V_HELP)
			{
				prev_view = view;
			}
			offset[view] = MAX(offset[view], 0);
		}
	}
	tui_restore();
}

/* ------------------------------------------------------------------------ */

static int parse_view(const char *name)
{
	size_t i;

	for (i = 0; i < nitems(view_keys); i++)
	{
		if (strcmp(name, view_keys[i]) == 0)
		{
			return ((int)i);
		}
	}
	if (name[0] >= '1' && name[0] < '1' + V_NVIEWS && name[1] == '\0')
	{
		return (name[0] - '1');
	}
	return (-1);
}

/* Non-interactive output of a view (or everything). */
static void print_view(const struct snap *x, int view)
{
	char b1[48];
	int rows, cols;

	if (!x->ok)
	{
		errx(1, "%s", x->err == ENOENT ? "rasmem is not loaded (kldload rasmem)" : x->err == EPROTO ? "rasmem kernel module and rasmemstat versions differ" : strerror(x->err));
	}
	term_size(&rows, &cols);
	if (!isatty(STDOUT_FILENO))
	{
		cols = 100;
	}
	switch (view)
	{
	case V_ALL:
		print_status(&x->s, &x->win, x->now);
		section("MODULES");
		print_dimms();
		snprintf(b1, sizeof(b1), "BAD PAGES (%zu, by %s)", x->n, sort_name());
		section(b1);
		view_pages(x, SIZE_MAX);
		if (x->map_ok)
		{
			section("MAP");
			view_map(x, MIN(cols, 120), 40);
		}
		break;
	case V_MAP:
		view_map(x, MIN(cols, 120), isatty(STDOUT_FILENO) ? MAX(rows - 2, 10) : 40);
		break;
	default:
		render_view(x, view, MIN(cols, 120), MAX(rows - 4, 10));
	}
}

int main(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "once",	no_argument,		NULL, '1' },
		{ "json",	no_argument,		NULL, 'J' },
		{ "modules",	no_argument,		NULL, 'd' },
		{ "file",	required_argument,	NULL, 'f' },
		{ "full",	no_argument,		NULL, 'F' },
		{ "merge",	no_argument,		NULL, 'm' },
		{ "rows",	required_argument,	NULL, 'n' },
		{ "sort",	required_argument,	NULL, 's' },
		{ "view",	required_argument,	NULL, 'V' },
		{ "wait",	required_argument,	NULL, 'w' },
		{ "avg",	required_argument,	NULL, 'a' },
		{ "no-color",	no_argument,		NULL, 'C' },
		{ "version",	no_argument,		NULL, 'v' },
		{ "help",	no_argument,		NULL, 'h' },
		{ NULL,		0,			NULL, 0 }
	};
	struct snap x;
	struct rasmem_db_header hdr;
	struct rasmem_region *r;
	struct row *rows;
	const char *dbfile;
	size_t n, nrows;
	double wait;
	bool once, json, tty, wait_set, nocolor, crc_ok;
	int ch, opt_rows, view;
	time_t now;
	char b1[48];

	out = stdout;
	once = json = wait_set = nocolor = false;
	dbfile = NULL;
	wait = 1.0;
	opt_rows = 0;
	view = -1;
	pagesize = getpagesize();
	while ((ch = getopt_long(argc, argv, "1JFV:a:df:mn:s:vw:h", longopts, NULL)) != -1)
	{
		switch (ch)
		{
		case '1':
			once = true;
			break;
		case 'J':
			json = true;
			break;
		case 'F':
			view = V_ALL;
			break;
		case 'V':
			if ((view = parse_view(optarg)) < 0)
			{
				usage();
			}
			break;
		case 'a':
			opt_avg = strtod(optarg, NULL);
			if (opt_avg < 1)
			{
				usage();
			}
			break;
		case 'd':
			view = V_MODULES;
			break;
		case 'f':
			dbfile = optarg;
			break;
		case 'm':
			opt_merge = true;
			break;
		case 'n':
			opt_rows = atoi(optarg);
			break;
		case 's':
			if (strchr("aet", optarg[0]) == NULL || optarg[1])
			{
				usage();
			}
			opt_sort = optarg[0];
			break;
		case 'w':
			wait = strtod(optarg, NULL);
			if (wait < 0.1)
			{
				usage();
			}
			wait_set = true;
			break;
		case 'C':
			nocolor = true;
			break;
		case 'v':
			printf("rasmemstat %s (%s)\n", RASMEM_VERSION, RASMEM_STAGE);
			printf("kernel module %s\n", module_version()[0] == '?' ? "not loaded, or older than 0.0.9b" : module_version());
			return (0);
		default:
			usage();
		}
	}
	if (optind != argc)
	{
		usage();
	}
	tty = isatty(STDOUT_FILENO);
	use_color = tty && !nocolor && !json && getenv("NO_COLOR") == NULL;

	/* Offline database dump. */
	if (dbfile != NULL)
	{
		r = read_db(dbfile, &n, &hdr, &crc_ok);
		if (json)
		{
			jpretty = true;
			json_db(dbfile, &hdr, crc_ok, r, n);
			return (0);
		}
		now = time(NULL);
		fprintf(out, "%sdatabase%s %s\n", col(C_BOLD), col(C_RESET), dbfile);
		kv("version", "%u", hdr.version);
		kv("saved", "%s", fmt_age(hdr.saved_ts, now, b1, sizeof(b1)));
		kv("fingerprint", "%016jx", (uintmax_t)(hdr.version >= 2 ? hdr.hw_fingerprint : 0));
		kv("checksum", "%s", crc_ok ? "ok" : "MISMATCH (the kernel will ignore this file)");
		snprintf(b1, sizeof(b1), "BAD PAGES (%zu, by %s)", n, sort_name());
		section(b1);
		rows = make_rows(r, n, &nrows);
		print_rows(rows, nrows, opt_rows > 0 ? (size_t)opt_rows : SIZE_MAX, now);
		return (0);
	}

	memset(&x, 0, sizeof(x));
	fetch_snap(&x);
	if (!x.ok)
	{
		if (x.err == ENOENT)
		{
			errx(1, "rasmem is not loaded (kldload rasmem)");
		}
		if (x.err == EPROTO)
		{
			errx(1, "rasmem kernel module and rasmemstat versions differ");
		}
		errno = x.err;
		err(1, "hw.rasmem.stats");
	}

	/* JSON: one document, or a stream of one object per line. */
	if (json)
	{
		jpretty = !wait_set;
		if (!wait_set)
		{
			json_live(&x.s, x.r, x.n, NULL, x.now);
			return (0);
		}
		signal(SIGINT, onsig);
		signal(SIGTERM, onsig);
		setvbuf(stdout, NULL, _IOLBF, 0);
		while (!quit)
		{
			usleep((useconds_t)(wait * 1e6));
			fetch_snap(&x);
			if (!x.ok)
			{
				fprintf(out, "{\"error\":\"%s\"}\n", strerror(x.err));
			}
			else
			{
				json_live(&x.s, x.r, x.n, &x.win, x.now);
			}
		}
		return (0);
	}

	/* One snapshot.  Default: the overview, then all bad pages. */
	if (once || (view == V_ALL && !wait_set) || (view == V_MODULES && !wait_set) || !tty)
	{
		if (opt_rows > 0 && view < 0)
		{
			view = V_PAGES;
		}
		do
		{
			if (view < 0)
			{
				fprintf(out, "%srasmem %s%s (%s)%s\n\n", col(C_BOLD), RASMEM_VERSION, col(C_RESET), RASMEM_STAGE, version_mismatch() ? ", kernel module differs" : "");
				view_overview(&x, 100);
				if (x.n > 0)
				{
					snprintf(b1, sizeof(b1), "BAD PAGES (%zu, by %s)", x.n, sort_name());
					section(b1);
					view_pages(&x, opt_rows > 0 ? (size_t)opt_rows : SIZE_MAX);
				}
			}
			else if (view == V_PAGES)
			{
				view_pages(&x, opt_rows > 0 ? (size_t)opt_rows : SIZE_MAX);
			}
			else
			{
				print_view(&x, view);
			}
			if (once || tty || !wait_set)
			{
				break;
			}
			/* Piped with -w: repeat. */
			fprintf(out, "\n");
			fflush(stdout);
			usleep((useconds_t)(wait * 1e6));
			fetch_snap(&x);
		} while (!quit);
		return (0);
	}

	/* Interactive. */
	signal(SIGINT, onsig);
	signal(SIGTERM, onsig);
	tui = true;
	if (!tui_start())
	{
		errx(1, "stdin is not a terminal; use -1 for a snapshot");
	}
	run_tui(&x, view < 0 || view >= V_NVIEWS ? V_OVERVIEW : view, wait);
	return (0);
}
