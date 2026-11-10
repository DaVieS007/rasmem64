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
 * rasmem - memory module inventory from SMBIOS.
 *
 * Type 17 (Memory Device) gives the modules (slot name, serial, part number,
 * size); type 20 (Memory Device Mapped Address), where the firmware
 * provides it, maps physical address ranges to modules.  With interleaving
 * several modules share a range, so a physical address maps to a *set* of
 * modules (a bit mask).  Many current firmwares omit type 20; the mask is
 * then 0 ("unknown") and only the inventory and fingerprint are available.
 *
 * The fingerprint identifies the memory configuration (modules + size) so
 * that a bad page database is not blindly applied to different hardware.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/gsb_crc32.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <machine/resource.h>

#include <dev/rasmem/rasmem_var.h>

#define	SM_MAXDIMMS	32		/* fits the 32-bit dimm_mask */
#define	SM_MAXMAPS	256
#define	SM_MAXTABLE	(1024 * 1024)
#define	SM_BIOS_START	0xf0000
#define	SM_BIOS_LEN	0x10000

struct sm_dimm
{
	struct rasmem_dimm_info	info;
	uint16_t		handle;
};

struct sm_map
{
	uint64_t	start;
	uint64_t	end;		/* exclusive */
	int		dimm;
};

static struct sm_dimm *sm_dimms;
static int sm_ndimms;
static struct sm_map *sm_maps;
static int sm_nmaps;
static uint64_t sm_fp;

static vm_paddr_t sm_find_eps(void)
{
	devclass_t dc;
	device_t dev;
	vm_paddr_t pa, v2;
	char *env, *va;
	u_int off;

	/* EFI loader: address of the SMBIOS (3) entry point. */
	if ((env = kern_getenv("hint.smbios.0.mem")) != NULL)
	{
		pa = strtouq(env, NULL, 0);
		freeenv(env);
		if (pa != 0)
		{
			return (pa);
		}
	}
	/* smbios(4), if attached. */
	if ((dc = devclass_find("smbios")) != NULL && (dev = devclass_get_device(dc, 0)) != NULL && (pa = bus_get_resource_start(dev, SYS_RES_MEMORY, 0)) != 0)
	{
		return (pa);
	}
	/* Legacy BIOS: scan the F segment, prefer the 64-bit entry point. */
	va = pmap_mapbios(SM_BIOS_START, SM_BIOS_LEN);
	if (va == NULL)
	{
		return (0);
	}
	pa = v2 = 0;
	for (off = 0; off + 32 <= SM_BIOS_LEN; off += 16)
	{
		if (memcmp(va + off, "_SM3_", 5) == 0)
		{
			pa = SM_BIOS_START + off;
			break;
		}
		if (v2 == 0 && memcmp(va + off, "_SM_", 4) == 0)
		{
			v2 = SM_BIOS_START + off;
		}
	}
	pmap_unmapbios(va, SM_BIOS_LEN);
	return (pa != 0 ? pa : v2);
}

static bool sm_table(vm_paddr_t eps, vm_paddr_t *tab, uint32_t *len, int *count)
{
	uint8_t *va;
	bool ok;

	va = pmap_mapbios(eps, 32);
	if (va == NULL)
	{
		return (false);
	}
	ok = true;
	if (memcmp(va, "_SM3_", 5) == 0)
	{
		*len = le32dec(va + 0x0c);
		*tab = le64dec(va + 0x10);
		*count = -1;			/* until type 127 */
	}
	else if (memcmp(va, "_SM_", 4) == 0)
	{
		*len = le16dec(va + 0x16);
		*tab = le32dec(va + 0x18);
		*count = le16dec(va + 0x1c);
	}
	else
	{
		ok = false;
	}
	pmap_unmapbios(va, 32);
	return (ok && *len > 0 && *len <= SM_MAXTABLE && *tab != 0);
}

/* String number idx (1-based) of the structure at p; "" if absent. */
static void sm_string(const uint8_t *p, const uint8_t *end, u_int idx, char *out, size_t outlen)
{
	const uint8_t *s;
	size_t i, n;

	out[0] = '\0';
	if (idx == 0)
	{
		return;
	}
	s = p + p[1];
	while (--idx > 0 && s < end)
	{
		while (s < end && *s != '\0')
		{
			s++;
		}
		s++;
	}
	if (s >= end)
	{
		return;
	}
	for (n = 0; s + n < end && s[n] != '\0'; n++)
	{
	}
	for (i = 0; i < n && i < outlen - 1; i++)
	{
		out[i] = (s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : '?';
	}
	out[i] = '\0';
	while (i > 0 && out[i - 1] == ' ')
	{
		out[--i] = '\0';
	}
}

static void sm_parse(const uint8_t *tab, uint32_t len, int count)
{
	const uint8_t *p, *q, *end;
	struct sm_dimm *d;
	struct sm_map *mp;
	uint64_t start, stop;
	uint32_t sk, ek, mb;
	uint16_t size;
	int n;

	end = tab + len;
	for (p = tab, n = 0; p + 4 <= end && (count < 0 || n < count); n++)
	{
		if (p[1] < 4 || p + p[1] > end)
		{
			break;
		}
		/* The string area ends with two NULs. */
		for (q = p + p[1]; q + 1 < end && (q[0] != 0 || q[1] != 0); q++)
		{
		}
		switch (p[0])
		{
		case 17:	/* Memory Device */
			if (p[1] < 0x15 || sm_ndimms >= SM_MAXDIMMS)
			{
				break;
			}
			size = le16dec(p + 0x0c);
			if (size == 0 || size == 0xffff)
			{
				break;			/* empty slot */
			}
			if (size == 0x7fff && p[1] >= 0x20)
			{
				mb = le32dec(p + 0x1c) & 0x7fffffff;
			}
			else if (size & 0x8000)
			{
				mb = (size & 0x7fff) / 1024;	/* KB units */
			}
			else
			{
				mb = size;
			}
			d = &sm_dimms[sm_ndimms++];
			d->handle = le16dec(p + 2);
			d->info.size_mb = mb;
			sm_string(p, end, p[0x10], d->info.locator, sizeof(d->info.locator));
			sm_string(p, end, p[0x11], d->info.bank, sizeof(d->info.bank));
			if (p[1] >= 0x1b)
			{
				sm_string(p, end, p[0x17], d->info.manufacturer, sizeof(d->info.manufacturer));
				sm_string(p, end, p[0x18], d->info.serial, sizeof(d->info.serial));
				sm_string(p, end, p[0x1a], d->info.part, sizeof(d->info.part));
			}
			break;
		case 20:	/* Memory Device Mapped Address */
			if (p[1] < 0x13 || sm_nmaps >= SM_MAXMAPS)
			{
				break;
			}
			sk = le32dec(p + 0x04);
			ek = le32dec(p + 0x08);
			if (sk == 0xffffffff && p[1] >= 0x23)
			{
				start = le64dec(p + 0x13);
				stop = le64dec(p + 0x1b) + 1;
			}
			else
			{
				start = (uint64_t)sk << 10;
				stop = ((uint64_t)ek + 1) << 10;
			}
			if (stop <= start)
			{
				break;
			}
			mp = &sm_maps[sm_nmaps++];
			mp->start = start;
			mp->end = stop;
			mp->dimm = -(int)le16dec(p + 0x0c) - 1; /* handle, fixed below */
			break;
		}
		if (p[0] == 127)
		{
			break;
		}
		p = q + 2;
	}
}

/* Returns the number of modules found. */
int rasmem_smbios_init(void)
{
	vm_paddr_t eps, tab;
	uint32_t len, crc, gib;
	uint8_t *va;
	char sz[16];
	int count, i, j;
	uint16_t h;

	sm_dimms = malloc(SM_MAXDIMMS * sizeof(*sm_dimms), M_RASMEM, M_WAITOK | M_ZERO);
	sm_maps = malloc(SM_MAXMAPS * sizeof(*sm_maps), M_RASMEM, M_WAITOK | M_ZERO);
	sm_ndimms = sm_nmaps = 0;

	eps = sm_find_eps();
	if (eps != 0 && sm_table(eps, &tab, &len, &count) && (va = pmap_mapbios(tab, len)) != NULL)
	{
		sm_parse(va, len, count);
		pmap_unmapbios(va, len);
	}
	else
	{
		RAS_LOG("SMBIOS not found: no module inventory\n");
	}

	/* Resolve type 20 device handles to module indices. */
	for (i = 0; i < sm_nmaps; i++)
	{
		h = (uint16_t)(-sm_maps[i].dimm - 1);
		sm_maps[i].dimm = -1;
		for (j = 0; j < sm_ndimms; j++)
		{
			if (sm_dimms[j].handle == h)
			{
				sm_maps[i].dimm = j;
				if (sm_dimms[j].info.nranges < RASMEM_DIMM_RANGES)
				{
					sm_dimms[j].info.range_start[sm_dimms[j].info.nranges] = sm_maps[i].start;
					sm_dimms[j].info.range_end[sm_dimms[j].info.nranges++] = sm_maps[i].end;
				}
				break;
			}
		}
	}

	/* Fingerprint: modules (high 32 bits) + memory size (low 32). */
	crc = ~0U;
	for (i = 0; i < sm_ndimms; i++)
	{
		crc = calculate_crc32c(crc, (const unsigned char *)sm_dimms[i].info.locator, sizeof(sm_dimms[i].info.locator) * 5);
		crc = calculate_crc32c(crc, (const unsigned char *)&sm_dimms[i].info.size_mb, sizeof(sm_dimms[i].info.size_mb));
	}
	gib = (uint32_t)((uint64_t)realmem >> (30 - PAGE_SHIFT));
	sm_fp = (sm_ndimms > 0 ? (uint64_t)crc << 32 : 0) | calculate_crc32c(~0U, (const unsigned char *)&gib, sizeof(gib));

	for (i = 0; i < sm_ndimms; i++)
	{
		snprintf(sz, sizeof(sz), "%u MB", sm_dimms[i].info.size_mb);
		RAS_VLOG("dimm %d: %s / %s, %s, %s %s s/n %s, %u range(s)\n", i, sm_dimms[i].info.locator, sm_dimms[i].info.bank, sz, sm_dimms[i].info.manufacturer, sm_dimms[i].info.part, sm_dimms[i].info.serial, sm_dimms[i].info.nranges);
	}
	if (sm_ndimms > 0)
	{
		RAS_LOG("%d memory module(s) in SMBIOS, address mapping %s\n", sm_ndimms, sm_nmaps > 0 ? "available" : "not provided by firmware");
	}
	return (sm_ndimms);
}

void rasmem_smbios_fini(void)
{

	free(sm_dimms, M_RASMEM);
	free(sm_maps, M_RASMEM);
	sm_dimms = NULL;
	sm_maps = NULL;
	sm_ndimms = sm_nmaps = 0;
}

uint32_t rasmem_dimm_mask(vm_paddr_t pa)
{
	uint32_t mask;
	int i;

	mask = 0;
	for (i = 0; i < sm_nmaps; i++)
	{
		if (sm_maps[i].dimm >= 0 && pa >= sm_maps[i].start && pa < sm_maps[i].end)
		{
			mask |= 1u << sm_maps[i].dimm;
		}
	}
	return (mask);
}

uint64_t rasmem_hw_fingerprint(void)
{

	return (sm_fp);
}

int rasmem_dimm_count(void)
{

	return (sm_ndimms);
}

void rasmem_dimm_get(int i, struct rasmem_dimm_info *out)
{

	if (i < 0 || i >= sm_ndimms)
	{
		bzero(out, sizeof(*out));
		return;
	}
	*out = sm_dimms[i].info;
}

/* "DIMM_A1|DIMM_B1" for a mask, "unknown" for 0. */
void rasmem_dimm_names(uint32_t mask, char *buf, size_t len)
{
	size_t pos;
	int i;

	buf[0] = '\0';
	if (mask == 0 || sm_ndimms == 0)
	{
		strlcpy(buf, "unknown", len);
		return;
	}
	pos = 0;
	for (i = 0; i < sm_ndimms && pos < len; i++)
	{
		if (mask & (1u << i))
		{
			pos += snprintf(buf + pos, len - pos, "%s%s", pos ? "|" : "", sm_dimms[i].info.locator[0] ? sm_dimms[i].info.locator : "?");
		}
	}
}
