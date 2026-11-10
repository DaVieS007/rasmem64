# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Viktor Hlavaji (DaVieS) <davies@npulse.net>

PROG=	rasmemstat
MAN=	rasmemstat.8
BINDIR?=	/usr/local/sbin
WARNS?=	6

# rasmem.h (shared ABI) lives in the kernel tree.
CFLAGS+=	-I${.CURDIR}/../../sys

.include <bsd.prog.mk>
