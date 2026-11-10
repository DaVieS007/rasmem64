# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Viktor Hlavaji (DaVieS) <davies@npulse.net>

# rasmem - RAS memory test suite kernel module (amd64), beta
#
# In-tree:      copy sys/dev/rasmem and sys/modules/rasmem into /usr/src/sys
#               and run "make" here.
# Out-of-tree:  works from this tree as long as SYSDIR points at the kernel
#               sources (default /usr/src/sys).

.PATH:	${.CURDIR}/../../dev/rasmem

KMOD=	rasmem
SRCS=	rasmem.c rasmem_test.c rasmem_smbios.c
SRCS+=	bus_if.h device_if.h vnode_if.h

CFLAGS+=	-I${.CURDIR}/../..

.include <bsd.kmod.mk>
