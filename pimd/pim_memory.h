// SPDX-License-Identifier: GPL-2.0-or-later
/* pimd memory type declarations
 *
 * Copyright (C) 2015  David Lamparter
 */

#ifndef _QUAGGA_PIM_MEMORY_H
#define _QUAGGA_PIM_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(PIMD);
DECLARE_MTYPE(PIM_CHANNEL_OIL);
DECLARE_MTYPE(PIM_INTERFACE);
DECLARE_MTYPE(PIM_IGMP_JOIN);
DECLARE_MTYPE(PIM_IGMP_SOCKET);
DECLARE_MTYPE(PIM_IGMP_GROUP);
DECLARE_MTYPE(PIM_IGMP_GROUP_SOURCE);
DECLARE_MTYPE(PIM_NEIGHBOR);
DECLARE_MTYPE(PIM_IFCHANNEL);
DECLARE_MTYPE(PIM_UPSTREAM);
DECLARE_MTYPE(PIM_SSMPINGD);
DECLARE_MTYPE(PIM_STATIC_ROUTE);
DECLARE_MTYPE(PIM_RP);
DECLARE_MTYPE(PIM_FILTER_NAME);
DECLARE_MTYPE(PIM_MSDP_PEER);
DECLARE_MTYPE(PIM_MSDP_MG_NAME);
DECLARE_MTYPE(PIM_MSDP_SA);
DECLARE_MTYPE(PIM_MSDP_MG);
DECLARE_MTYPE(PIM_MSDP_MG_MBR);
DECLARE_MTYPE(PIM_SEC_ADDR);
DECLARE_MTYPE(PIM_JP_AGG_GROUP);
DECLARE_MTYPE(PIM_JP_AGG_SOURCE);
DECLARE_MTYPE(PIM_PIM_INSTANCE);
DECLARE_MTYPE(PIM_NEXTHOP_CACHE);
DECLARE_MTYPE(PIM_SSM_INFO);
DECLARE_MTYPE(PIM_PLIST_NAME);
DECLARE_MTYPE(PIM_VXLAN_SG);

#endif /* _QUAGGA_PIM_MEMORY_H */
