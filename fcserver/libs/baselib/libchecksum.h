#ifndef LIBCHECKSUM_H
#define LIBCHECKSUM_H

#include <stdint.h>

extern uint16_t csum_fold(uint32_t csum);
extern uint16_t ip_fast_csum(const void* iph, uint32_t ihl);
extern uint32_t csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr, uint16_t len,
                                   uint16_t proto, uint32_t sum);
extern uint32_t csum_partial(const void* buff, int len, uint32_t wsum);

#endif
