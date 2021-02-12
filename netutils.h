
#include "types.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>


#ifndef TUNTEST_NETUTILS_H
#define TUNTEST_NETUTILS_H

const char * fmt_str(const char * fmt, 
                     char * const str, 
                     const size_t strlen, 
                     const uint8_t val);

const char * fmt_str2(const char * fmt, 
                      char * const str, 
                      const size_t strlen, 
                      const uint8_t val1,
                      const uint8_t val2);


void set_ipv4_hdr(iphdr * ip, 
                  const uint8_t hlen,
                  const uint8_t tos,
                  const uint8_t ttl,
                  const uint16_t plen,
                  const uint8_t proto,
                  const in_addr_t src,
                  const in_addr_t dst);

void set_udp_hdr(iphdr * udp,
                 const uint16_t src, 
                 const uint16_t dst, 
                 const iphdr * ip,
                 const void * data,
                 const uint16_t dlen);

void print_hex(const char * buff, size_t const bufflen, const Colors & colors);

uint16_t csum16(const void *buff, uint16_t len, uint16_t carry = 0);

uint16_t csum16v(const iovec * iov, const size_t iovn);

size_t build_rip_frame(char * buff, size_t bufflen, uint8_t tunId);

int parse_frame(char *buff, size_t bufflen, size_t msglen, uint8_t tunId);

size_t build_igmp_query(ether_header * eth, iphdr * ip, uint32_t * ra, igmp * igmp, uint8_t tunId);


#endif
