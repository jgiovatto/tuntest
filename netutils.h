
#include "types.h"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>

#include <vector>

#ifndef TUNTEST_NETUTILS_H
#define TUNTEST_NETUTILS_H


using InAddrs = std::vector<in_addr_t>;

struct dvmrphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
} __attribute__((packed));


struct dvmrpprobe {
    uint16_t cap;
    uint8_t  minor;
    uint8_t  major;
    uint32_t genid;
} __attribute__((packed));



const char * fmt_str(const char * fmt, 
                     char * const str, 
                     const size_t strlen, 
                     const uint8_t val);

const char * fmt_str(const char * fmt, 
                     char * const str, 
                     const size_t strlen, 
                     const uint8_t val1,
                     const uint8_t val2,
                     const uint8_t val3);


void set_ipv4_hdr(iphdr * ip, 
                  const uint8_t tos,
                  const uint8_t ttl,
                  const uint16_t id,
                  const uint16_t plen,
                  const uint8_t proto,
                  const in_addr_t src,
                  const in_addr_t dst,
                  const uint32_t * opts,
                  const size_t numopts);

void set_udp_hdr(iphdr * udp,
                 const uint16_t src, 
                 const uint16_t dst, 
                 const iphdr * ip,
                 const void * data,
                 const uint16_t dlen);

void set_igmp_hdr(igmp * igmp,
                  const uint8_t type, 
                  const uint8_t code, 
                  const in_addr_t grp);

void set_eth_hdr(ether_header * eth,
                 const ether_addr * src,
                 const ether_addr * dst,
                 const uint16_t type);

void set_igmp_query(ether_header * eth, 
                    iphdr * ip, 
                    uint32_t * ipop,
                    igmp * igmp, 
                    const uint8_t tunId);

void set_dvmrp_probe(ether_header * eth, 
                     iphdr * ip, 
                     uint32_t * ipop,
                     dvmrphdr * hdr, 
                     dvmrpprobe * probe, 
                     const InAddrs & nbrs,
                     const uint8_t tunId);



void print_hex(const char * buff, size_t const bufflen, const Colors & colors);

uint16_t csum16(const void *buff, uint16_t len, uint16_t carry = 0);

uint16_t csum16v(const iovec * iov, const size_t iovn);

size_t build_rip_frame(char * buff, size_t bufflen, uint8_t tunId);

int parse_frame(char *buff, size_t bufflen, size_t msglen, uint8_t tunId);


#endif
