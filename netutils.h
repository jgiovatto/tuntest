
#include "types.h"

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


void print_hex(const char * buff, size_t const bufflen, const Colors & colors);

uint16_t csum16(const void *buff, uint16_t len, uint16_t carry = 0);

uint16_t csum16v(const struct iovec * iov, const size_t iovn);

size_t build_rip_frame(char * buff, size_t bufflen, uint8_t tunId);

int parse_frame(char *buff, size_t bufflen, size_t msglen, uint8_t tunId);

#endif
