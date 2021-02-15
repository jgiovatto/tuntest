
#ifndef TUNTEST_TYPES_H
#define TUNTEST_TYPES_H

#include "defs.h"

#include <sys/uio.h>
#include <arpa/inet.h>
#include <vector>

// add some color to our logs
struct Color {
  Color(const char * c) : c_(c) { }
  const char * c_;
};

using Colors = std::vector<Color>;

using IOV = std::pair<const iovec *, size_t>;


// building blocks for rip msgs

// common rip header
 struct riphdr_t {
   uint8_t     command_, version_;
   uint16_t    mbz_;

   riphdr_t(uint8_t command) : 
    command_(command), // 1 req, 2 resp
    version_(2),
    mbz_(0)
   { }
 } __attribute__((packed));

// rip entry 1 or more
struct ripentry_t {
  uint16_t family_, tag_;
  uint32_t addr_, mask_, next_, metric_;
 
  ripentry_t(const char * addr, const char * mask, uint32_t metric, uint16_t family = 2) :
    family_(htons(family)),
    tag_(0),
    addr_(inet_addr(addr)),
    mask_(inet_addr(mask)),
    next_(0),                // implies self
    metric_(htonl(metric))
    { }
  }__attribute__((packed));

// simple rip request msg
 struct ripreqmsg_t {
   ripreqmsg_t() :
     hdr_(1),
     entry_(anyIPstr, anyIPstr, 16, 0)
   { }

   riphdr_t    hdr_; 
   ripentry_t entry_;
 } __attribute__((packed));


#endif
