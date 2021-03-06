#ifndef TUNTEST_DVMRP_H
#define TUNTEST_DVMRP_H

#include "types.h"

#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>

#define DVMRP_MINOR  0xFF
#define DVMRP_MAJOR  0x03

#define DVMRP_CODE_PROBE   0x01
#define DVMRP_CODE_REPORT  0x02

#define DVMRP_CAP_M       0x08
#define DVMRP_CAP_G       0x04
#define DVMRP_CAP_P       0x02
#define DVMRP_CAP_L       0x01

// dvmrp ip addr
#define   dvmrpIPstr  "224.0.0.4"
#define   dvmrpHWstr  "01:00:5e:00:00:04"


struct dvmrphdr_t {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
} __attribute__((packed));


struct dvmrpprobe_t {
    uint16_t cap;
    uint8_t  minor;
    uint8_t  major;
    uint32_t genid;
} __attribute__((packed));

struct dvmrpneighbor_t {
    in_addr_t  metric;
} __attribute__((packed));

using dvmrpneighbors_t = std::vector<dvmrpneighbor_t>;

struct dvmrpreport_t {
    uint16_t res;
    uint8_t  minor;
    uint8_t  major;
} __attribute__((packed));


struct dvmrproute_t {
    uint8_t  mask[3];
    uint8_t  net [3];
    uint8_t  metric;
} __attribute__((packed));

using dvmrproutes_t = std::vector<dvmrproute_t>;



class DVMRP_Probe {
  public:
    DVMRP_Probe(const ether_addr * hw_src, 
                const in_addr_t ip_src, 
                const uint32_t genid,
                const dvmrpneighbors_t & nbrs);

    IOV getIOV() const;

  private:
    ether_header     eth_hdr_;
    iphdr            ip_hdr_;
    uint32_t         ip_option_;
    dvmrphdr_t       dvmrp_hdr_;
    dvmrpprobe_t     dvmrp_probe_;
    dvmrpneighbors_t nbrs_;

    iovec            iov_[6];
};



class DVMRP_Report {
  public:
    DVMRP_Report(const ether_addr * hw_src, 
                 const in_addr_t ip_src, 
                 const dvmrproutes_t & routes);

    IOV getIOV() const;

  private:
    ether_header   eth_hdr_;
    iphdr          ip_hdr_;
    uint32_t       ip_option_;
    dvmrphdr_t     dvmrp_hdr_;
    dvmrpreport_t  dvmrp_report_;
    dvmrproutes_t  routes_;

    iovec          iov_[6];
};


#endif
