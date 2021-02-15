
#include "dvmrp.h"
#include "netutils.h"

#include <unistd.h>
#include <time.h>


DVMRP_Probe::DVMRP_Probe(const ether_addr * hw_src,
                         const in_addr_t  ip_src,
                         const InAddrs  & nbrs) :
 ip_option_{htonl(ROUTER_ALERT)},
 nbrs_{nbrs},
 iov_{{(void *) &eth_hdr_,     sizeof(eth_hdr_)},
      {(void *) &ip_hdr_,      sizeof(ip_hdr_)},
      {(void *) &ip_option_,   sizeof(ip_option_)},
      {(void *) &dvmrp_hdr_,   sizeof(dvmrp_hdr_)},
      {(void *) &dvmrp_probe_, sizeof(dvmrp_probe_)},
      {(void *) nbrs_.data(),  nbrs_.size() * 4}}

  {
    // set eth hdr
    set_eth_hdr(&eth_hdr_,
                hw_src,
                ether_aton(dvmrpHWstr),  // all dvmrp routers
                ETHERTYPE_IP);           // ipv4

    // set ip hdr
    set_ipv4_hdr(&ip_hdr_,
                 TOS_NC,                                                         // tos
                 1,                                                              // ttl
                 getpid(),                                                       // id
                 sizeof(dvmrp_hdr_) + sizeof(dvmrp_probe_) + (nbrs_.size() * 4), // payload
                 IPPROTO_IGMP,                                                   // proto
                 ip_src,                                                         // ip src
                 inet_addr(dvmrpIPstr),                                          // all dvmrp routers
                 &ip_option_,                                                    // options
                 1);                                                             // num options

    // set dvmrp hdr
    dvmrp_hdr_.type  = IGMP_DVMRP;
    dvmrp_hdr_.code  = DVMRP_CODE_PROBE; // dvmrp probe
    dvmrp_hdr_.check = 0;

    // set dvmrp probe hdr
    dvmrp_probe_.cap   = htons(DVMRP_CAP_G + DVMRP_CAP_P);       // genid, prune
    dvmrp_probe_.cap  += htons(nbrs_.empty() ? DVMRP_CAP_L : 0); // leaf
    dvmrp_probe_.minor = DVMRP_MINOR;
    dvmrp_probe_.major = DVMRP_MAJOR;
    dvmrp_probe_.genid = htonl((uint32_t)time(NULL));

    const iovec chkv[3] = {{(void*)&dvmrp_hdr_,   sizeof(dvmrp_hdr_)}, 
                           {(void*)&dvmrp_probe_, sizeof(dvmrp_probe_)},
                           {(void*)nbrs_.data(),  nbrs_.size() * 4}};

    // set dvmrp hdr csum
    dvmrp_hdr_.check = ~csum16v(chkv, 3);
  }


 IOV DVMRP_Probe::getIOV() const
  {
    return IOV{iov_, nbrs_.empty() ? 5 : 6};
  }
