

#ifndef TUNTEST_DEFS_H
#define TUNTEST_DEFS_H

#include <stdint.h>

#define COLOR_NRM "\033[0m"
#define COLOR_BLE "\033[0;34m"
#define COLOR_GRN "\033[0;32m"
#define COLOR_CYN "\033[0;36m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YEL "\033[1;33m"

// string fmt helper
extern char str1[64];

// tuntap name fmt
#define tunTapfmt  "tuntap%hhu"

const uint16_t ripPortNum = 520;

const uint32_t ROUTER_ALERT = 0x94040000;

const uint8_t  TOS_NC = 0xC0;

// see /usr/include/netinet/if_ether.h for mc hw fmt
//

// known ripv2 addrs
#define   ripIPstr    "224.0.0.9"
#define   ripHWstr    "01:00:5e:00:00:09"
// all hosts
#define   ahIPstr     "224.0.0.1"
#define   ahHWstr     "01:00:5e:00:00:01"

// local addr fmt
#define localHWfmt    "02:02:00:00:%02hhx:01"
#define localIPfmt    "172.16.%hhu.1"

// faux nbr (99) addr fmt
#define fauxHWfmt     "02:02:00:00:%02hhx:63"
#define fauxIPfmt     "172.16.%hhu.99"

// faux nbr attached lan segment(s) fmt
#define rmtNWfmt      "10.%hhu.%hhu.%hhu"
#define rmtNMfmt      "255.255.255.0"

#define anyIPstr      "0.0.0.0"


#endif
