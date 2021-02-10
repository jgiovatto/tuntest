// jgiovatto@adjacentlink.com
// Jan 29, 2021
// tuntest tool to play with ip/arp frames
//
// may need to pop open the new interface
// sudo iptables -I INPUT -i tuntap0 -j ACCEPT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>

#include <linux/if_tun.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include "tuntap.h"

#include <vector>

#define COLOR_NRM "\033[0m"
#define COLOR_BLE "\033[0;34m"
#define COLOR_GRN "\033[0;32m"
#define COLOR_CYN "\033[0;36m"
#define COLOR_RED "\033[0;31m"
#define COLOR_YEL "\033[1;33m"

char str1[64];

// ripv2 addrs
const char *   ripIPstr   = "224.0.0.9";
const char *   ripHWstr   = "01:00:5e:00:00:09";
const uint16_t ripPortstr = 520;
const char *   anyIPstr   = "0.0.0.0";

// tuntap name fmt
const char * tunTapfmt = "tuntap%hhu";

// local addr fmt
const char * localHWfmt = "02:02:00:00:%02hhx:01";
const char * localIPfmt = "172.16.%hhu.1";

// faux nbr (99) addr fmt
const char * fauxHWfmt = "02:02:00:00:%02hhx:63";
const char * fauxIPfmt = "172.16.%hhu.99";

// faux nbr attached lan
const char * rmtIPfmt = "192.168.%hhu.0";
const char * rmtNWfmt = "255.255.255.0";


/*
 *   this demo gives the illusion of the following topology
 *
 *
 *  |------- local IP stack -------|               |---------  faux nbr IP stack ------------|
 *  |                              |               |                                         |
 *  | eth0       tuntap1           |               |     eth0                     eth1       |
 *  |            172.16.1.1        |               |  172.16.0.99             172.16.99.0/24 |
 *  |            02:02:00:00:00:01 |               |  02:02:00:00:00:63                      |
 *                   |                                     |
 *                   |                                     |
 *                   |------------172.16.0.0/24----------- | 
 */


// add some color to our logs
struct Color {
  Color(const char * c) : c_(c) { }
  const char * c_;
};

using Colors = std::vector<Color>;


volatile bool bRunning = true;


static void bye(const char *msg)
{
    perror(msg);
    exit(0);
}


static const char * fmt_str(const char * fmt, char * const str, const size_t strlen, const uint8_t val)
{
    memset(str, 0x0, strlen);

    snprintf(str, strlen - 1, fmt, val);

    return str;
}


static void print_hex(const char * buff, size_t const bufflen, const Colors & colors)
{
    const size_t lineLen = 16;

    size_t linenum = 0;
    size_t pos = 0;

    while(pos < bufflen)
    {
        struct Str {
          size_t pos;
          char   buf[128];
          Str() : pos(0), buf{0} { } 
        }strHex, strTxt;

        for(size_t idx = 0; idx < lineLen; ++idx, ++pos)
        {
            if((idx != 0) && (idx % (lineLen / 2) == 0))
            {
                strHex.pos += snprintf(strHex.buf + strHex.pos, sizeof(strHex.buf) - strHex.pos, " ");
                strTxt.pos += snprintf(strTxt.buf + strTxt.pos, sizeof(strTxt.buf) - strTxt.pos, " ");
            }

            if(pos < bufflen)
            {
                const char val = buff[pos];

                // as hex
                strHex.pos += snprintf(strHex.buf + strHex.pos, sizeof(strHex.buf) - strHex.pos, "%s%02hhx ", colors[pos].c_, (uint8_t) val);

                // as txt
                strTxt.pos += snprintf(strTxt.buf + strTxt.pos, sizeof(strTxt.buf) - strTxt.pos, "%c", isalnum(val) ? val : '.');
            }
            else
            {
                // fill the last line
                strHex.pos += snprintf(strHex.buf + strHex.pos, sizeof(strHex.buf) - strHex.pos, "   ");
                strTxt.pos += snprintf(strTxt.buf + strTxt.pos, sizeof(strTxt.buf) - strTxt.pos, " ");
            }
        }
        printf("%03zu  %s    %s\n", linenum * lineLen, strTxt.buf, strHex.buf);

        ++linenum;
    }

   printf("%s\n", COLOR_NRM);
}


static uint16_t csum16(const void *buff, uint16_t len, uint16_t carry = 0)
{
  uint32_t sum = carry;

  uint16_t const * p = (uint16_t const *) buff;

  while(len > 1) {
     sum += *p++;
     len -= 2;
   }

  if(len > 0) {
     sum += *((uint8_t *) p);
   }

  while(sum >> 16) {
     sum = (sum & 0xFFFF) + (sum >> 16);
   }

  return(sum);
}


static uint16_t csum16v(const struct iovec * iov, const size_t iovn)
{
  uint16_t sum = 0;

  for(size_t n = 0; n < iovn; ++n)
   {
     sum = csum16(iov[n].iov_base, iov[n].iov_len, sum);
   }

  return sum;
}



static size_t build_rip(char * buff, size_t bufflen, uint8_t id)
{
   Colors colors(bufflen, Color(COLOR_NRM));

   memset(buff, 0x0, bufflen);

   static uint8_t cnt = 0;

   auto eth = (struct ether_header *)  buff;
   auto ip  = (struct iphdr *)        (buff + 14);
   auto udp = (struct udphdr *)       (buff + 34);

   struct rip_entry_t {
     uint16_t family, tag;
     uint32_t addr, mask, next, metric;
  
     rip_entry_t() :
      family(htons(2)),
      tag(0),
      addr(cnt == 0 ? inet_addr(anyIPstr) : inet_addr(rmtIPfmt)), // faux rmt network
      mask(cnt == 0 ? inet_addr(anyIPstr) : inet_addr(rmtNWfmt)), // faux rmt netmask
      next(inet_addr(anyIPstr)),                                  // implies self
      metric(htonl(cnt == 0 ? 16: 1))
      { }
    }__attribute__((packed));

   struct riphdr {
     uint8_t     command, version;
     uint16_t    mbz;
     rip_entry_t entry[1];

     riphdr() : 
      command(cnt == 0 ? 1 : 2),
      version(2),
      mbz(0)
     { }
   } __attribute__((packed)) rip;

   memcpy(buff + 42, &rip, sizeof(rip));

   // bump rip cnt
   ++cnt;
 
   // udp header and data len
   const uint16_t udplen = sizeof(*udp) + sizeof(rip);

   // set eth hdr
   memcpy(&eth->ether_dhost, ether_aton(ripHWstr), ETH_ALEN); // ripv2
   memcpy(&eth->ether_shost, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), id)), ETH_ALEN); // faux nbr
   eth->ether_type = htons(ETHERTYPE_IP);

   colors[12].c_ = COLOR_YEL;
   colors[13].c_ = COLOR_YEL;

   // set ip hdr
   ip->version  = 4;
   ip->ihl      = 5;
   ip->tos      = 0;
   ip->tot_len  = htons((ip->ihl << 2) + udplen);
   ip->id       = htons(0);
   ip->frag_off = htons(0);
   ip->ttl      = 1;
   ip->protocol = IPPROTO_UDP;
   ip->check    = htons(0);
   ip->saddr    = inet_addr(fmt_str(fauxIPfmt, str1, sizeof(str1), id));  // faux nbr ip
   ip->daddr    = inet_addr(ripIPstr);                                    // ripv2
   // ip csum
   ip->check = ~csum16(ip, ip->ihl << 2);

   colors[14].c_ = COLOR_GRN;
   colors[23].c_ = COLOR_GRN;
 
   // set udp hdr
   udp->source = htons(ripPortstr); // rip port
   udp->dest   = htons(ripPortstr); // rip port
   udp->len    = htons(udplen);
   udp->check  = 0;

   // udp pseudo sum
   struct {
     uint32_t src, dst;
     uint8_t  res, proto;
     uint16_t len;
   } __attribute__((packed)) psum = {ip->saddr,
                                     ip->daddr,
                                     0,
                                     ip->protocol,
                                     htons(udplen)};

   const struct iovec chkv[3] = {{(void*)&psum, sizeof(psum)}, 
                                 {(void*)udp,   sizeof(*udp)},
                                 {(void*)&rip,  sizeof(rip)}};

   // udp csum
   udp->check = ~csum16v(chkv, 3);

   const size_t result = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(rip);

   print_hex(buff, result, colors);

   return result;
}



static int parse_frame(char *buff, size_t len, uint8_t tunId)
{
    Colors colors(len, Color(COLOR_NRM));

    printf("%s tunId %hhu\n", __func__, tunId);

    int result = 0;

    if(len > sizeof(ether_header))
    {
        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        // sanity check for eth arp eth/ipv4
        if((len == sizeof(struct ether_header) + sizeof(struct arphdr) + (2 * (ETH_ALEN + 4))) && 
           (ether_type == ETHERTYPE_ARP))
        {
            struct arphdr * arp = (struct arphdr*) (eth + 1);
 
            colors[12].c_ = COLOR_YEL;
            colors[13].c_ = COLOR_YEL;
      
            print_hex(buff, len, colors);

            if((ntohs(arp->ar_op)  == ARPOP_REQUEST) &&
               (ntohs(arp->ar_hrd) == ARPHRD_ETHER)  &&
               (ntohs(arp->ar_pro) == ETHERTYPE_IP)  &&
               (arp->ar_hln        == ETH_ALEN)      &&
               (arp->ar_pln        == 4))
            {
                struct arp_ipv4_req_ {
                    struct ether_addr src_hw;
                    in_addr           src_ip;

                    struct ether_addr tar_hw;
                    in_addr           tar_ip;
                } __attribute__((packed)) * arp_req = (struct arp_ipv4_req_ *) (arp + 1);
#ifdef DEBUG
                printf(COLOR_YEL "in  ETH ARP:");
                printf("t_hw [%s]",   ether_ntoa(&arp_req->tar_hw));
                printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));

                printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                printf("\n" COLOR_NRM);
#endif

                // swap src/target ip addrs
                const in_addr tmp_ip = arp_req->tar_ip;
                arp_req->tar_ip = arp_req->src_ip;
                arp_req->src_ip = tmp_ip;

                // swap src/target hw addrs
                memcpy(&arp_req->tar_hw, &arp_req->src_hw,  ETH_ALEN);
                memcpy(&arp_req->src_hw, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), ETH_ALEN); // faux nbr
            
                // set as reply   
                arp->ar_op = htons(ARPOP_REPLY);

#ifdef DEBUG
                printf(COLOR_YEL "out ETH ARP:");
                printf("t_hw [%s]",   ether_ntoa(&arp_req->tar_hw));
                printf(", s_hw [%s]", ether_ntoa(&arp_req->src_hw));

                printf(", s_ip [%s]", inet_ntoa(arp_req->src_ip));
                printf(", t_ip [%s]", inet_ntoa(arp_req->tar_ip));
                printf("\n" COLOR_NRM);
#endif

                // return complete arp reply
                result = len;
            }
        }
        // sanity check for eth/ipv4
        else if((len > sizeof(struct iphdr)) && (ether_type == ETHERTYPE_IP))
        {
            struct iphdr * ip = (struct iphdr*) (eth + 1);

            // set ip colors
            colors[14].c_ = COLOR_GRN;
            colors[23].c_ = COLOR_GRN;

            print_hex(buff, len, colors);
 
            if(csum16(ip, ip->ihl << 2) == 0xffff)
             {
                switch(ip->protocol)
                 {
                    case IPPROTO_ICMP:
                     {
                       struct icmphdr * icmp = (struct icmphdr *)(buff + sizeof(ether_header) + (ip->ihl << 2));

                       const size_t icmplen = ntohs(ip->tot_len) - (ip->ihl << 2);

                       if(csum16(icmp, icmplen) == 0xffff)
                        {
                           if(icmp->type == ICMP_ECHO)
                             {

#ifdef DEBUG
                               if(icmplen >= (sizeof(icmphdr) + sizeof(struct timeval)))
                                 {
                                   // see man ping
                                   struct ts_ {
                                     struct timeval tv;
                                   } __attribute__((packed))* ts = (struct ts_*) (icmp + 1);
                                   printf("ETH IPv4 ICMP ECHO_REQ seq %hu, ts %ld:%06ld\n", 
                                          ntohs(icmp->un.echo.sequence),
                                          htole64(ts->tv.tv_sec), htole64(ts->tv.tv_usec));
                                 }
#endif

                               // turn into echo reply
                               icmp->type = ICMP_ECHOREPLY;

                               // icmp checksum
                               icmp->checksum = 0;
                               icmp->checksum = ~csum16(icmp, icmplen);

                               // swap ip srd/dst
                               const in_addr_t tmp_ip = ip->saddr;
                               ip->saddr = ip->daddr;
                               ip->daddr = tmp_ip;
 
                               // ip checksum
                               ip->check = 0;
                               ip->check = ~csum16(ip, ip->ihl << 2);

                               result = len;
                            }
                        }
                       else
                        {
                           printf(COLOR_RED "ETH IPv4 ICMP: bad chksum\n" COLOR_NRM);
                        }
                     }
                    break;

                    case IPPROTO_UDP:

                     // XXX TODO check for rip request
                    break;
                 }
             }
            else
             {
               printf(COLOR_RED "ETH IPv4: bad chksum\n" COLOR_NRM);
             }
        }

      // something to send back
      if(result > 0)
       {
         // swap eth src/dst
         memcpy(&eth->ether_dhost, &eth->ether_shost, ETH_ALEN);
         memcpy(&eth->ether_shost, ether_aton(fmt_str(fauxHWfmt, str1, sizeof(str1), tunId)), ETH_ALEN); // faux nbr
       }

    }

   return result;
}



static void sig_handle(int sig)
{
  if(sig == SIGINT || sig == SIGTERM)
    {
      printf("caught term signal\n");

      bRunning = false;
    }
}


int main(int, char *[])
{
    signal(SIGINT,  sig_handle);
    signal(SIGTERM, sig_handle);

    const size_t NUM_TUN_TAP = 2;

    TunTap tunTap[NUM_TUN_TAP];

    int fd_max = -1;

    fd_set read_fds;

    FD_ZERO(&read_fds);

    for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
     {
       const uint8_t tunId = idx + 1;

       // open device
       if(tunTap[idx].open("/dev/net/tun", 
            fmt_str(tunTapfmt, str1, sizeof(str1), tunId), 
              IFF_TAP | IFF_NO_PI) < 0)
        {
           bye("tun open");
        }

       // set ip addr
       if(tunTap[idx].set_ip_address(inet_addr(
             fmt_str(localIPfmt, str1, sizeof(str1), tunId)), 24) < 0)
        {
           bye("tun set ip");
        }

       // set hw addr
       if(tunTap[idx].set_hw_address(ether_aton(
             fmt_str(localHWfmt, str1, sizeof(str1), tunId))) < 0)
        {
           bye("tun set ip");
        }

       // set up, arp on
       if(tunTap[idx].activate(true, true) < 0)
        {
           bye("tun activate");
        }

       // set blocking
       if(tunTap[idx].set_blocking(true) < 0)
        {
           bye("tun setblocking");
        }

       const int fd = tunTap[idx].get_handle();

       // add to read fd set
       FD_SET(fd, &read_fds);

       // get max fd
       fd_max = std::max(fd_max, fd);
     }

    while(bRunning)
     {
       char buff[2048] = {0};

       fd_set rfds = read_fds;
       
       int num_ready = select(fd_max + 1, &rfds, nullptr, nullptr, nullptr);

       while(num_ready > 0 && bRunning)
        {
          for(uint8_t idx = 0; idx < NUM_TUN_TAP; ++idx)
           {
              const int fd = tunTap[idx].get_handle();

              if(FD_ISSET(fd, &rfds))
               {
                 const int num_read = tunTap[idx].read(buff, sizeof(buff));

                 if(num_read > 0) 
                  {
                     const int num_write = parse_frame(buff, num_read, idx + 1);

                     if(num_write > 0)
                      {
                        tunTap[idx].write(buff, num_write);
                      }
                  }
                 else
                  {
                    perror("tuntap.read");
                  }

                  --num_ready;
                  FD_CLR(fd, &rfds);
               }
           }  
        }
    }

    printf("bye \n" COLOR_NRM);

    return (0);
}
