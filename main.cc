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

// ripv2 addrs
const char *   ripIP   = "224.0.0.9";
const char *   ripHW   = "01:00:5e:00:00:09";
const uint16_t ripPort = 520;
const char *   anyIP   = "0.0.0.0";

// our tuntap addrs
const char * localIP = "172.16.0.1";
const char * localHW = "02:02:00:00:00:01";

// faux nbr addrs 
const char * nbrIP = "172.16.0.99";
const char * nbrHW = "02:02:00:00:00:63";

// faux nbr lan
const char * rmtIP = "172.16.99.0";
const char * rmtNW = "255.255.255.0";


/*
 *   this demo gives the illusion of the following topology
 *
 *
 *  |------- local IP stack -------|               |---------  faux nbr IP stack ------------|
 *  |                              |               |                                         |
 *  | eth0       tuntap0           |               |     eth0                     eth1       |
 *  |            172.16.0.1        |               |  172.16.0.99             172.16.99.0/24 |
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


bool bRunning = true;


void bye(const char *msg)
{
    perror(msg);
    exit(0);
}


void print_hex(const char * buff, size_t const bufflen, const Colors & colors)
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


uint16_t csum16(const void *buff, uint16_t len, uint16_t carry = 0)
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


uint16_t csum16v(const struct iovec * iov, const size_t iovn)
{
  uint16_t sum = 0;

  for(size_t n = 0; n < iovn; ++n)
   {
     sum = csum16(iov[n].iov_base, iov[n].iov_len, sum);
   }

  return sum;
}


int parse_frame(char *buff, size_t len)
{
    Colors colors(len, Color(COLOR_NRM));

    int result = 0;

    if(len > sizeof(ether_header))
    {
        struct ether_header * eth = (struct ether_header *) buff;

        const uint16_t ether_type = htons(eth->ether_type);

        colors[12].c_ = COLOR_YEL;
        colors[13].c_ = COLOR_YEL;

        // sanity check for eth arp eth/ipv4
        if((len == sizeof(struct ether_header) + sizeof(struct arphdr) + (2 * (ETH_ALEN + 4))) && 
           (ether_type == ETHERTYPE_ARP))
        {
            struct arphdr * arp = (struct arphdr*) (eth + 1);
       
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
                memcpy(&arp_req->src_hw, ether_aton(nbrHW), ETH_ALEN); // faux nbr
            
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
         memcpy(&eth->ether_shost, ether_aton(nbrHW), ETH_ALEN); // faux nbr
       }

       print_hex(buff, len, colors);
    }

   return result;
}


/*
 * IP (tos 0x0, ttl 1, id 0, offset 0, flags [none], proto UDP (17), length 52)
 *   172.16.0.99.520 > 224.0.0.9.520: [udp sum ok] 
 *	RIPv2, Request, length: 24, routes: 1 or less
 *	  AFI IPv4,     172.16.1.99/24, tag 0x0000, metric: 1, next-hop: self
 *	0x0000:  0102 0000 0002 0000 ac10 0163 ffff ff00
 *	0x0010:  0000 0000 0000 0001
 */
size_t build_rip(char * buff, size_t bufflen)
{
   Colors colors(bufflen, Color(COLOR_NRM));

   memset(buff, 0x0, bufflen);

   static uint8_t id = 0;

   auto eth = (struct ether_header *)  buff;
   auto ip  = (struct iphdr *)        (buff + 14);
   auto udp = (struct udphdr *)       (buff + 34);

   struct rip_entry_t {
     uint16_t family, tag;
     uint32_t addr, mask, next, metric;
  
     rip_entry_t() :
      family(htons(2)),
      tag(0),
      addr(id == 0 ? inet_addr(anyIP) : inet_addr(rmtIP)), // faux rmt network
      mask(id == 0 ? inet_addr(anyIP) : inet_addr(rmtNW)), // faux rmt netmask
      next(inet_addr(anyIP)),                              // implies self
      metric(htonl(id == 0 ? 16: 1))
      { }
    }__attribute__((packed));

   struct riphdr {
     uint8_t     command, version;
     uint16_t    mbz;
     rip_entry_t entry[1];

     riphdr() : 
      command(id == 0 ? 1 : 2),
      version(2),
      mbz(0)
     { }
   } __attribute__((packed)) rip;

   memcpy(buff + 42, &rip, sizeof(rip));

   // bump rip id
   ++id;
 
   // udp header and data len
   const uint16_t udplen = sizeof(*udp) + sizeof(rip);

   // set eth hdr
   memcpy(&eth->ether_dhost, ether_aton(ripHW), ETH_ALEN); // ripv2
   memcpy(&eth->ether_shost, ether_aton(nbrHW), ETH_ALEN); // faux nbr
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
   ip->saddr    = inet_addr(nbrIP);  // faux nbr
   ip->daddr    = inet_addr(ripIP);     // ripv2
   // ip csum
   ip->check = ~csum16(ip, ip->ihl << 2);

   colors[14].c_ = COLOR_GRN;
   colors[23].c_ = COLOR_GRN;
 
   // set udp hdr
   udp->source = htons(ripPort); // rip port
   udp->dest   = htons(ripPort); // rip port
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



int main(int, char *[])
{
    // create tun tap object
    TunTap tunTap;

    // open
    if(tunTap.open("/dev/net/tun", "tuntap0", IFF_TAP | IFF_NO_PI) < 0)
     {
        bye("tun open");
     }

    // set ip addr
    if(tunTap.set_ip_address(inet_addr(localIP), 24) < 0)
     {
        bye("tun set ip");
     }

    // set hw addr
    if(tunTap.set_hw_address(ether_aton(localHW)) < 0)
     {
        bye("tun set ip");
     }

    // set up, arp on
    if(tunTap.activate(true, true) < 0)
     {
        bye("tun activate");
     }

    // set non blocking
    if(tunTap.set_blocking(false) < 0)
     {
        bye("tun setblocking");
     }

    while(bRunning)
     {
       char buff[2048] = {0};

       const int num_read = tunTap.read(buff, sizeof(buff));

       if(num_read > 0) 
         {
           const int num_write = parse_frame(buff, num_read);

           if(num_write > 0)
            {
              tunTap.write(buff, num_write);
            }
         }
       else
         {
           const size_t num_write = build_rip(buff, sizeof(buff));
           
           if(num_write > 0)
           {
             tunTap.write(buff, num_write);
           }

          sleep(1);
        }
    }

    printf("bye \n" COLOR_NRM);

    return (0);
}
